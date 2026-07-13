package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	apperrors "ebpf-autoheal/internal/errors"
	"ebpf-autoheal/internal/blastradius"
	"ebpf-autoheal/internal/graph"
	pb "ebpf-autoheal/proto/gen"
)

type dedupEntry struct {
	lastSent time.Time
	aggCount int
}

type dedupTracker struct {
	mu       sync.Mutex
	entries  map[string]*dedupEntry
	window   time.Duration
	minScore float64
}

func newDedupTracker(window time.Duration, minScore float64) *dedupTracker {
	return &dedupTracker{
		entries:  make(map[string]*dedupEntry),
		window:   window,
		minScore: minScore,
	}
}

func (d *dedupTracker) shouldSend(nodeID string, score float64) (send bool, suppressed int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if score >= d.minScore {
		d.entries[nodeID] = &dedupEntry{lastSent: time.Now()}
		return true, 0
	}
	now := time.Now()
	entry, exists := d.entries[nodeID]
	if !exists || now.Sub(entry.lastSent) > d.window {
		d.entries[nodeID] = &dedupEntry{lastSent: now}
		return true, 0
	}
	entry.aggCount++
	return false, entry.aggCount
}

func (d *dedupTracker) cleanupExpired() {
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := time.Now().Add(-d.window * 2)
	for id, entry := range d.entries {
		if entry.lastSent.Before(cutoff) {
			delete(d.entries, id)
		}
	}
}

// EventMsg 是分析引擎发布的事件。
type EventMsg struct {
	NodeID         string
	AnomalyScore   float64
	AvgLatMs       float64
	CallCount      int64
	SuspectChain   []string
	RootCauseScore float64
}

// Server 封装 gRPC 服务，同时实现 TopologyService 和 RemediationService。
type Server struct {
	pb.UnimplementedTopologyServiceServer
	pb.UnimplementedRemediationServiceServer

	server      *grpc.Server
	graph       *graph.ServiceGraph
	anomalyCh   chan EventMsg
	subscribers []chan *pb.AnomalyEvent
	dedup       *dedupTracker
	addr        string
	notifyFn    func(EventMsg)
}

// NewServer 创建 gRPC 服务。
func NewServer(addr string, g *graph.ServiceGraph, notifyFn func(EventMsg)) *Server {
	return &Server{
		graph:       g,
		anomalyCh:   make(chan EventMsg, 100),
		subscribers: make([]chan *pb.AnomalyEvent, 0),
		dedup:       newDedupTracker(60*time.Second, 80.0),
		addr:        addr,
		notifyFn:    notifyFn,
	}
}

// Start 启动 gRPC 服务。
func (s *Server) Start() error {
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("gRPC listen (%v): %w", err, apperrors.ErrGRPCListen)
	}
	s.server = grpc.NewServer()
	pb.RegisterTopologyServiceServer(s.server, s)
	pb.RegisterRemediationServiceServer(s.server, s)
	reflection.Register(s.server)
	go func() {
		slog.Info(fmt.Sprintf("AetherOps gRPC server listening on %s", s.addr))
		if err := s.server.Serve(lis); err != nil {
			slog.Info(fmt.Sprintf("AetherOps gRPC server stopped: %v", err))
		}
	}()
	return nil
}

// Shutdown 优雅停止。
func (s *Server) Shutdown() {
	if s.server != nil {
		s.server.GracefulStop()
	}
}

// PublishEvent 由分析引擎调用，发布异常事件。
func (s *Server) PublishEvent(msg EventMsg) {
	send, _ := s.dedup.shouldSend(msg.NodeID, msg.AnomalyScore)
	if !send {
		return
	}

	evt := &pb.AnomalyEvent{
		NodeId:           msg.NodeID,
		AnomalyScore:     msg.AnomalyScore,
		AvgLatencyMs:     msg.AvgLatMs,
		CallCount:        msg.CallCount,
		SuspectChain:     msg.SuspectChain,
		TimestampUnixNano: time.Now().UnixNano(),
		RootCauseScore:   msg.RootCauseScore,
	}

	for _, sub := range s.subscribers {
		select {
		case sub <- evt:
		default:
		}
	}

	if s.notifyFn != nil {
		s.notifyFn(msg)
	}
}

// CleanupExpired 定期清理过期 dedup 记录。
func (s *Server) CleanupExpired() {
	s.dedup.cleanupExpired()
}

// GetTopology 实现 TopologyServiceServer。
func (s *Server) GetTopology(ctx context.Context, req *pb.GetTopologyRequest) (*pb.TopologySnapshot, error) {
	s.graph.RLock()
	defer s.graph.RUnlock()

	snapshot := &pb.TopologySnapshot{
		TimestampUnixNano: time.Now().UnixNano(),
	}

	for _, n := range s.graph.Nodes {
		snapshot.Nodes = append(snapshot.Nodes, &pb.TopologyNode{
			Id:           n.ID,
			AvgLatencyMs: n.AvgLat,
			ErrorRate:    n.ErrorRate,
			CallCount:    n.CallCount,
		})
	}

	for _, e := range s.graph.Edges {
		if e.AnomalyScore == 0 && !req.IncludeHealthy {
			continue
		}
		snapshot.Edges = append(snapshot.Edges, &pb.TopologyEdge{
			Src:              e.Src,
			Dst:              e.Dst,
			CallCount:        e.Count,
			AvgLatencyMs:     e.AvgLat,
			EmaLatencyMs:     e.EmaLat,
			P95LatencyMs:     e.P95,
			AnomalyScore:     e.AnomalyScore,
			CallAnomalyScore: e.CallAnomaly,
		})
	}

	snapshot.NodeCount = int32(len(snapshot.Nodes))
	snapshot.EdgeCount = int32(len(snapshot.Edges))
	return snapshot, nil
}

// SubscribeAnomalyEvents 实现 TopologyServiceServer 流式订阅。
func (s *Server) SubscribeAnomalyEvents(req *pb.AnomalySubscription, stream pb.TopologyService_SubscribeAnomalyEventsServer) error {
	sub := make(chan *pb.AnomalyEvent, 32)

	s.subscribers = append(s.subscribers, sub)
	slog.Info(fmt.Sprintf("AetherOps gRPC: new anomaly subscriber (threshold=%.2f)", req.MinScoreThreshold))

	defer func() {
		for i, c := range s.subscribers {
			if c == sub {
				s.subscribers = append(s.subscribers[:i], s.subscribers[i+1:]...)
				break
			}
		}
		close(sub)
	}()

	for {
		select {
		case evt := <-sub:
			if evt.AnomalyScore < req.MinScoreThreshold {
				continue
			}
			if err := stream.Send(evt); err != nil {
				return fmt.Errorf("stream send failed (%v): %w", err, apperrors.ErrGRPCStreamSend)
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

// EvaluateRemediation 实现 RemediationServiceServer。
func (s *Server) EvaluateRemediation(ctx context.Context, req *pb.RemediationRequest) (*pb.RemediationReport, error) {
	return blastradius.Evaluate(s.graph, req.TargetNode, req.Action, 0), nil
}

// ExecuteRemediation 实现 RemediationServiceServer。
func (s *Server) ExecuteRemediation(ctx context.Context, req *pb.ExecuteRequest) (*pb.ExecuteResponse, error) {
	report := blastradius.Evaluate(s.graph, req.TargetNode, req.Action, 0)
	execID := fmt.Sprintf("exec-%s-%d", req.TargetNode, time.Now().Unix())

	if !req.Force && report.RiskLevel == pb.RiskLevel_RISK_HIGH {
		return &pb.ExecuteResponse{
			Accepted:    false,
			ExecutionId: execID,
			Status:      "pending_approval",
			Details:     fmt.Sprintf("High risk action. %s", report.Recommendation),
		}, nil
	}

	return &pb.ExecuteResponse{
		Accepted:    true,
		ExecutionId: execID,
		Status:      "executed",
		Details:     fmt.Sprintf("Action %s on %s accepted", req.Action, req.TargetNode),
	}, nil
}
