package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"ebpf-autoheal/internal/blastradius"
	apperrors "ebpf-autoheal/internal/errors"
	"ebpf-autoheal/internal/graph"
	"ebpf-autoheal/internal/mitigation"
	"ebpf-autoheal/internal/policy"
	pb "ebpf-autoheal/proto/gen"
)

// Server 封装 MCP 服务。
type Server struct {
	mcp   *server.MCPServer
	sse   *server.SSEServer
	httpS *http.Server
	addr  string

	graph      *graph.ServiceGraph
	mitigation *mitigation.Service
	policy     *policy.Engine
	cfg        Config
}

// Config MCP server 配置。
type Config struct {
	ProfileDurationSec int
}

// NewServer 创建 MCP 服务。
func NewServer(addr string, g *graph.ServiceGraph, mit *mitigation.Service, pol *policy.Engine, cfg Config) *Server {
	mcpServer := server.NewMCPServer(
		"AetherOps",
		"1.0.0",
		server.WithResourceCapabilities(true, false),
		server.WithToolCapabilities(true),
		server.WithInstructions(
			"AetherOps eBPF Data Plane — real-time service topology monitoring, anomaly detection, "+
				"blast radius evaluation, and graded remediation execution.",
		),
		server.WithRecovery(),
	)

	s := &Server{
		mcp:        mcpServer,
		addr:       addr,
		graph:      g,
		mitigation: mit,
		policy:     pol,
		cfg:        cfg,
	}

	s.registerTools()
	s.registerResources()

	sseServer := server.NewSSEServer(mcpServer)
	s.sse = sseServer
	return s
}

// Start 启动 HTTP 服务。
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.Handle("/sse", s.sse.SSEHandler())
	mux.Handle("/message", s.sse.MessageHandler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"service": "aetherops-mcp",
			"version": "1.0.0",
		})
	})

	s.httpS = &http.Server{Addr: s.addr, Handler: mux}
	go func() {
		slog.Info(fmt.Sprintf("AetherOps MCP server listening on %s", s.addr))
		if err := s.httpS.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Info(fmt.Sprintf("MCP server error: %v", err))
		}
	}()
	return nil
}

// Shutdown 优雅关闭。
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpS != nil {
		return s.httpS.Shutdown(ctx)
	}
	return nil
}

// PublishAnomaly 广播异常事件。
func (s *Server) PublishAnomaly(nodeID string, score float64, avgLat float64, callCount int64, suspectChain []string) {
	if s.mcp == nil {
		return
	}
	s.mcp.SendNotificationToAllClients("notifications/events/anomaly", map[string]interface{}{
		"node_id":        nodeID,
		"anomaly_score":  score,
		"avg_latency_ms": avgLat,
		"call_count":     callCount,
		"suspect_chain":  suspectChain,
		"timestamp_nano": time.Now().UnixNano(),
	})
}

func (s *Server) registerTools() {
	s.mcp.AddTool(mcp.NewTool("get_topology",
		mcp.WithDescription("Get current service topology graph (nodes, edges, anomaly scores)"),
		mcp.WithBoolean("include_healthy",
			mcp.Description("Include edges with zero anomaly score"),
			mcp.DefaultBool(false),
		),
	), s.handleGetTopology)

	s.mcp.AddTool(mcp.NewTool("evaluate_remediation",
		mcp.WithDescription("Evaluate the blast radius of a remediation action before executing it"),
		mcp.WithString("target_node", mcp.Description("Target service name or IP:Port"), mcp.Required()),
		mcp.WithString("action",
			mcp.Description("Remediation action type"),
			mcp.Enum("TC_DROP", "POD_RESTART", "SCALE_UP", "CONFIG_CHANGE", "IMAGE_ROLLBACK"),
			mcp.Required(),
		),
	), s.handleEvaluateRemediation)

	s.mcp.AddTool(mcp.NewTool("execute_remediation",
		mcp.WithDescription("Execute a remediation action through the graded execution pipeline"),
		mcp.WithString("target_node", mcp.Description("Target service name or IP:Port"), mcp.Required()),
		mcp.WithString("action",
			mcp.Description("Remediation action type"),
			mcp.Enum("TC_DROP", "POD_RESTART", "SCALE_UP", "CONFIG_CHANGE", "IMAGE_ROLLBACK"),
			mcp.Required(),
		),
		mcp.WithBoolean("force", mcp.Description("Skip risk check and force execution"), mcp.DefaultBool(false)),
	), s.handleExecuteRemediation)

	s.mcp.AddTool(mcp.NewTool("check_policy",
		mcp.WithDescription("Evaluate a remediation action against all active OPA-style policies"),
		mcp.WithString("action",
			mcp.Description("Remediation action to evaluate"),
			mcp.Enum("TC_DROP", "POD_RESTART", "SCALE_UP", "SCALE_DOWN", "CONFIG_CHANGE", "IMAGE_ROLLBACK"),
			mcp.Required(),
		),
		mcp.WithString("target_node", mcp.Description("Target service name, IP:Port, or pod name"), mcp.Required()),
		mcp.WithString("target_ip", mcp.Description("Target IP address (optional)"), mcp.DefaultString("")),
		mcp.WithString("namespace", mcp.Description("K8s namespace (optional)"), mcp.DefaultString("")),
	), s.handleCheckPolicy)

	s.mcp.AddTool(mcp.NewTool("list_policies",
		mcp.WithDescription("List all active OPA-style policies with descriptions and effects"),
	), s.handleListPolicies)
}

func (s *Server) registerResources() {
	s.mcp.AddResource(mcp.NewResource("topology://current", "Current Service Topology",
		mcp.WithResourceDescription("Live snapshot of the service topology graph"),
		mcp.WithMIMEType("application/json"),
	), s.handleReadTopologyResource)

	s.mcp.AddResource(mcp.NewResource("topology://anomalies", "Recent Anomaly Events",
		mcp.WithResourceDescription("Recent anomaly events from the root cause analysis engine"),
		mcp.WithMIMEType("application/json"),
	), s.handleReadAnomaliesResource)

	s.mcp.AddResource(mcp.NewResource("policy://rules", "Active Policy Rules",
		mcp.WithResourceDescription("All active OPA-style policy rules"),
		mcp.WithMIMEType("application/json"),
	), s.handleReadPolicyResource)
}

// ---- Tool Handlers ----

func (s *Server) handleGetTopology(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	includeHealthy := req.GetBool("include_healthy", false)
	if s.graph == nil {
		return mcp.NewToolResultText(`{"status": "not ready"}`), nil
	}

	s.graph.RLock()
	defer s.graph.RUnlock()

	type nodeJSON struct {
		ID        string  `json:"id"`
		AvgLatMs  float64 `json:"avg_latency_ms"`
		ErrRate   float64 `json:"error_rate"`
		CallCount int64   `json:"call_count"`
	}
	type edgeJSON struct {
		Src         string  `json:"src"`
		Dst         string  `json:"dst"`
		Count       int64   `json:"call_count"`
		AvgLat      float64 `json:"avg_latency_ms"`
		EmaLat      float64 `json:"ema_latency_ms"`
		P95         float64 `json:"p95_latency_ms"`
		Anomaly     float64 `json:"anomaly_score"`
		CallAnomaly float64 `json:"call_anomaly_score"`
	}

	nodes := make([]nodeJSON, 0, len(s.graph.Nodes))
	for _, n := range s.graph.Nodes {
		nodes = append(nodes, nodeJSON{n.ID, n.AvgLat, n.ErrorRate, n.CallCount})
	}
	edges := make([]edgeJSON, 0, len(s.graph.Edges))
	for _, e := range s.graph.Edges {
		if e.AnomalyScore == 0 && !includeHealthy {
			continue
		}
		edges = append(edges, edgeJSON{e.Src, e.Dst, e.Count, e.AvgLat, e.EmaLat, e.P95, e.AnomalyScore, e.CallAnomaly})
	}

	return mcp.NewToolResultStructuredOnly(map[string]interface{}{
		"nodes":          nodes,
		"edges":          edges,
		"node_count":     len(nodes),
		"edge_count":     len(edges),
		"timestamp_nano": time.Now().UnixNano(),
	}), nil
}

func (s *Server) handleEvaluateRemediation(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	targetNode, err := req.RequireString("target_node")
	if err != nil {
		return nil, fmt.Errorf("invalid arguments (%v): %w", err, apperrors.ErrMCPInvalidArgs)
	}
	action, err := req.RequireString("action")
	if err != nil {
		return nil, fmt.Errorf("invalid arguments (%v): %w", err, apperrors.ErrMCPInvalidArgs)
	}

	actionVal, ok := pb.RemediationAction_value[action]
	if !ok {
		return nil, fmt.Errorf("unknown action (%s): %w", action, apperrors.ErrMCPInvalidArgs)
	}

	report := blastradius.Evaluate(s.graph, targetNode, pb.RemediationAction(actionVal), s.cfg.ProfileDurationSec)
	return mcp.NewToolResultStructuredOnly(map[string]interface{}{
		"target_node":         report.TargetNode,
		"action":              report.Action.String(),
		"risk_level":          report.RiskLevel.String(),
		"affected_upstream":   report.AffectedUpstreamCount,
		"affected_downstream": report.AffectedDownstreamCount,
		"affected_services":   report.AffectedServices,
		"error_budget_pct":    report.EstimatedErrorBudgetConsumption,
		"downtime_sec":        report.EstimatedDowntimeSeconds,
		"recommendation":      report.Recommendation,
	}), nil
}

func (s *Server) handleExecuteRemediation(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	targetNode, err := req.RequireString("target_node")
	if err != nil {
		return nil, fmt.Errorf("invalid arguments (%v): %w", err, apperrors.ErrMCPInvalidArgs)
	}
	action, err := req.RequireString("action")
	if err != nil {
		return nil, fmt.Errorf("invalid arguments (%v): %w", err, apperrors.ErrMCPInvalidArgs)
	}
	force := req.GetBool("force", false)

	actionVal, ok := pb.RemediationAction_value[action]
	if !ok {
		return nil, fmt.Errorf("unknown action (%s): %w", action, apperrors.ErrMCPInvalidArgs)
	}

	report := blastradius.Evaluate(s.graph, targetNode, pb.RemediationAction(actionVal), s.cfg.ProfileDurationSec)
	execID := fmt.Sprintf("exec-%s-%d", targetNode, time.Now().Unix())

	if !force && report.RiskLevel == pb.RiskLevel_RISK_HIGH {
		return mcp.NewToolResultStructuredOnly(map[string]interface{}{
			"accepted":     false,
			"execution_id": execID,
			"status":       "pending_approval",
			"details":      fmt.Sprintf("High risk action. %s", report.Recommendation),
		}), nil
	}

	return mcp.NewToolResultStructuredOnly(map[string]interface{}{
		"accepted":     true,
		"execution_id": execID,
		"status":       "evaluated_only",
		"details":      fmt.Sprintf("Action %s on %s evaluated (blast radius only, actual exec requires TC/k8s access in MCP path)", action, targetNode),
	}), nil
}

func (s *Server) handleCheckPolicy(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	pAction, err := req.RequireString("action")
	if err != nil {
		return nil, fmt.Errorf("invalid arguments (%v): %w", err, apperrors.ErrMCPInvalidArgs)
	}
	targetNode, err := req.RequireString("target_node")
	if err != nil {
		return nil, fmt.Errorf("invalid arguments (%v): %w", err, apperrors.ErrMCPInvalidArgs)
	}
	targetIP := req.GetString("target_ip", "")
	namespace := req.GetString("namespace", "")

	if s.policy == nil {
		return mcp.NewToolResultText(`{"allowed": true, "reason": "policy engine not initialized"}`), nil
	}

	result := s.policy.Check(policy.PolicyAction{
		Action:     policy.RemediationActionType(pAction),
		TargetNode: targetNode,
		TargetIP:   targetIP,
		Namespace:  namespace,
		Timestamp:  time.Now(),
	})
	return mcp.NewToolResultStructuredOnly(map[string]interface{}{
		"allowed":    result.Allowed,
		"denied":     result.Denied,
		"warned":     result.Warned,
		"reasons":    result.Reasons,
		"matched_by": result.MatchedBy,
	}), nil
}

func (s *Server) handleListPolicies(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if s.policy == nil {
		return mcp.NewToolResultText(`{"status": "not initialized"}`), nil
	}
	return mcp.NewToolResultStructuredOnly(s.policy.GetReport()), nil
}

// ---- Resource Handlers ----

func (s *Server) handleReadTopologyResource(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	if s.graph == nil {
		return []mcp.ResourceContents{
			mcp.TextResourceContents{URI: "topology://current", MIMEType: "application/json", Text: `{"status": "not ready"}`},
		}, nil
	}

	s.graph.RLock()
	defer s.graph.RUnlock()

	type nodeJSON struct {
		ID        string  `json:"id"`
		AvgLatMs  float64 `json:"avg_latency_ms"`
		ErrRate   float64 `json:"error_rate"`
		CallCount int64   `json:"call_count"`
	}
	type edgeJSON struct {
		Src         string  `json:"src"`
		Dst         string  `json:"dst"`
		Count       int64   `json:"call_count"`
		AvgLat      float64 `json:"avg_latency_ms"`
		EmaLat      float64 `json:"ema_latency_ms"`
		P95         float64 `json:"p95_latency_ms"`
		Anomaly     float64 `json:"anomaly_score"`
		CallAnomaly float64 `json:"call_anomaly_score"`
	}

	nodes := make([]nodeJSON, 0, len(s.graph.Nodes))
	for _, n := range s.graph.Nodes {
		nodes = append(nodes, nodeJSON{n.ID, n.AvgLat, n.ErrorRate, n.CallCount})
	}
	edges := make([]edgeJSON, 0, len(s.graph.Edges))
	for _, e := range s.graph.Edges {
		edges = append(edges, edgeJSON{e.Src, e.Dst, e.Count, e.AvgLat, e.EmaLat, e.P95, e.AnomalyScore, e.CallAnomaly})
	}

	data, _ := json.Marshal(map[string]interface{}{
		"nodes":          nodes,
		"edges":          edges,
		"node_count":     len(nodes),
		"edge_count":     len(edges),
		"timestamp_nano": time.Now().UnixNano(),
	})
	return []mcp.ResourceContents{
		mcp.TextResourceContents{URI: "topology://current", MIMEType: "application/json", Text: string(data)},
	}, nil
}

func (s *Server) handleReadAnomaliesResource(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	data, _ := json.Marshal(map[string]interface{}{
		"anomalies": []interface{}{},
		"message":   "Recent anomalies are streamed via notifications.",
		"timestamp": time.Now().UnixNano(),
	})
	return []mcp.ResourceContents{
		mcp.TextResourceContents{URI: "topology://anomalies", MIMEType: "application/json", Text: string(data)},
	}, nil
}

func (s *Server) handleReadPolicyResource(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
	if s.policy == nil {
		data, _ := json.Marshal(map[string]string{"status": "not initialized"})
		return []mcp.ResourceContents{
			mcp.TextResourceContents{URI: "policy://rules", MIMEType: "application/json", Text: string(data)},
		}, nil
	}
	data, _ := json.Marshal(s.policy.GetReport())
	return []mcp.ResourceContents{
		mcp.TextResourceContents{URI: "policy://rules", MIMEType: "application/json", Text: string(data)},
	}, nil
}
