package graph

import (
	"fmt"
	"math"
	"sort"
	"sync"
)

const (
	// EmaAlpha is the EMA smoothing factor for average latency.
	EmaAlpha = 0.2

	// BaselineEmaAlpha is the EMA smoothing factor for BaselineP95.
	// A lower value (0.1) makes the baseline more stable against transient spikes.
	BaselineEmaAlpha = 0.1

	// BaselineGateMultiplier gates whether a window P95 is anomalous.
	// When window P95 exceeds BaselineP95 * GateMultiplier, the current window
	// is considered anomalous and is NOT incorporated into the baseline.
	BaselineGateMultiplier = 2.0
)

// ServiceNode 表示服务拓扑中的一个节点。
type ServiceNode struct {
	ID        string
	AvgLat    float64
	ErrorRate float64
	CallCount int64
}

// ServiceEdge 表示两个服务节点之间的调用关系。
type ServiceEdge struct {
	Src          string
	Dst          string
	Count        int64
	TotalLat     float64
	Errors       int64
	AvgLat       float64
	EmaLat       float64
	AnomalyScore float64

	LatencyWindow []float64
	WindowSize    int
	P95           float64

	// BaselineP95 is a stable P95 baseline tracked via EMA with anomaly gating.
	// It only incorporates non-anomalous windows so that bimodal traffic
	// (normal + anomalous) does not inflate the anomaly threshold.
	BaselineP95 float64

	// RTT-specific stats — end-to-end round-trip time (tcp_sendmsg → tcp_recvmsg).
	// Kept independent from the main (tcp_sendmsg kernel buffer) stats so that
	// anomaly detection can use real network RTT without dilution from μs-level
	// kernel buffer copy measurements.
	RttCount       int64
	RttTotalLat    float64
	RttAvgLat      float64
	RttWindow      []float64
	RttWindowSize  int
	RttP95         float64
	RttBaselineP95 float64

	LastCount   int64
	CallEma     float64
	CallAnomaly float64

	// Protocol 标注此边的应用协议类型
	Protocol string

	// ProtocolCommands 统计各协议命令的计数（如 Redis GET:100, SET:50）
	ProtocolCommands map[string]int64

	// RecentTraces 最近的分布式追踪 Trace ID 列表（环形，最多 100 条）
	RecentTraces []TraceContext
}

// TraceContext 分布式追踪上下文。
type TraceContext struct {
	TraceID     string
	SpanID      string
	TraceSource string // "w3c", "jaeger", "datadog", "generic"
}

// ServiceGraph 是完整的服务调用拓扑图。
type ServiceGraph struct {
	mu       sync.RWMutex
	Nodes    map[string]*ServiceNode
	Edges    map[string]*ServiceEdge
	OutEdges map[string][]*ServiceEdge
	InEdges  map[string][]*ServiceEdge
}

// NewServiceGraph 创建一个空的服务拓扑图。
func NewServiceGraph() *ServiceGraph {
	return &ServiceGraph{
		Nodes:    make(map[string]*ServiceNode),
		Edges:    make(map[string]*ServiceEdge),
		OutEdges: make(map[string][]*ServiceEdge),
		InEdges:  make(map[string][]*ServiceEdge),
	}
}

// Lock 返回写锁。
func (g *ServiceGraph) Lock() {
	g.mu.Lock()
}

// Unlock 释放写锁。
func (g *ServiceGraph) Unlock() {
	g.mu.Unlock()
}

// RLock 返回读锁。
func (g *ServiceGraph) RLock() {
	g.mu.RLock()
}

// RUnlock 释放读锁。
func (g *ServiceGraph) RUnlock() {
	g.mu.RUnlock()
}

func (g *ServiceGraph) getOrCreateNode(id string) *ServiceNode {
	if n, ok := g.Nodes[id]; ok {
		return n
	}
	n := &ServiceNode{ID: id}
	g.Nodes[id] = n
	return n
}

// EdgeKey 返回边的 map key。
func EdgeKey(src, dst string) string {
	return src + "->" + dst
}

// AddProtocolCall 添加一次带协议信息的服务调用记录。
func (g *ServiceGraph) AddProtocolCall(src, dst string, latencyMs float64, isError bool, protocol, cmd string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.addCallLocked(src, dst, latencyMs, isError)

	key := EdgeKey(src, dst)
	if e, ok := g.Edges[key]; ok {
		if e.Protocol == "" {
			e.Protocol = protocol
		}
		if e.ProtocolCommands == nil {
			e.ProtocolCommands = make(map[string]int64)
		}
		if cmd != "" {
			e.ProtocolCommands[cmd]++
		}
	}
}

// AddTraceContext 将 Trace 上下文关联到拓扑边。
func (g *ServiceGraph) AddTraceContext(src, dst string, tc TraceContext) {
	g.mu.Lock()
	defer g.mu.Unlock()

	key := EdgeKey(src, dst)
	e, ok := g.Edges[key]
	if !ok {
		return
	}
	const maxTraces = 100
	if len(e.RecentTraces) >= maxTraces {
		e.RecentTraces = e.RecentTraces[1:]
	}
	e.RecentTraces = append(e.RecentTraces, tc)
}

// AddCall 添加一次服务调用记录（tcp_sendmsg 内核缓冲拷贝延迟）。
func (g *ServiceGraph) AddCall(src, dst string, latencyMs float64, isError bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.addCallLocked(src, dst, latencyMs, isError)
}

// AddRttCall 添加一次 TCP RTT 调用记录（tcp_sendmsg → tcp_recvmsg 端到端往返延迟）。
// RTT 统计独立于 tcp_sendmsg 内核缓冲拷贝延迟，不会被 μs 级测量稀释。
func (g *ServiceGraph) AddRttCall(src, dst string, rttMs float64, isError bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	key := EdgeKey(src, dst)
	e, ok := g.Edges[key]
	if !ok {
		e = &ServiceEdge{
			Src:           src,
			Dst:           dst,
			WindowSize:    30,
			RttWindowSize: 30,
		}
		g.Edges[key] = e
		g.OutEdges[src] = append(g.OutEdges[src], e)
		g.InEdges[dst] = append(g.InEdges[dst], e)
	}

	e.RttCount++
	e.RttTotalLat += rttMs
	if isError {
		e.Errors++
	}
	e.RttAvgLat = e.RttTotalLat / float64(e.RttCount)

	e.RttWindow = append(e.RttWindow, rttMs)
	if len(e.RttWindow) > e.RttWindowSize {
		e.RttWindow = e.RttWindow[1:]
	}
	e.RttP95 = Percentile(e.RttWindow, 95.0)

	if e.RttBaselineP95 == 0 {
		e.RttBaselineP95 = e.RttP95
	} else if e.RttP95 < e.RttBaselineP95*BaselineGateMultiplier {
		e.RttBaselineP95 = BaselineEmaAlpha*e.RttP95 + (1-BaselineEmaAlpha)*e.RttBaselineP95
	}
}

// addCallLocked 假定调用者已持有 g.mu 写锁。
func (g *ServiceGraph) addCallLocked(src, dst string, latencyMs float64, isError bool) {
	g.getOrCreateNode(src)
	g.getOrCreateNode(dst)

	key := EdgeKey(src, dst)
	e, ok := g.Edges[key]
	if !ok {
		e = &ServiceEdge{
			Src:           src,
			Dst:           dst,
			WindowSize:    30,
			LatencyWindow: make([]float64, 0, 30),
			RttWindowSize: 30,
		}
		g.Edges[key] = e
		g.OutEdges[src] = append(g.OutEdges[src], e)
		g.InEdges[dst] = append(g.InEdges[dst], e)
	}
	e.Count++
	e.TotalLat += latencyMs
	if isError {
		e.Errors++
	}
	e.AvgLat = e.TotalLat / float64(e.Count)

	if e.EmaLat == 0 {
		e.EmaLat = e.AvgLat
	} else {
		e.EmaLat = EmaAlpha*e.AvgLat + (1-EmaAlpha)*e.EmaLat
	}

	e.LatencyWindow = append(e.LatencyWindow, latencyMs)
	if len(e.LatencyWindow) > e.WindowSize {
		e.LatencyWindow = e.LatencyWindow[1:]
	}
	e.P95 = Percentile(e.LatencyWindow, 95.0)

	if e.BaselineP95 == 0 {
		e.BaselineP95 = e.P95
	} else if e.P95 < e.BaselineP95*BaselineGateMultiplier {
		e.BaselineP95 = BaselineEmaAlpha*e.P95 + (1-BaselineEmaAlpha)*e.BaselineP95
	}

	dstNode := g.Nodes[dst]
	dstNode.CallCount++
	dstNode.ErrorRate = float64(e.Errors) / float64(e.Count)
	var sumLat float64
	var cnt int64
	for _, in := range g.InEdges[dst] {
		cnt += in.Count
		sumLat += in.TotalLat
	}
	if cnt > 0 {
		dstNode.AvgLat = sumLat / float64(cnt)
	}
}

// PrintStats 打印当前拓扑图。
func (g *ServiceGraph) PrintStats(anomalyGetter func(src, dst string) float64, latencyGetter func(node string, lat float64)) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	fmt.Println("\n========== Call Topology ==========")
	for _, e := range g.Edges {
		fmt.Printf("%s -> %s | count:%d avgLat:%.2f ms emaLat:%.2f ms P95:%.2f ms score:%.2f callAnomaly:%.2f errors:%d\n",
			e.Src, e.Dst, e.Count, e.AvgLat, e.EmaLat, e.P95, e.AnomalyScore, e.CallAnomaly, e.Errors)
		if anomalyGetter != nil {
			anomalyGetter(e.Src, e.Dst)
		}
	}
	for _, n := range g.Nodes {
		if latencyGetter != nil {
			latencyGetter(n.ID, n.AvgLat)
		}
	}
	fmt.Println("==============================")
}

// Percentile 计算一组数据的 P 分位数。
func Percentile(data []float64, p float64) float64 {
	if len(data) == 0 {
		return 0
	}
	sorted := make([]float64, len(data))
	copy(sorted, data)
	sort.Float64s(sorted)
	k := (p / 100) * float64(len(sorted)-1)
	f := math.Floor(k)
	c := math.Ceil(k)
	if f == c {
		return sorted[int(f)]
	}
	return sorted[int(f)]*(c-k) + sorted[int(c)]*(k-f)
}
