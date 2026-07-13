package graph

import (
	"fmt"
	"math"
	"sort"
	"sync"
)

const emaAlpha = 0.2

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

	LastCount   int64
	CallEma     float64
	CallAnomaly float64
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

// AddCall 添加一次服务调用记录。
func (g *ServiceGraph) AddCall(src, dst string, latencyMs float64, isError bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.getOrCreateNode(src)
	g.getOrCreateNode(dst)

	key := EdgeKey(src, dst)
	e, ok := g.Edges[key]
	if !ok {
		e = &ServiceEdge{
			Src:          src,
			Dst:          dst,
			WindowSize:   30,
			LatencyWindow: make([]float64, 0, 30),
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
		e.EmaLat = emaAlpha*e.AvgLat + (1-emaAlpha)*e.EmaLat
	}

	e.LatencyWindow = append(e.LatencyWindow, latencyMs)
	if len(e.LatencyWindow) > e.WindowSize {
		e.LatencyWindow = e.LatencyWindow[1:]
	}
	e.P95 = Percentile(e.LatencyWindow, 95.0)

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
