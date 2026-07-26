package detection

import (
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"
	"time"

	"ebpf-autoheal/internal/config"
	"ebpf-autoheal/internal/graph"
)

// AnalyzeRootCause 在图上执行完整的根因分析流程。
func AnalyzeRootCause(g *graph.ServiceGraph, cfg *config.Config) []graph.Suspicion {
	g.Lock()
	defer g.Unlock()

	// 第 1 步：计算每条边的异常分数
	for _, e := range g.Edges {
		if e.Count < 2 && e.RttCount < 2 {
			e.AnomalyScore = 0
			continue
		}

		deltaCount := e.Count - e.LastCount
		currentQPS := float64(deltaCount) / cfg.AnalysisWindowSec
		if e.CallEma == 0 {
			e.CallEma = currentQPS
		} else {
			e.CallEma = graph.EmaAlpha*currentQPS + (1-graph.EmaAlpha)*e.CallEma
		}

		e.CallAnomaly = 0
		if cfg.CallQPSThreshold > 0 && e.CallEma > 0 && currentQPS < e.CallEma*cfg.CallQPSDropRatio {
			e.CallAnomaly = 1.0 + (e.CallEma-currentQPS)/e.CallEma
		}

		// Compute latRatio using tcp_sendmsg (kernel buffer copy) stats.
		baseline := e.BaselineP95
		if baseline == 0 {
			baseline = e.P95
		}
		threshold := baseline * cfg.P95Multiplier
		if threshold < cfg.MinLatThresholdMs {
			threshold = cfg.MinLatThresholdMs
		}
		sendmsgLatRatio := e.AvgLat / threshold
		if sendmsgLatRatio < 1.0 {
			sendmsgLatRatio = 0
		}

		// Compute latRatio using RTT (end-to-end round-trip) stats.
		// RTT baseline reflects real network latency, not just kernel buffer copy.
		rttLatRatio := 0.0
		if e.RttCount >= 2 {
			rttBaseline := e.RttBaselineP95
			if rttBaseline == 0 {
				rttBaseline = e.RttP95
			}
			rttThreshold := rttBaseline * cfg.P95Multiplier
			if rttThreshold < cfg.MinLatThresholdMs {
				rttThreshold = cfg.MinLatThresholdMs
			}
			rttLatRatio = e.RttAvgLat / rttThreshold
			if rttLatRatio < 1.0 {
				rttLatRatio = 0
			}
		}

		// Use the stronger signal: max of sendmsg-based and RTT-based latRatio.
		latRatio := sendmsgLatRatio
		if rttLatRatio > latRatio {
			latRatio = rttLatRatio
		}

		errorFactor := 1.0
		if e.Count > 0 {
			errorFactor += float64(e.Errors) / float64(e.Count)
		}

		e.AnomalyScore = latRatio*errorFactor + e.CallAnomaly*cfg.CallAnomalyWeight
	}

	for _, e := range g.Edges {
		e.LastCount = e.Count
	}

	// 第 2 步：反向随机游走
	probs := faultPropagationRank(g)
	if len(probs) == 0 {
		return nil
	}

	var sorted []kv
	for node, score := range probs {
		sorted = append(sorted, kv{node, score})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Score > sorted[j].Score })

	var suspects []graph.Suspicion
	for i, item := range sorted {
		if i >= cfg.MaxSuspects {
			break
		}
		n := g.Nodes[item.Node]
		if n == nil {
			continue
		}
		isIP := strings.Contains(item.Node, ":") && len(strings.Split(item.Node, ":")[0]) > 0
		suspects = append(suspects, graph.Suspicion{
			Node: item.Node, Score: item.Score * 1000,
			AvgLat: n.AvgLat, CallCount: n.CallCount, IsIPPort: isIP,
		})
	}

	// 第 3 步：故障集群分组
	clusters := ClusterSuspects(suspects)
	if len(clusters) > 0 {
		slog.Info("fault clusters detected", "count", len(clusters))
		for i, c := range clusters {
			nodes := make([]string, len(c.Nodes))
			for j, s := range c.Nodes {
				nodes[j] = fmt.Sprintf("%s(%.2f)", s.Node, s.Score)
			}
			slog.Info(fmt.Sprintf("  cluster %d: %v", i+1, nodes))
		}
	}

	return suspects
}

type kv struct {
	Node  string
	Score float64
}

// faultPropagationRank 在反向图上执行带重启的随机游走。
func faultPropagationRank(g *graph.ServiceGraph) map[string]float64 {
	const restartProb = 0.15
	const maxIter = 50
	const epsilon = 1e-8

	seeds := make(map[string]float64)
	totalSeed := 0.0
	for _, e := range g.Edges {
		if e.AnomalyScore > 0 {
			seeds[e.Dst] += e.AnomalyScore
			totalSeed += e.AnomalyScore
		}
	}
	if totalSeed == 0 {
		return nil
	}
	for node := range seeds {
		seeds[node] /= totalSeed
	}

	prob := make(map[string]float64)
	for node, p := range seeds {
		prob[node] = p
	}

	for iter := 0; iter < maxIter; iter++ {
		nextProb := make(map[string]float64)

		for node, seed := range seeds {
			nextProb[node] += restartProb * seed
		}

		for node, p := range prob {
			if p < epsilon {
				continue
			}
			inEdges := g.InEdges[node]
			if len(inEdges) == 0 {
				continue
			}
			totalWeight := 0.0
			for _, e := range inEdges {
				totalWeight += e.AnomalyScore
			}
			if totalWeight == 0 {
				continue
			}
			propagate := (1 - restartProb) * p
			for _, e := range inEdges {
				src := e.Src
				weight := e.AnomalyScore
				nextProb[src] += propagate * weight / totalWeight
			}
		}
		prob = nextProb
	}
	return prob
}

// ClusterSuspects 将嫌疑节点按分数相近程度分组。
func ClusterSuspects(suspects []graph.Suspicion) []graph.SuspicionCluster {
	if len(suspects) <= 1 {
		return nil
	}
	var clusters []graph.SuspicionCluster
	currentCluster := graph.SuspicionCluster{Nodes: []graph.Suspicion{suspects[0]}}
	for i := 1; i < len(suspects); i++ {
		prev := suspects[i-1]
		curr := suspects[i]
		if math.Abs(prev.Score-curr.Score) < prev.Score*0.15 {
			currentCluster.Nodes = append(currentCluster.Nodes, curr)
		} else {
			clusters = append(clusters, currentCluster)
			currentCluster = graph.SuspicionCluster{Nodes: []graph.Suspicion{curr}}
		}
	}
	clusters = append(clusters, currentCluster)
	return clusters
}

// HistoryRecord 保存一次根因分析的历史记录。
type HistoryRecord struct {
	Time time.Time
	ID   string
}

// ServiceHistory 管理根因分析的历史记录，用于模式匹配。
type ServiceHistory struct {
	records   []HistoryRecord
	maxSize   int
	expireMin time.Duration
	minSim    float64
}

// NewServiceHistory 创建历史记录管理器。
func NewServiceHistory(maxSize int, expireMin, minSim float64) *ServiceHistory {
	return &ServiceHistory{
		records:   make([]HistoryRecord, 0, maxSize),
		maxSize:   maxSize,
		expireMin: time.Duration(expireMin * float64(time.Minute)),
		minSim:    minSim,
	}
}

// Record 记录一次分析。
func (h *ServiceHistory) Record(rec HistoryRecord) {
	h.records = append(h.records, rec)
	if len(h.records) > h.maxSize {
		h.records = h.records[1:]
	}
}

// FindSimilar 查找与当前故障相似的历史记录。
func (h *ServiceHistory) FindSimilar(id string) (bool, string) {
	now := time.Now()
	for _, old := range h.records {
		if now.Sub(old.Time) > h.expireMin {
			continue
		}
		if old.ID == id {
			return true, "与 " + old.Time.Format("15:04:05") + " 的故障模式相似"
		}
	}
	return false, ""
}

// JaccardSimilarity 计算两个字符串集合的 Jaccard 相似度。
func JaccardSimilarity(a, b []string) float64 {
	setA := make(map[string]bool)
	for _, s := range a {
		setA[s] = true
	}
	setB := make(map[string]bool)
	for _, s := range b {
		setB[s] = true
	}
	intersection := 0
	for k := range setA {
		if setB[k] {
			intersection++
		}
	}
	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}
