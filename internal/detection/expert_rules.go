package detection

import (
	"fmt"
	"sort"

	"ebpf-autoheal/internal/graph"
)

// ExpertMatch 表示一条命中的专家规则及其诊断结果。
type ExpertMatch struct {
	RuleName        string  // 规则名称
	Severity        float64 // 0-1，严重程度
	SuggestedAction string  // 建议的自愈动作
	Node            string  // 嫌疑节点
	Reason          string  // 命中原因
}

// rule 定义一条专家规则。
type rule struct {
	name     string
	match    func(g *graph.ServiceGraph) []ExpertMatch
	severity float64
	action   string
}

var rules = []rule{
	{name: "cpu-throttle", match: matchCPUThrottle, severity: 0.6, action: "SCALE_UP"},
	{name: "conn-pool-exhaustion", match: matchConnPoolExhaustion, severity: 0.8, action: "POD_RESTART"},
	{name: "network-partition", match: matchNetworkPartition, severity: 0.9, action: "TC_DROP"},
	{name: "cascading-failure", match: matchCascadingFailure, severity: 0.7, action: "TC_DROP"},
	{name: "retry-storm", match: matchRetryStorm, severity: 0.5, action: "CONFIG_CHANGE"},
}

// MatchExpertRules 在拓扑图上运行所有专家规则，返回命中的匹配结果。
// 规则按严重程度降序排列。当 MCP/Python 不可用时作为 Go 本地降级诊断。
func MatchExpertRules(g *graph.ServiceGraph) []ExpertMatch {
	var matches []ExpertMatch
	for _, r := range rules {
		m := r.match(g)
		for i := range m {
			m[i].Severity = r.severity
			m[i].SuggestedAction = r.action
			m[i].RuleName = r.name
		}
		matches = append(matches, m...)
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Severity > matches[j].Severity
	})
	return matches
}

// matchCPUThrottle 检测 CPU 节流模式：
// 同一源节点的所有出边 P95 同时升高，但错误率保持低位（<1%）。
func matchCPUThrottle(g *graph.ServiceGraph) []ExpertMatch {
	if len(g.OutEdges) < 2 {
		return nil
	}
	var matches []ExpertMatch
	for src, edges := range g.OutEdges {
		if len(edges) < 2 {
			continue
		}
		allElevated := true
		lowErrors := true
		for _, e := range edges {
			if e.Count < 5 {
				allElevated = false
				break
			}
			if e.BaselineP95 > 0 && e.P95 < e.BaselineP95*1.5 {
				allElevated = false
			}
			errorRate := float64(0)
			if e.Count > 0 {
				errorRate = float64(e.Errors) / float64(e.Count)
			}
			if errorRate > 0.01 {
				lowErrors = false
			}
		}
		if allElevated && lowErrors {
			reasons := make([]string, 0)
			for _, e := range edges {
				if e.BaselineP95 > 0 && e.P95 > e.BaselineP95*2 {
					reasons = append(reasons, e.Dst)
				}
			}
			reason := "all outgoing edges latency elevated with low error rate"
			if len(reasons) > 0 {
				reason += ", worst: "
				for i, r := range reasons {
					if i > 0 {
						reason += ", "
					}
					reason += r
				}
			}
			matches = append(matches, ExpertMatch{Node: src, Reason: reason})
		}
	}
	return matches
}

// matchConnPoolExhaustion 检测连接池耗尽模式：
// 单条数据库边高延迟+高错误，但同源的邻居边（到其他目标的边）表现正常。
func matchConnPoolExhaustion(g *graph.ServiceGraph) []ExpertMatch {
	var matches []ExpertMatch
	for _, e := range g.Edges {
		if e.Count < 5 {
			continue
		}
		errorRate := float64(0)
		if e.Count > 0 {
			errorRate = float64(e.Errors) / float64(e.Count)
		}
		// 高延迟（>2x baseline）且高错误率（>10%）
		if e.BaselineP95 <= 0 || e.P95 < e.BaselineP95*2 || errorRate < 0.1 {
			continue
		}
		// 检查邻居边（同 src 的其他边）
		neighbors := g.OutEdges[e.Src]
		badCount := 0
		allNormal := true
		for _, n := range neighbors {
			if n.Dst == e.Dst {
				continue
			}
			if n.Count < 3 {
				continue
			}
			badCount++
			if n.BaselineP95 > 0 && n.P95 > n.BaselineP95*1.5 {
				allNormal = false
			}
			nErrRate := float64(0)
			if n.Count > 0 {
				nErrRate = float64(n.Errors) / float64(n.Count)
			}
			if nErrRate > 0.05 {
				allNormal = false
			}
		}
		if allNormal && badCount > 0 {
			reason := fmt.Sprintf("%s -> %s high latency (P95=%.1fms) and error rate (%.0f%%) while neighbor edges are normal",
				e.Src, e.Dst, e.P95, errorRate*100)
			matches = append(matches, ExpertMatch{Node: e.Dst, Reason: reason})
		}
	}
	return matches
}

// matchNetworkPartition 检测网络分区模式：
// 单个源节点的所有出边错误率接近 100%。
func matchNetworkPartition(g *graph.ServiceGraph) []ExpertMatch {
	var matches []ExpertMatch
	for src, edges := range g.OutEdges {
		if len(edges) < 2 {
			continue
		}
		totalCalls := int64(0)
		totalErrors := int64(0)
		for _, e := range edges {
			totalCalls += e.Count
			totalErrors += e.Errors
		}
		if totalCalls < 5 {
			continue
		}
		errRate := float64(totalErrors) / float64(totalCalls)
		if errRate > 0.9 {
			matches = append(matches, ExpertMatch{
				Node:   src,
				Reason: fmt.Sprintf("%s all edges have %.0f%% error rate, likely network partition", src, errRate*100),
			})
		}
	}
	return matches
}

// matchCascadingFailure 检测级联故障模式：
// 在一条调用链上，延迟从上游到下游递增。
func matchCascadingFailure(g *graph.ServiceGraph) []ExpertMatch {
	var matches []ExpertMatch
	// 遍历所有边，寻找具有延迟递增特征的调用链
	for _, e := range g.Edges {
		if e.Count < 5 || e.BaselineP95 <= 0 {
			continue
		}
		latRatio := e.P95 / e.BaselineP95
		if latRatio < 1.5 {
			continue
		}
		// 检查此边的 dst 是否有进一步下游，且下游延迟更高
		downstream := g.OutEdges[e.Dst]
		cascadeCount := 0
		for _, d := range downstream {
			if d.Count < 3 || d.BaselineP95 <= 0 {
				continue
			}
			if d.P95/d.BaselineP95 > latRatio {
				cascadeCount++
			}
		}
		if cascadeCount > 0 {
			matches = append(matches, ExpertMatch{
				Node:   e.Dst,
				Reason: fmt.Sprintf("%s -> %s latency elevated (P95=%.1fms), cascading to %s downstream", e.Src, e.Dst, e.P95, e.Dst),
			})
		}
	}
	return matches
}

// matchRetryStorm 检测重试风暴模式：
// 调用量 > 3x 正常，但每次调用的延迟仅微增。
func matchRetryStorm(g *graph.ServiceGraph) []ExpertMatch {
	var matches []ExpertMatch
	for _, e := range g.Edges {
		deltaCount := e.Count - e.LastCount
		if deltaCount < 10 || e.CallEma <= 0 {
			continue
		}
		currentQPS := float64(deltaCount) / 15.0
		qpsRatio := currentQPS / e.CallEma
		if qpsRatio < 3.0 {
			continue
		}
		if e.BaselineP95 > 0 && e.P95 < e.BaselineP95*1.5 {
			matches = append(matches, ExpertMatch{
				Node:   e.Dst,
				Reason: fmt.Sprintf("%s -> %s call volume %.1fx normal, latency only slightly elevated, suspect retry storm", e.Src, e.Dst, qpsRatio),
			})
		}
	}
	return matches
}
