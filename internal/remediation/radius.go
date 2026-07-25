package remediation

import (
	"fmt"
	"strings"

	"ebpf-autoheal/internal/graph"
	pb "ebpf-autoheal/proto/gen"
)

// BlastRadiusGate 爆炸半径门控结果。
type BlastRadiusGate struct {
	Allowed       bool
	EscalateHuman bool
	Reason        string
}

// affectedStats 返回 targetNode 的上下游服务数量和错误预算消耗百分比。
func affectedStats(g *graph.ServiceGraph, targetNode string) (upCount, downCount int, budgetPct float64) {
	for _, e := range g.Edges {
		if e.Dst == targetNode {
			upCount++
		}
		if e.Src == targetNode {
			downCount++
		}
	}

	totalCalls := int64(0)
	nodeCalls := int64(0)
	for _, e := range g.Edges {
		totalCalls += e.Count
		if e.Src == targetNode || e.Dst == targetNode {
			nodeCalls += e.Count
		}
	}
	if totalCalls > 0 {
		budgetPct = float64(nodeCalls) / float64(totalCalls) * 100
	}
	return
}

// GateByBlastRadius 基于服务的上下游影响范围做自愈门控。
// 阈值：上下游影响 > 20 服务 → 升级人工；> 10 → 拒绝自动执行。
// 错误预算消耗 > 15% → 升级人工。
func GateByBlastRadius(g *graph.ServiceGraph, targetNode string) BlastRadiusGate {
	upCount, downCount, budgetPct := affectedStats(g, targetNode)
	totalAffected := upCount + downCount

	if totalAffected > 20 {
		return BlastRadiusGate{
			Allowed:       false,
			EscalateHuman: true,
			Reason: fmt.Sprintf(
				"%s affects %d services (up=%d down=%d) > 20 — escalate to human",
				targetNode, totalAffected, upCount, downCount,
			),
		}
	}

	if totalAffected > 10 {
		return BlastRadiusGate{
			Allowed:       false,
			EscalateHuman: false,
			Reason: fmt.Sprintf(
				"%s affects %d services (up=%d down=%d) > 10 — auto-remediation denied",
				targetNode, totalAffected, upCount, downCount,
			),
		}
	}

	if budgetPct > 15 {
		return BlastRadiusGate{
			Allowed:       true,
			EscalateHuman: true,
			Reason: fmt.Sprintf(
				"%s error budget consumption %.1f%% > 15%% — escalate to human review",
				targetNode, budgetPct,
			),
		}
	}

	return BlastRadiusGate{
		Allowed:       true,
		EscalateHuman: false,
		Reason: fmt.Sprintf(
			"%s affects %d services, budget %.1f%% — auto-remediation allowed",
			targetNode, totalAffected, budgetPct,
		),
	}
}

// Evaluate computes the impact of taking an action on targetNode.
func Evaluate(g *graph.ServiceGraph, targetNode string, action pb.RemediationAction, profileDurationSec int) *pb.RemediationReport {
	report := &pb.RemediationReport{
		TargetNode: targetNode,
		Action:     action,
	}

	affectedUp := make(map[string]bool)
	affectedDown := make(map[string]bool)

	for _, e := range g.Edges {
		if e.Src == targetNode {
			affectedDown[e.Dst] = true
		}
		if e.Dst == targetNode {
			affectedUp[e.Src] = true
		}
	}

	for s := range affectedUp {
		report.AffectedServices = append(report.AffectedServices, s)
	}
	for s := range affectedDown {
		report.AffectedServices = append(report.AffectedServices, s)
	}
	report.AffectedUpstreamCount = int32(len(affectedUp))
	report.AffectedDownstreamCount = int32(len(affectedDown))

	_, _, budgetPct := affectedStats(g, targetNode)
	report.EstimatedErrorBudgetConsumption = budgetPct
	report.EstimatedDowntimeSeconds = float64(profileDurationSec + 5)

	report.RiskLevel = assignRiskLevel(targetNode, action, report)
	report.Recommendation = buildRecommendation(targetNode, action, report)

	return report
}

func assignRiskLevel(targetNode string, action pb.RemediationAction, report *pb.RemediationReport) pb.RiskLevel {
	switch action {
	case pb.RemediationAction_TC_DROP:
		if report.AffectedDownstreamCount > 5 {
			return pb.RiskLevel_RISK_MEDIUM
		}
		return pb.RiskLevel_RISK_LOW
	case pb.RemediationAction_SCALE_UP:
		return pb.RiskLevel_RISK_LOW
	case pb.RemediationAction_POD_RESTART:
		if report.AffectedUpstreamCount > 3 || report.EstimatedErrorBudgetConsumption > 10 {
			return pb.RiskLevel_RISK_HIGH
		}
		return pb.RiskLevel_RISK_MEDIUM
	case pb.RemediationAction_CONFIG_CHANGE, pb.RemediationAction_IMAGE_ROLLBACK:
		return pb.RiskLevel_RISK_HIGH
	default:
		return pb.RiskLevel_RISK_UNKNOWN
	}
}

func buildRecommendation(targetNode string, action pb.RemediationAction, report *pb.RemediationReport) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Action %s on %s affects %d upstream and %d downstream services. ",
		action, targetNode, report.AffectedUpstreamCount, report.AffectedDownstreamCount))
	b.WriteString(fmt.Sprintf("Estimated error budget consumption: %.1f%%. ",
		report.EstimatedErrorBudgetConsumption))

	switch report.RiskLevel {
	case pb.RiskLevel_RISK_LOW:
		b.WriteString("Low risk — safe to auto-execute.")
	case pb.RiskLevel_RISK_MEDIUM:
		b.WriteString("Medium risk — recommend TEE sandbox execution with audit logging.")
	case pb.RiskLevel_RISK_HIGH:
		b.WriteString("High risk — requires human approval. Generate GitOps PR.")
	}
	return b.String()
}
