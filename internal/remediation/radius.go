package remediation

import (
	"fmt"
	"strings"

	"ebpf-autoheal/internal/graph"
	pb "ebpf-autoheal/proto/gen"
)

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

	totalCalls := int64(0)
	nodeCalls := int64(0)
	for _, e := range g.Edges {
		totalCalls += e.Count
		if e.Src == targetNode || e.Dst == targetNode {
			nodeCalls += e.Count
		}
	}
	if totalCalls > 0 {
		report.EstimatedErrorBudgetConsumption = float64(nodeCalls) / float64(totalCalls) * 100
	}
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
