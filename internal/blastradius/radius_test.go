package blastradius

import (
	"fmt"
	"strings"
	"testing"

	"ebpf-autoheal/internal/graph"
	pb "ebpf-autoheal/proto/gen"
)

func newTestGraph() *graph.ServiceGraph {
	g := graph.NewServiceGraph()
	g.AddCall("frontend", "backend", 10, false)
	g.AddCall("frontend", "auth", 5, false)
	g.AddCall("backend", "database", 20, false)
	g.AddCall("backend", "cache", 15, false)
	g.AddCall("auth", "database", 8, false)
	return g
}

func TestEvaluateComputeAffected(t *testing.T) {
	g := newTestGraph()
	report := Evaluate(g, "backend", pb.RemediationAction_TC_DROP, 10)

	if report.TargetNode != "backend" {
		t.Errorf("expected target 'backend', got '%s'", report.TargetNode)
	}
	if report.AffectedUpstreamCount != 1 {
		t.Errorf("expected 1 upstream (frontend), got %d", report.AffectedUpstreamCount)
	}
	if report.AffectedDownstreamCount != 2 {
		t.Errorf("expected 2 downstreams (database, cache), got %d", report.AffectedDownstreamCount)
	}
}

func TestEvaluateBudgetConsumption(t *testing.T) {
	g := newTestGraph()
	report := Evaluate(g, "backend", pb.RemediationAction_TC_DROP, 10)
	// backend has edges: frontend->backend, backend->database, backend->cache = 3 edges
	// Total edges in graph: 5
	// nodeCalls = frontend->backend(1) + backend->database(1) + backend->cache(1) = 3
	// totalCalls = 5
	if report.EstimatedErrorBudgetConsumption <= 0 {
		t.Errorf("expected positive error budget consumption, got %f", report.EstimatedErrorBudgetConsumption)
	}
}

func TestEvaluateDowntimeSeconds(t *testing.T) {
	report := Evaluate(graph.NewServiceGraph(), "x", pb.RemediationAction_POD_RESTART, 30)
	if report.EstimatedDowntimeSeconds != 35 {
		t.Errorf("expected 35s downtime (30+5), got %f", report.EstimatedDowntimeSeconds)
	}
}

func TestAssignRiskLevelTCDropLow(t *testing.T) {
	g := newTestGraph()
	report := Evaluate(g, "frontend", pb.RemediationAction_TC_DROP, 10)
	if report.RiskLevel != pb.RiskLevel_RISK_LOW {
		t.Errorf("expected RISK_LOW for frontend TC_DROP, got %s", report.RiskLevel)
	}
}

func TestAssignRiskLevelTCDropMedium(t *testing.T) {
	g := graph.NewServiceGraph()
	// Add many downstreams to trigger medium risk
	for i := 0; i < 10; i++ {
		g.AddCall("target", fmt.Sprintf("svc-%d", i), 1, false)
	}
	report := Evaluate(g, "target", pb.RemediationAction_TC_DROP, 10)
	if report.RiskLevel != pb.RiskLevel_RISK_MEDIUM {
		t.Errorf("expected RISK_MEDIUM for TC_DROP with 10 downstreams, got %s", report.RiskLevel)
	}
}

func TestAssignRiskLevelScaleUp(t *testing.T) {
	report := Evaluate(graph.NewServiceGraph(), "x", pb.RemediationAction_SCALE_UP, 10)
	if report.RiskLevel != pb.RiskLevel_RISK_LOW {
		t.Errorf("expected RISK_LOW for SCALE_UP, got %s", report.RiskLevel)
	}
}

func TestAssignRiskLevelPodRestartHigh(t *testing.T) {
	g := graph.NewServiceGraph()
	g.AddCall("u1", "target", 1, false)
	g.AddCall("u2", "target", 1, false)
	g.AddCall("u3", "target", 1, false)
	g.AddCall("u4", "target", 1, false)
	report := Evaluate(g, "target", pb.RemediationAction_POD_RESTART, 10)
	if report.RiskLevel != pb.RiskLevel_RISK_HIGH {
		t.Errorf("expected RISK_HIGH for POD_RESTART with 4 upstreams, got %s", report.RiskLevel)
	}
}

func TestAssignRiskLevelPodRestartMedium(t *testing.T) {
	g := graph.NewServiceGraph()
	g.AddCall("u1", "target", 1, false)
	g.AddCall("u2", "target", 1, false)
	// Add enough unrelated edges to keep error budget under 10%
	for i := 0; i < 200; i++ {
		g.AddCall(fmt.Sprintf("other-%d", i), "sink", 1, false)
	}
	report := Evaluate(g, "target", pb.RemediationAction_POD_RESTART, 10)
	if report.RiskLevel != pb.RiskLevel_RISK_MEDIUM {
		t.Errorf("expected RISK_MEDIUM for POD_RESTART with 2 upstreams, budget=%.1f%%, got %s",
			report.EstimatedErrorBudgetConsumption, report.RiskLevel)
	}
}

func TestAssignRiskLevelConfigChange(t *testing.T) {
	report := Evaluate(graph.NewServiceGraph(), "x", pb.RemediationAction_CONFIG_CHANGE, 10)
	if report.RiskLevel != pb.RiskLevel_RISK_HIGH {
		t.Errorf("expected RISK_HIGH for CONFIG_CHANGE, got %s", report.RiskLevel)
	}
}

func TestAssignRiskLevelImageRollback(t *testing.T) {
	report := Evaluate(graph.NewServiceGraph(), "x", pb.RemediationAction_IMAGE_ROLLBACK, 10)
	if report.RiskLevel != pb.RiskLevel_RISK_HIGH {
		t.Errorf("expected RISK_HIGH for IMAGE_ROLLBACK, got %s", report.RiskLevel)
	}
}

func TestAssignRiskLevelUnknown(t *testing.T) {
	report := Evaluate(graph.NewServiceGraph(), "x", pb.RemediationAction(999), 10)
	if report.RiskLevel != pb.RiskLevel_RISK_UNKNOWN {
		t.Errorf("expected RISK_UNKNOWN for unknown action, got %s", report.RiskLevel)
	}
}

func TestBuildRecommendationLowRisk(t *testing.T) {
	report := Evaluate(graph.NewServiceGraph(), "test-svc", pb.RemediationAction_SCALE_UP, 10)
	if report.Recommendation == "" {
		t.Error("expected non-empty recommendation")
	}
}

func TestBuildRecommendationContainsAction(t *testing.T) {
	report := Evaluate(graph.NewServiceGraph(), "test-svc", pb.RemediationAction_TC_DROP, 10)
	if !strings.Contains(report.Recommendation, "safe") {
		t.Errorf("expected 'safe' in low risk recommendation, got: %s", report.Recommendation)
	}
}

func TestEvaluateEmptyGraph(t *testing.T) {
	g := graph.NewServiceGraph()
	report := Evaluate(g, "nonexistent", pb.RemediationAction_POD_RESTART, 10)
	if report.AffectedUpstreamCount != 0 || report.AffectedDownstreamCount != 0 {
		t.Errorf("expected 0 affected for nonexistent node, got up=%d down=%d",
			report.AffectedUpstreamCount, report.AffectedDownstreamCount)
	}
}

func TestEvaluateAffectedServicesList(t *testing.T) {
	g := graph.NewServiceGraph()
	g.AddCall("frontend", "backend", 5, false)
	g.AddCall("auth", "backend", 3, false)
	report := Evaluate(g, "backend", pb.RemediationAction_POD_RESTART, 10)

	// Affected services should include frontend and auth (upstreams)
	found := make(map[string]bool)
	for _, s := range report.AffectedServices {
		found[s] = true
	}
	if !found["frontend"] || !found["auth"] {
		t.Errorf("expected affected services to include frontend and auth, got %v", report.AffectedServices)
	}
}
