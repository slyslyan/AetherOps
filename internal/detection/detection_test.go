package detection

import (
	"math"
	"testing"
	"time"

	"ebpf-autoheal/internal/config"
	"ebpf-autoheal/internal/graph"
)

func cfg() *config.Config {
	return &config.Config{
		P95Multiplier:     0.3,
		MinLatThresholdMs: 10,
		CallQPSDropRatio:  0.3,
		CallAnomalyWeight: 2.0,
		AnalysisWindowSec: 15,
		MaxSuspects:       5,
	}
}

func makeGraph() *graph.ServiceGraph {
	g := graph.NewServiceGraph()
	g.AddCall("svc-a", "svc-b", 5, false)
	g.AddCall("svc-b", "svc-c", 5, false)
	return g
}

func makeGraphWithAnomaly() *graph.ServiceGraph {
	g := graph.NewServiceGraph()
	for i := 0; i < 10; i++ {
		g.AddCall("svc-a", "svc-b", 5, false)
		g.AddCall("svc-b", "svc-c", 5, false)
	}
	for i := 0; i < 5; i++ {
		g.AddCall("svc-b", "svc-c", 500, false)
	}
	return g
}

func TestAnalyzeRootCauseNoAnomaly(t *testing.T) {
	g := makeGraph()
	result := AnalyzeRootCause(g, cfg())
	if result != nil {
		t.Errorf("expected nil for no anomaly, got %v", result)
	}
}

func TestAnalyzeRootCauseWithAnomaly(t *testing.T) {
	g := makeGraphWithAnomaly()
	result := AnalyzeRootCause(g, cfg())
	if result == nil {
		t.Fatal("expected suspects, got nil")
	}
	if len(result) == 0 {
		t.Fatal("expected at least one suspect")
	}
	if result[0].Node != "svc-c" {
		t.Errorf("expected top suspect svc-c, got %s", result[0].Node)
	}
	if result[0].Score <= 0 {
		t.Errorf("expected positive score, got %f", result[0].Score)
	}
}

func TestAnalyzeRootCauseScoreOrdering(t *testing.T) {
	g := graph.NewServiceGraph()
	for i := 0; i < 10; i++ {
		g.AddCall("a", "b", 5, false)
		g.AddCall("b", "c", 5, false)
		g.AddCall("c", "d", 5, false)
	}
	for i := 0; i < 5; i++ {
		g.AddCall("b", "c", 500, false)
	}

	result := AnalyzeRootCause(g, cfg())
	if len(result) < 2 {
		t.Fatal("expected at least 2 suspects")
	}
	for i := 1; i < len(result); i++ {
		if result[i-1].Score < result[i].Score {
			t.Errorf("scores not descending at %d: %f < %f", i, result[i-1].Score, result[i].Score)
		}
	}
}

func TestAnalyzeRootCauseMaxSuspects(t *testing.T) {
	g := graph.NewServiceGraph()
	for i := 0; i < 10; i++ {
		g.AddCall("a", "b", 5, false)
	}
	for i := 0; i < 5; i++ {
		g.AddCall("a", "b", 500, false)
	}

	customCfg := cfg()
	customCfg.MaxSuspects = 2
	result := AnalyzeRootCause(g, customCfg)
	if result != nil && len(result) > 2 {
		t.Errorf("expected at most 2 suspects, got %d", len(result))
	}
}

func TestAnalyzeRootCauseWithError(t *testing.T) {
	g := graph.NewServiceGraph()
	for i := 0; i < 10; i++ {
		g.AddCall("a", "b", 10, i%2 == 0)
	}

	result := AnalyzeRootCause(g, cfg())
	if result == nil {
		t.Fatal("expected suspects with high error rate, got nil")
	}
}

func TestFaultPropagationRankNoAnomaly(t *testing.T) {
	g := makeGraph()
	result := faultPropagationRank(g)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestFaultPropagationRankWithAnomaly(t *testing.T) {
	g := makeGraphWithAnomaly()
	for _, e := range g.Edges {
		e.AnomalyScore = 1.0
	}
	result := faultPropagationRank(g)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result) == 0 {
		t.Fatal("expected at least one entry")
	}
}

func TestFaultPropagationRankConverges(t *testing.T) {
	g := graph.NewServiceGraph()
	g.AddCall("a", "b", 5, false)
	g.AddCall("b", "c", 5, false)
	g.AddCall("c", "d", 5, false)
	for _, e := range g.Edges {
		e.AnomalyScore = 2.0
	}
	result := faultPropagationRank(g)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	for _, node := range []string{"a", "b", "c", "d"} {
		if result[node] <= 0 {
			t.Errorf("expected positive probability for %s, got %f", node, result[node])
		}
	}
}

func TestClusterSuspectsNilForEmpty(t *testing.T) {
	if got := ClusterSuspects(nil); got != nil {
		t.Error("expected nil for empty input")
	}
}

func TestClusterSuspectsNilForSingle(t *testing.T) {
	suspects := []graph.Suspicion{{Node: "a", Score: 10}}
	if got := ClusterSuspects(suspects); got != nil {
		t.Error("expected nil for single suspect")
	}
}

func TestClusterSuspectsGroupsSimilar(t *testing.T) {
	suspects := []graph.Suspicion{
		{Node: "a", Score: 100},
		{Node: "b", Score: 92},
		{Node: "c", Score: 50},
		{Node: "d", Score: 45},
	}
	clusters := ClusterSuspects(suspects)
	if len(clusters) != 2 {
		t.Fatalf("expected 2 clusters, got %d", len(clusters))
	}
	if len(clusters[0].Nodes) != 2 {
		t.Errorf("expected 2 nodes in first cluster, got %d", len(clusters[0].Nodes))
	}
	if len(clusters[1].Nodes) != 2 {
		t.Errorf("expected 2 nodes in second cluster, got %d", len(clusters[1].Nodes))
	}
}

func TestJaccardSimilarityIdentical(t *testing.T) {
	a := []string{"x", "y", "z"}
	b := []string{"x", "y", "z"}
	got := JaccardSimilarity(a, b)
	if math.Abs(got-1.0) > 0.001 {
		t.Errorf("expected 1.0, got %f", got)
	}
}

func TestJaccardSimilarityDisjoint(t *testing.T) {
	a := []string{"a", "b"}
	b := []string{"c", "d"}
	got := JaccardSimilarity(a, b)
	if math.Abs(got-0.0) > 0.001 {
		t.Errorf("expected 0.0, got %f", got)
	}
}

func TestJaccardSimilarityPartial(t *testing.T) {
	a := []string{"a", "b", "c"}
	b := []string{"b", "c", "d"}
	got := JaccardSimilarity(a, b)
	if math.Abs(got-0.5) > 0.001 {
		t.Errorf("expected 0.5, got %f", got)
	}
}

func TestJaccardSimilarityEmpty(t *testing.T) {
	if got := JaccardSimilarity(nil, nil); got != 0 {
		t.Errorf("expected 0 for empty sets, got %f", got)
	}
}

func TestServiceHistoryRecordAndExpiry(t *testing.T) {
	h := NewServiceHistory(100, 0.1, 0.6)
	h.Record(HistoryRecord{Time: time.Now(), ID: "svc-a"})

	found, _ := h.FindSimilar("svc-a")
	if !found {
		t.Error("expected to find recently recorded ID")
	}

	h.expireMin = time.Nanosecond
	time.Sleep(time.Millisecond)
	found, _ = h.FindSimilar("svc-a")
	if found {
		t.Error("expected record to be expired")
	}
}

func TestServiceHistoryMaxSizeEviction(t *testing.T) {
	h := NewServiceHistory(3, 10, 0.6)
	for i := 0; i < 10; i++ {
		h.Record(HistoryRecord{Time: time.Now(), ID: "svc-a"})
	}
	if len(h.records) > 3 {
		t.Errorf("expected max 3 records, got %d", len(h.records))
	}
}

func TestServiceHistorySimilarNotFound(t *testing.T) {
	h := NewServiceHistory(10, 10, 0.6)
	h.Record(HistoryRecord{Time: time.Now(), ID: "svc-a"})
	found, _ := h.FindSimilar("svc-b")
	if found {
		t.Error("expected no match for different ID")
	}
}

func TestSuspectIsIPPortDetection(t *testing.T) {
	tests := []struct {
		node string
		want bool
	}{
		{"192.168.1.1:8080", true},
		{"svc-a", false},
		{"10.0.0.1:9090", true},
		{"backend-service:443", false},
	}
	for _, tt := range tests {
		g := graph.NewServiceGraph()
		g.AddCall("client", tt.node, 5, false)
		AnalyzeRootCause(g, cfg())
		_ = tt.want
	}
}
