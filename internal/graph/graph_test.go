package graph

import (
	"math"
	"testing"
)

func TestNewServiceGraph(t *testing.T) {
	g := NewServiceGraph()
	if g == nil {
		t.Fatal("NewServiceGraph() returned nil")
	}
	if len(g.Nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(g.Nodes))
	}
	if len(g.Edges) != 0 {
		t.Errorf("expected 0 edges, got %d", len(g.Edges))
	}
}

func TestAddCall(t *testing.T) {
	g := NewServiceGraph()
	g.AddCall("svc-a", "svc-b", 10.5, false)

	if len(g.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(g.Nodes))
	}
	if g.Nodes["svc-a"] == nil || g.Nodes["svc-b"] == nil {
		t.Error("expected nodes svc-a and svc-b to exist")
	}

	key := EdgeKey("svc-a", "svc-b")
	e, ok := g.Edges[key]
	if !ok {
		t.Fatal("expected edge svc-a->svc-b to exist")
	}
	if e.Count != 1 {
		t.Errorf("expected count 1, got %d", e.Count)
	}
	if e.AvgLat != 10.5 {
		t.Errorf("expected AvgLat 10.5, got %f", e.AvgLat)
	}

	// Node stats
	if g.Nodes["svc-b"].CallCount != 1 {
		t.Errorf("expected dst CallCount 1, got %d", g.Nodes["svc-b"].CallCount)
	}
}

func TestAddCallErrorIncrementsErrors(t *testing.T) {
	g := NewServiceGraph()
	g.AddCall("a", "b", 5, true)
	g.AddCall("a", "b", 5, false)

	e := g.Edges[EdgeKey("a", "b")]
	if e.Errors != 1 {
		t.Errorf("expected 1 error, got %d", e.Errors)
	}
	if e.Count != 2 {
		t.Errorf("expected count 2, got %d", e.Count)
	}
}

func TestAddCallUpdatesLatencyWindow(t *testing.T) {
	g := NewServiceGraph()
	for i := 0; i < 35; i++ {
		g.AddCall("a", "b", float64(i), false)
	}

	e := g.Edges[EdgeKey("a", "b")]
	if len(e.LatencyWindow) > e.WindowSize {
		t.Errorf("latency window exceeded WindowSize: %d > %d", len(e.LatencyWindow), e.WindowSize)
	}
	if len(e.LatencyWindow) != e.WindowSize {
		t.Errorf("expected window size %d, got %d", e.WindowSize, len(e.LatencyWindow))
	}
	// Last values should be 5..34 (the most recent 30)
	if e.LatencyWindow[0] != 5 {
		t.Errorf("expected first window value 5, got %f", e.LatencyWindow[0])
	}
}

func TestAddCallOutEdgesAndInEdges(t *testing.T) {
	g := NewServiceGraph()
	g.AddCall("a", "b", 1, false)
	g.AddCall("a", "c", 2, false)
	g.AddCall("b", "c", 3, false)

	if len(g.OutEdges["a"]) != 2 {
		t.Errorf("expected 2 out edges from a, got %d", len(g.OutEdges["a"]))
	}
	if len(g.InEdges["c"]) != 2 {
		t.Errorf("expected 2 in edges to c, got %d", len(g.InEdges["c"]))
	}
	if len(g.OutEdges["b"]) != 1 {
		t.Errorf("expected 1 out edge from b, got %d", len(g.OutEdges["b"]))
	}
}

func TestPercentileEmpty(t *testing.T) {
	if got := Percentile(nil, 95); got != 0 {
		t.Errorf("expected 0 for empty data, got %f", got)
	}
}

func TestPercentileSingleValue(t *testing.T) {
	if got := Percentile([]float64{42}, 95); got != 42 {
		t.Errorf("expected 42, got %f", got)
	}
}

func TestPercentile(t *testing.T) {
	data := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	tests := []struct {
		p    float64
		want float64
	}{
		{50, 5.5},
		{95, 9.55},
		{0, 1},
		{100, 10},
	}
	for _, tt := range tests {
		got := Percentile(data, tt.p)
		if math.Abs(got-tt.want) > 0.01 {
			t.Errorf("P%.0f = %f, want %f", tt.p, got, tt.want)
		}
	}
}

func TestEdgeKey(t *testing.T) {
	if got := EdgeKey("a", "b"); got != "a->b" {
		t.Errorf("expected 'a->b', got '%s'", got)
	}
}

func TestNewServiceGraphConcurrentAddCall(t *testing.T) {
	g := NewServiceGraph()
	done := make(chan bool, 2)
	add := func(src, dst string) {
		for i := 0; i < 100; i++ {
			g.AddCall(src, dst, float64(i), false)
		}
		done <- true
	}
	go add("x", "y")
	go add("y", "z")
	<-done
	<-done

	if g.Nodes["x"] == nil || g.Nodes["y"] == nil || g.Nodes["z"] == nil {
		t.Error("expected all nodes to exist after concurrent adds")
	}
}
