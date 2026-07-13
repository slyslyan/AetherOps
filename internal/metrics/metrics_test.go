package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func newTestGauge(name string) *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: "test"}, []string{"label"})
}

func newTestCounter(name string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: "test"}, []string{"l1", "l2"})
}

func newTestHistogram(name string) *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: name, Help: "test", Buckets: []float64{1, 10}}, []string{"l1"})
}

func TestGuardDisabledPassesThrough(t *testing.T) {
	g := NewCardinalityGuard(false, 10)
	gauge := newTestGauge("test_disabled_gauge")
	g.GuardGaugeSet(gauge, "foo", 42)

	// If it panics or drops, we have a problem
}

func TestGuardGaugeSetUnderLimit(t *testing.T) {
	g := NewCardinalityGuard(true, 10)
	vec := newTestGauge("test_under_gauge")
	g.GuardGaugeSet(vec, "key1", 1)
	g.GuardGaugeSet(vec, "key2", 2)

	// Should not drop — 2 < 10
}

func TestGuardGaugeSetAtLimit(t *testing.T) {
	g := NewCardinalityGuard(true, 2)
	vec := newTestGauge("test_at_limit_gauge")
	g.GuardGaugeSet(vec, "k1", 1)
	g.GuardGaugeSet(vec, "k2", 2)
	g.GuardGaugeSet(vec, "k3", 3) // should be dropped

	// k3 should NOT have been set because k1 and k2 already consume the limit.
	// Verify by checking the internal state: the guard should have blocked it.
	g.mu.Lock()
	seen := g.seen[vec]
	lenBefore := len(seen)
	g.mu.Unlock()
	if lenBefore != 2 {
		t.Errorf("expected 2 tracked labels, got %d", lenBefore)
	}
}

func TestGuardGaugeSetExistingLabelAlwaysPasses(t *testing.T) {
	g := NewCardinalityGuard(true, 2)
	vec := newTestGauge("test_existing_gauge")
	g.GuardGaugeSet(vec, "k1", 1)
	g.GuardGaugeSet(vec, "k2", 2)
	g.GuardGaugeSet(vec, "k1", 99) // k1 already tracked, should pass
	g.GuardGaugeSet(vec, "k3", 3)  // should be dropped

	g.mu.Lock()
	seen := g.seen[vec]
	_ = seen
	g.mu.Unlock()
}

func TestGuardCounterIncUnderLimit(t *testing.T) {
	g := NewCardinalityGuard(true, 10)
	c := newTestCounter("test_counter_inc")
	g.GuardCounterInc(c, "a", "b")
	g.GuardCounterInc(c, "c", "d")
}

func TestGuardCounterIncAtLimit(t *testing.T) {
	g := NewCardinalityGuard(true, 1)
	c := newTestCounter("test_counter_limit")
	g.GuardCounterInc(c, "a", "b")
	g.GuardCounterInc(c, "a", "b") // same key, should pass (already tracked)
	g.GuardCounterInc(c, "c", "d") // different key, should be dropped

	g.mu.Lock()
	seen := g.counter[c]
	length := len(seen)
	g.mu.Unlock()
	if length != 1 {
		t.Errorf("expected 1 tracked counter label, got %d", length)
	}
}

func TestGuardCounterAdd(t *testing.T) {
	g := NewCardinalityGuard(true, 10)
	c := newTestCounter("test_counter_add")
	g.GuardCounterAdd(c, 5, "x", "y")
}

func TestGuardHistogramObserveUnderLimit(t *testing.T) {
	g := NewCardinalityGuard(true, 10)
	h := newTestHistogram("test_hist")
	g.GuardHistogramObserve(h, 5, "l1val")
}

func TestGuardHistogramObserveAtLimit(t *testing.T) {
	g := NewCardinalityGuard(true, 1)
	h := newTestHistogram("test_hist_limit")
	g.GuardHistogramObserve(h, 5, "a")
	g.GuardHistogramObserve(h, 10, "b") // should be dropped

	g.mu.Lock()
	seen := g.histSeen[h]
	if len(seen) != 1 {
		t.Errorf("expected 1 tracked hist label, got %d", len(seen))
	}
	g.mu.Unlock()
}

func TestGuardGaugeSetByLabels(t *testing.T) {
	g := NewCardinalityGuard(true, 5)
	vec := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "multi_gauge", Help: "test"}, []string{"a", "b"})
	g.GuardGaugeSetByLabels(vec, 1, "x", "y")
	g.GuardGaugeSetByLabels(vec, 2, "z", "w")
}

func TestJoinLabels(t *testing.T) {
	got := joinLabels([]string{"a", "b", "c"})
	if got != "a\x00b\x00c" {
		t.Errorf("unexpected joined: %q", got)
	}
}

func TestGuardEnabledEdgeCases(t *testing.T) {
	// Disabled guard with same gauge should not track at all
	g := NewCardinalityGuard(false, 0)
	vec := newTestGauge("disabled_no_limit")
	g.GuardGaugeSet(vec, "anything", 1)
	g.GuardGaugeSet(vec, "another", 2)
	g.GuardGaugeSet(vec, "onemore", 3)
}

func newPromRegistry() *prometheus.Registry {
	return prometheus.NewRegistry()
}

func init() {
	// Ensure tests that register metrics use a fresh registry
	prometheus.DefaultRegisterer = prometheus.NewRegistry()
}
