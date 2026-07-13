package metrics

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// ===== 业务指标 =====

var (
	EdgeLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ebpf_edge_latency_ms",
			Help:    "Latency of calls between services in ms",
			Buckets: []float64{0.5, 1, 5, 10, 20, 50, 100, 200, 500, 1000, 2000},
		},
		[]string{"src", "dst"},
	)

	EdgeCalls = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_edge_calls_total",
			Help: "Total number of calls between services",
		},
		[]string{"src", "dst"},
	)

	EdgeErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_edge_errors_total",
			Help: "Total number of error calls between services",
		},
		[]string{"src", "dst"},
	)

	AnomalyScore = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_edge_anomaly_score",
			Help: "Current anomaly score of the edge",
		},
		[]string{"src", "dst"},
	)

	NodeAvgLatency = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_node_avg_latency_ms",
			Help: "Average latency of incoming calls to a node",
		},
		[]string{"node"},
	)

	RootCauseScore = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_root_cause_score",
			Help: "Root cause suspicion score of the node",
		},
		[]string{"node"},
	)

	Mitigation = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_mitigation_total",
			Help: "Total number of mitigations triggered",
		},
		[]string{"node", "action"},
	)

	HTTPTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_http_requests_total",
			Help: "Total number of HTTP requests observed",
		},
		[]string{"method", "status"},
	)

	HTTPLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ebpf_http_request_duration_ms",
			Help:    "HTTP request duration in ms",
			Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 3000},
		},
		[]string{"method", "status"},
	)
)

// ===== 自监控指标 =====

var (
	AgentEvents = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_agent_events_total",
		Help: "Total ring buffer events processed",
	})

	AgentErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ebpf_agent_errors_total",
		Help: "Total errors during event processing",
	})

	AgentUp = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_agent_up",
		Help: "1 if agent is running",
	})
)

func init() {
	prometheus.MustRegister(EdgeLatency)
	prometheus.MustRegister(EdgeCalls)
	prometheus.MustRegister(EdgeErrors)
	prometheus.MustRegister(AnomalyScore)
	prometheus.MustRegister(NodeAvgLatency)
	prometheus.MustRegister(RootCauseScore)
	prometheus.MustRegister(Mitigation)
	prometheus.MustRegister(HTTPTotal)
	prometheus.MustRegister(HTTPLatency)
	prometheus.MustRegister(AgentEvents)
	prometheus.MustRegister(AgentErrors)
	prometheus.MustRegister(AgentUp)
}

// CardinalityGuard 限制每个 Prometheus 指标的标签组合数，
// 防止动态拓扑导致标签基数爆炸。
type CardinalityGuard struct {
	enabled bool
	max     int

	mu       sync.Mutex
	seen     map[*prometheus.GaugeVec]map[string]bool
	counter  map[*prometheus.CounterVec]map[string]bool
	histSeen map[*prometheus.HistogramVec]map[string]bool
}

// NewCardinalityGuard 创建标签基数保护器。
func NewCardinalityGuard(enabled bool, max int) *CardinalityGuard {
	return &CardinalityGuard{
		enabled:  enabled,
		max:      max,
		seen:     make(map[*prometheus.GaugeVec]map[string]bool),
		counter:  make(map[*prometheus.CounterVec]map[string]bool),
		histSeen: make(map[*prometheus.HistogramVec]map[string]bool),
	}
}

// GuardGaugeSet 安全设置 Gauge 值。
func (g *CardinalityGuard) GuardGaugeSet(m *prometheus.GaugeVec, labelValue string, val float64) {
	if !g.enabled {
		m.WithLabelValues(labelValue).Set(val)
		return
	}
	g.mu.Lock()
	seen, ok := g.seen[m]
	if !ok {
		seen = make(map[string]bool)
		g.seen[m] = seen
	}
	if len(seen) >= g.max && !seen[labelValue] {
		g.mu.Unlock()
		slog.Info(fmt.Sprintf("cardinality guard dropped gauge: %v (max=%d)", labelValue, g.max))
		return
	}
	seen[labelValue] = true
	g.mu.Unlock()
	m.WithLabelValues(labelValue).Set(val)
}

// GuardCounterInc 安全增加 Counter 值。
func (g *CardinalityGuard) GuardCounterInc(c *prometheus.CounterVec, labels ...string) {
	if !g.enabled {
		c.WithLabelValues(labels...).Inc()
		return
	}
	key := joinLabels(labels)
	g.mu.Lock()
	seen, ok := g.counter[c]
	if !ok {
		seen = make(map[string]bool)
		g.counter[c] = seen
	}
	if len(seen) >= g.max && !seen[key] {
		g.mu.Unlock()
		slog.Info(fmt.Sprintf("cardinality guard dropped counter inc: %v (max=%d)", key, g.max))
		return
	}
	seen[key] = true
	g.mu.Unlock()
	c.WithLabelValues(labels...).Inc()
}

// GuardCounterAdd 安全增加 Counter 值（指定增量）。
func (g *CardinalityGuard) GuardCounterAdd(c *prometheus.CounterVec, val float64, labels ...string) {
	if !g.enabled {
		c.WithLabelValues(labels...).Add(val)
		return
	}
	key := joinLabels(labels)
	g.mu.Lock()
	seen, ok := g.counter[c]
	if !ok {
		seen = make(map[string]bool)
		g.counter[c] = seen
	}
	if len(seen) >= g.max && !seen[key] {
		g.mu.Unlock()
		slog.Info(fmt.Sprintf("cardinality guard dropped counter add: %v (max=%d)", key, g.max))
		return
	}
	seen[key] = true
	g.mu.Unlock()
	c.WithLabelValues(labels...).Add(val)
}

// GuardHistogramObserve 安全记录 Histogram 观测值。
func (g *CardinalityGuard) GuardHistogramObserve(h *prometheus.HistogramVec, val float64, labels ...string) {
	if !g.enabled {
		h.WithLabelValues(labels...).Observe(val)
		return
	}
	key := joinLabels(labels)
	g.mu.Lock()
	seen, ok := g.histSeen[h]
	if !ok {
		seen = make(map[string]bool)
		g.histSeen[h] = seen
	}
	if len(seen) >= g.max && !seen[key] {
		g.mu.Unlock()
		slog.Info(fmt.Sprintf("cardinality guard dropped histogram: %v (max=%d)", key, g.max))
		return
	}
	seen[key] = true
	g.mu.Unlock()
	h.WithLabelValues(labels...).Observe(val)
}

// GuardGaugeSetByLabels 安全设置多标签 Gauge 值。
func (g *CardinalityGuard) GuardGaugeSetByLabels(m *prometheus.GaugeVec, val float64, labelValues ...string) {
	if !g.enabled {
		m.WithLabelValues(labelValues...).Set(val)
		return
	}
	key := joinLabels(labelValues)
	g.mu.Lock()
	seen, ok := g.seen[m]
	if !ok {
		seen = make(map[string]bool)
		g.seen[m] = seen
	}
	if len(seen) >= g.max && !seen[key] {
		g.mu.Unlock()
		slog.Info(fmt.Sprintf("cardinality guard dropped gauge by labels: %v (max=%d)", key, g.max))
		return
	}
	seen[key] = true
	g.mu.Unlock()
	m.WithLabelValues(labelValues...).Set(val)
}

func joinLabels(labels []string) string {
	var b []byte
	for i, l := range labels {
		if i > 0 {
			b = append(b, '\x00')
		}
		b = append(b, l...)
	}
	return string(b)
}
