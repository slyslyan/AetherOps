package metrics

import (
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
