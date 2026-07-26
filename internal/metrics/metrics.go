package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// ===== 业务指标 =====

var (
	EdgeLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ebpf_edge_latency_ms",
			Help:    "Latency of calls between services in ms. Label latency_source distinguishes tcp_sendmsg (kernel buffer copy), tcp_rtt (request-level round-trip), and tcp_conntrack (connection lifetime).",
			Buckets: []float64{0.5, 1, 5, 10, 20, 50, 100, 200, 500, 1000, 2000},
		},
		[]string{"src", "dst", "latency_source"},
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

	// ===== 协议解析指标 =====

	RedisCommands = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_redis_commands_total",
			Help: "Total number of Redis commands observed via eBPF",
		},
		[]string{"command"},
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

	RingbufEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_ringbuf_events_total",
			Help: "Total events read from each ring buffer",
		},
		[]string{"buffer"},
	)

	RingbufDropped = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_ringbuf_dropped_total",
			Help: "Events dropped by ring buffer",
		},
		[]string{"buffer"},
	)

	RingbufReadErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_ringbuf_read_errors_total",
			Help: "Read errors from ring buffer",
		},
		[]string{"buffer"},
	)

	DecisionLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "ebpf_decision_latency_ms",
			Help:    "End-to-end latency from eBPF event to remediation decision",
			Buckets: []float64{10, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000},
		},
	)

	MCPConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_mcp_connections",
		Help: "Number of active MCP client connections",
	})

	MCPToolCalls = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ebpf_mcp_tool_calls_total",
			Help: "Total MCP tool calls by tool name",
		},
		[]string{"tool"},
	)

	EventsPerSecond = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ebpf_events_per_second",
		Help: "Current eBPF event throughput",
	})

	ComponentHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_agent_health",
			Help: "Component health status (1=healthy, 0=unhealthy)",
		},
		[]string{"component"},
	)
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
	prometheus.MustRegister(RedisCommands)
	prometheus.MustRegister(AgentEvents)
	prometheus.MustRegister(AgentErrors)
	prometheus.MustRegister(AgentUp)
	prometheus.MustRegister(RingbufEvents)
	prometheus.MustRegister(RingbufDropped)
	prometheus.MustRegister(RingbufReadErrors)
	prometheus.MustRegister(DecisionLatency)
	prometheus.MustRegister(MCPConnections)
	prometheus.MustRegister(MCPToolCalls)
	prometheus.MustRegister(EventsPerSecond)
	prometheus.MustRegister(ComponentHealth)
}
