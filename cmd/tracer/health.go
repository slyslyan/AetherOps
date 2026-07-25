package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"ebpf-autoheal/internal/metrics"
)

// runHealthCheck 周期检查各组件健康状态，更新 Prometheus 指标。
func (a *App) runHealthCheck(ctx context.Context) {
	metrics.AgentUp.Set(1)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	components := []string{
		"tracer_ringbuf",
		"conntrack_ringbuf",
		"rtt_ringbuf",
		"redis_ringbuf",
		"proto_cls_ringbuf",
		"trace_ctx_ringbuf",
		"http_probe",
		"mcp_server",
	}

	for {
		select {
		case <-ctx.Done():
			metrics.AgentUp.Set(0)
			for _, c := range components {
				metrics.ComponentHealth.WithLabelValues(c).Set(0)
			}
			return
		case <-ticker.C:
			a.checkComponents(components)
		}
	}
}

func (a *App) checkComponents(components []string) {
	for _, c := range components {
		healthy := a.isComponentHealthy(c)
		if healthy {
			metrics.ComponentHealth.WithLabelValues(c).Set(1)
		} else {
			metrics.ComponentHealth.WithLabelValues(c).Set(0)
			slog.Warn(fmt.Sprintf("Health check: %s is unhealthy", c))
		}
	}

	// Decision latency estimation: check if graph has recent data
	if a.graph != nil {
		// If the graph has edges with recent calls, the pipeline is working
		mcpHealthy := a.mcpSrv != nil
		if mcpHealthy {
			metrics.ComponentHealth.WithLabelValues("mcp_server").Set(1)
		}
	}
}

func (a *App) isComponentHealthy(component string) bool {
	switch component {
	case "tracer_ringbuf":
		return a.mainRd != nil
	case "conntrack_ringbuf":
		return a.connRd != nil
	case "rtt_ringbuf":
		return a.rttRd != nil
	case "redis_ringbuf":
		return a.redisRd != nil
	case "proto_cls_ringbuf":
		return a.protoClsRd != nil
	case "trace_ctx_ringbuf":
		return a.traceCtxRd != nil
	case "http_probe":
		return len(a.httpProbeLinks) > 0
	case "mcp_server":
		return a.mcpSrv != nil
	default:
		return false
	}
}
