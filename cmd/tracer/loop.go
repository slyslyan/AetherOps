package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"ebpf-autoheal/internal/detection"
	"ebpf-autoheal/internal/metrics"
)

// RunMainLoop 运行主事件循环，阻塞直到 ctx 取消或 Ring Buffer 关闭。
func (a *App) RunMainLoop(ctx context.Context) error {
	<-a.ready

	go a.consumeConnEvents(ctx)
	go a.consumeRTTEvents(ctx)

	simulate := false
	simulateStr := os.Getenv("SIMULATE_LATENCY")
	simulate = simulateStr == "1" || strings.ToLower(simulateStr) == "true"
	simDelayMs := 2000.0
	if ds := os.Getenv("SIMULATED_DELAY_MS"); ds != "" {
		if v, err := strconv.ParseFloat(ds, 64); err == nil && v > 0 {
			simDelayMs = v
		}
	}

	topoTick := time.NewTicker(time.Duration(a.cfg.TopologyPrintInterval) * time.Second)
	analysisTick := time.NewTicker(time.Duration(a.cfg.AnalysisInterval) * time.Second)
	tcDropCleanupTick := time.NewTicker(1 * time.Minute)
	defer topoTick.Stop()
	defer analysisTick.Stop()
	defer tcDropCleanupTick.Stop()

	// 定时打印拓扑
	go func() {
		for {
			select {
			case <-topoTick.C:
				a.graph.PrintStats(nil, nil)
			case <-ctx.Done():
				return
			}
		}
	}()

	// 定时执行根因分析
	go func() {
		for {
			select {
			case <-analysisTick.C:
				suspects := detection.AnalyzeRootCause(a.graph, a.cfg)
				// Report anomaly scores + node latency to Prometheus.
				a.reportMetricsToPrometheus()
				expertMatches := detection.MatchExpertRules(a.graph)
				for _, m := range expertMatches {
					slog.Info(fmt.Sprintf("Expert rule: %s (%.2f) — %s: %s", m.RuleName, m.Severity, m.Node, m.Reason))
				}
				a.adjustSamplingOnAnomaly(suspects)
				if len(suspects) > 0 {
					slog.Info("Root cause analysis: high-latency suspects")
					for _, s := range suspects {
						slog.Info(fmt.Sprintf("  suspect: %s (score: %.2f, avg latency: %.2f ms, calls: %d)",
							s.Node, s.Score, s.AvgLat, s.CallCount))
					}
					a.StartHTTPProbe()
					a.mitigation.PerformMitigation(suspects, a.graph, nil, nil)
					if a.mcpSrv != nil {
						top := suspects[0]
						chain := make([]string, len(suspects))
						for i, s := range suspects {
							chain[i] = s.Node
						}
						a.mcpSrv.PublishAnomaly(top.Node, top.Score, top.AvgLat, top.CallCount, chain)
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// 定时清理 TC drop 规则
	go func() {
		for {
			select {
			case <-tcDropCleanupTick.C:
				a.cleanupExpiredTCRules()
			case <-ctx.Done():
				return
			}
		}
	}()

	// ===== 主循环：读取 Ring Buffer =====
	for {
		record, err := a.mainRd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				slog.Info("ringbuf closed, exiting")
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			metrics.AgentErrors.Inc()
			metrics.RingbufReadErrors.WithLabelValues("main").Inc()
			slog.Warn(fmt.Sprintf("ringbuf read failed: %v", err))
			time.Sleep(100 * time.Millisecond)
			continue
		}
		metrics.AgentEvents.Inc()
		metrics.RingbufEvents.WithLabelValues("main").Inc()

		var raw netEventRaw
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			metrics.AgentErrors.Inc()
			metrics.RingbufReadErrors.WithLabelValues("main").Inc()
			slog.Warn(fmt.Sprintf("parse failed: %v", err))
			continue
		}
		comm := strings.TrimRight(string(raw.Comm[:]), "\x00")
		delayMs := float64(raw.Delta) / 1e6
		if raw.Saddr == 0 && raw.Daddr == 0 {
			fmt.Printf("PID=%d (%s) [failed: Family=%d]\n", raw.Pid, comm, raw.Family)
			continue
		}
		srcIP := uint32ToIP(raw.Saddr)
		dstIP := uint32ToIP(raw.Daddr)
		if simulate {
			delayMs = simDelayMs
		}
		srcService := a.resolver.Resolve(raw.Pid, comm)
		dstService := fmt.Sprintf("%s:%d", dstIP, raw.Dport)
		isError := delayMs > 1000.0
		a.graph.AddCall(srcService, dstService, delayMs, isError)
		metrics.EdgeLatency.WithLabelValues(srcService, dstService, "tcp_sendmsg").Observe(delayMs)
		metrics.EdgeCalls.WithLabelValues(srcService, dstService).Inc()
		if isError {
			metrics.EdgeErrors.WithLabelValues(srcService, dstService).Inc()
		}
		fmt.Printf("PID=%d (%s) %s:%d -> %s:%d delay=%.2f ms\n",
			raw.Pid, comm, srcIP, raw.Sport, dstIP, raw.Dport, delayMs)
	}
}
