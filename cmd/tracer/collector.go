package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/ebpf/ringbuf"
)

// consumeConnEvents 读取 tcp_conntrack 的连接事件 Ring Buffer。
func (a *App) consumeConnEvents(ctx context.Context) {
	slog.Info("conntrack event consumer started")
	for {
		record, err := a.connRd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			slog.Info(fmt.Sprintf("conntrack ringbuf read failed: %v", err))
			continue
		}
		var evt connEventRaw
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			slog.Info(fmt.Sprintf("conntrack parse failed: %v", err))
			continue
		}
		comm := strings.TrimRight(string(evt.Comm[:]), "\x00")
		srcIP := uint32ToIP(evt.Saddr)
		dstIP := uint32ToIP(evt.Daddr)

		role := "client"
		if evt.Role == 2 {
			role = "server"
		}
		durationMs := float64(evt.DurationNs) / 1e6
		slog.Info(fmt.Sprintf("CONN %s %s:%d -> %s:%d duration=%.2f ms pid=%d (%s)",
			role, srcIP, evt.Sport, dstIP, evt.Dport, durationMs, evt.Pid, comm))

		// Feed short-lived connection RTT into the graph for anomaly detection.
		// Filter out connections >30s (e.g. pooled DB connections) to avoid
		// polluting the baseline with connection-lifetime durations.
		if durationMs > 0 && durationMs < 30000 {
			srcSvc := a.resolver.Resolve(evt.Pid, comm)
			dstSvc := fmt.Sprintf("%s:%d", dstIP, evt.Dport)
			isErr := durationMs > 1000.0
			a.graph.AddCall(srcSvc, dstSvc, durationMs, isErr)
		}
	}
}

// consumeRTTEvents 读取 tcp_rtt Ring Buffer 中的请求级 RTT 事件。
func (a *App) consumeRTTEvents(ctx context.Context) {
	if a.rttRd == nil {
		return
	}
	slog.Info("RTT event consumer started")
	for {
		record, err := a.rttRd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
			slog.Info(fmt.Sprintf("rtt ringbuf read failed: %v", err))
			continue
		}
		var evt netEventRaw
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			slog.Info(fmt.Sprintf("rtt parse failed: %v", err))
			continue
		}
		comm := strings.TrimRight(string(evt.Comm[:]), "\x00")
		dstIP := uint32ToIP(evt.Daddr)

		rttMs := float64(evt.Delta) / 1e6
		// Filter implausible values.
		if rttMs <= 0 || rttMs > 30000 {
			continue
		}
		srcSvc := a.resolver.Resolve(evt.Pid, comm)
		dstSvc := fmt.Sprintf("%s:%d", dstIP, evt.Dport)
		isErr := rttMs > 1000.0
		a.graph.AddCall(srcSvc, dstSvc, rttMs, isErr)
	}
}
