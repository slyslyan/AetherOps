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

	"ebpf-autoheal/internal/graph"
	"ebpf-autoheal/internal/metrics"
)

// consumeConnEvents 读取 tcp_conntrack 的连接事件 Ring Buffer。
// 短连接（<30s）的连接时长近似等于网络 RTT，使用 AddRttCall 写入独立 RTT 统计。
func (a *App) consumeConnEvents(ctx context.Context) {
	if a.connRd == nil {
		return
	}
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
			slog.Warn(fmt.Sprintf("conntrack ringbuf read failed: %v", err))
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

		if durationMs > 0 && durationMs < 30000 {
			srcSvc := a.resolver.Resolve(evt.Pid, comm)
			dstSvc := fmt.Sprintf("%s:%d", dstIP, evt.Dport)
			isErr := durationMs > 1000.0
			a.graph.AddRttCall(srcSvc, dstSvc, durationMs, isErr)
			metrics.EdgeLatency.WithLabelValues(srcSvc, dstSvc, "tcp_conntrack").Observe(durationMs)
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
			slog.Warn(fmt.Sprintf("rtt ringbuf read failed: %v", err))
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
		a.graph.AddRttCall(srcSvc, dstSvc, rttMs, isErr)
		metrics.EdgeLatency.WithLabelValues(srcSvc, dstSvc, "tcp_rtt").Observe(rttMs)
	}
}

// redisCommandName 将命令 ID 映射为字符串名。
func redisCommandName(cmdID uint8) string {
	switch cmdID {
	case 1:
		return "GET"
	case 2:
		return "SET"
	case 3:
		return "DEL"
	case 4:
		return "MGET"
	case 5:
		return "MSET"
	case 6:
		return "INCR"
	case 7:
		return "DECR"
	case 8:
		return "LPOP"
	case 9:
		return "RPOP"
	case 10:
		return "EVAL"
	case 11:
		return "HGET"
	case 12:
		return "HSET"
	case 13:
		return "PING"
	case 14:
		return "AUTH"
	case 15:
		return "LPUSH"
	case 16:
		return "RPUSH"
	case 17:
		return "SELECT"
	case 18:
		return "EXPIRE"
	case 19:
		return "HGETALL"
	default:
		return "UNKNOWN"
	}
}

// consumeRedisEvents 持续读取 Redis 事件 Ring Buffer。
func (a *App) consumeRedisEvents(ctx context.Context) {
	if a.redisRd == nil {
		return
	}
	slog.Info("Redis event consumer started")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		record, err := a.redisRd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				slog.Info("Redis ringbuf closed, exiting")
				return
			}
			slog.Warn(fmt.Sprintf("Redis ringbuf read failed: %v", err))
			continue
		}
		var evt redisEventRaw
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			slog.Info(fmt.Sprintf("Redis event parse failed: %v", err))
			continue
		}

		cmd := strings.TrimRight(string(evt.Command[:]), "\x00")
		cmdID := evt.Pad[0]
		cmdName := redisCommandName(cmdID)
		if cmd != "" && cmdName == "UNKNOWN" {
			cmdName = cmd
		}

		comm := fmt.Sprintf("pid-%d", evt.Pid)
		srcSvc := a.resolver.Resolve(evt.Pid, comm)
		dstSvc := fmt.Sprintf("redis:%d", 6379)

		// Redis 延迟不可直接测量（只有 send），使用 0 表示仅做协议发现
		a.graph.AddProtocolCall(srcSvc, dstSvc, 0, false, "redis", cmdName)

		metrics.RedisCommands.WithLabelValues(cmdName).Inc()

		slog.Info(fmt.Sprintf("Redis: pid=%d cmd=%s data_len=%d", evt.Pid, cmdName, evt.DataLen))
	}
}

// protoName 返回协议类型 ID 的可读名称。
func protoName(p uint8) string {
	switch p {
	case 1:
		return "http1"
	case 2:
		return "http2"
	case 3:
		return "mysql"
	case 4:
		return "redis"
	default:
		return "unknown"
	}
}

// consumeProtoEvents 持续读取协议分类事件 Ring Buffer。
func (a *App) consumeProtoEvents(ctx context.Context) {
	if a.protoClsRd == nil {
		return
	}
	slog.Info("Protocol classifier event consumer started")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		record, err := a.protoClsRd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			slog.Warn(fmt.Sprintf("proto_classifier ringbuf read failed: %v", err))
			continue
		}
		var evt protoEventRaw
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			slog.Info(fmt.Sprintf("proto_classifier parse failed: %v", err))
			continue
		}
		comm := strings.TrimRight(string(evt.Comm[:]), "\x00")
		dstIP := uint32ToIP(evt.Daddr)
		proto := protoName(evt.DetectedProto)

		srcSvc := a.resolver.Resolve(evt.Pid, comm)
		dstSvc := fmt.Sprintf("%s:%d", dstIP, evt.Dport)
		a.graph.AddProtocolCall(srcSvc, dstSvc, 0, false, proto, "")

		slog.Info(fmt.Sprintf("Proto: pid=%d (%s) %s:%d -> %s:%d proto=%s confidence=%d%%",
			evt.Pid, comm, uint32ToIP(evt.Saddr), evt.Sport, dstIP, evt.Dport, proto, evt.Confidence))
	}
}

// traceSourceName 返回 trace source ID 的可读名称。
func traceSourceName(s uint8) string {
	switch s {
	case 1:
		return "w3c"
	case 2:
		return "jaeger"
	case 3:
		return "datadog"
	case 4:
		return "generic"
	default:
		return "unknown"
	}
}

// consumeTraceEvents 持续读取分布式追踪上下文事件 Ring Buffer。
func (a *App) consumeTraceEvents(ctx context.Context) {
	if a.traceCtxRd == nil {
		return
	}
	slog.Info("Trace context event consumer started")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		record, err := a.traceCtxRd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			slog.Warn(fmt.Sprintf("trace_context ringbuf read failed: %v", err))
			continue
		}
		var evt traceEventRaw
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			slog.Info(fmt.Sprintf("trace_context parse failed: %v", err))
			continue
		}
		srcIP := uint32ToIP(evt.Saddr)
		dstIP := uint32ToIP(evt.Daddr)
		source := traceSourceName(evt.TraceSource)

		srcSvc := a.resolver.Resolve(evt.Pid, "")
		dstSvc := fmt.Sprintf("%s:%d", dstIP, evt.Dport)

		tc := graph.TraceContext{
			TraceID:     fmt.Sprintf("%032x", evt.TraceID),
			SpanID:      fmt.Sprintf("%016x", evt.SpanID),
			TraceSource: source,
		}
		a.graph.AddTraceContext(srcSvc, dstSvc, tc)

		slog.Info(fmt.Sprintf("Trace: pid=%d %s:%d -> %s:%d source=%s trace=%s span=%s",
			evt.Pid, srcIP, evt.Sport, dstIP, evt.Dport, source, tc.TraceID[:16], tc.SpanID))
	}
}
