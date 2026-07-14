package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	apperrors "ebpf-autoheal/internal/errors"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"ebpf-autoheal/internal/metrics"
)

// initHTTPProbe 加载 HTTP uprobe 程序并挂载到目标二进制。
func (a *App) initHTTPProbe(targetExe string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock (%v): %w", err, apperrors.ErrRemoveMemlock)
	}

	var objs http_probeObjects
	if err := loadHttp_probeObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading HTTP probe BPF objects failed (%v): %w", err, apperrors.ErrHTTPProbeLoad)
	}
	a.httpProbeObjs = objs

	rd, err := ringbuf.NewReader(objs.HttpEvents)
	if err != nil {
		objs.Close()
		return fmt.Errorf("creating HTTP ringbuf reader failed (%v): %w", err, apperrors.ErrRingBufCreate)
	}
	a.httpEventsRd = rd

	if targetExe == "" {
		return nil
	}

	exe, err := link.OpenExecutable(targetExe)
	if err != nil {
		slog.Info(fmt.Sprintf("HTTP uprobe: open %s failed: %v, HTTP parsing unavailable", targetExe, err))
		return nil
	}

	up1, err := exe.Uprobe("net/http.(*conn).readRequest", objs.UprobeHttpReadRequest, nil)
	if err != nil {
		slog.Info(fmt.Sprintf("HTTP uprobe: readRequest attach failed: %v", err))
	} else {
		a.httpProbeLinks = append(a.httpProbeLinks, up1)
		slog.Info("HTTP uprobe: readRequest attached")
	}

	up2, err := exe.Uprobe("net/http.(*response).WriteHeader", objs.UprobeHttpWriteHeader, nil)
	if err != nil {
		slog.Info(fmt.Sprintf("HTTP uprobe: WriteHeader attach failed: %v", err))
	} else {
		a.httpProbeLinks = append(a.httpProbeLinks, up2)
		slog.Info("HTTP uprobe: WriteHeader attached")
	}

	up3, err := exe.Uprobe("google.golang.org/grpc.(*ClientConn).Invoke", objs.UprobeGrpcInvoke, nil)
	if err != nil {
		slog.Info(fmt.Sprintf("gRPC uprobe: Invoke attach failed: %v (target may not use gRPC)", err))
	} else {
		a.httpProbeLinks = append(a.httpProbeLinks, up3)
		slog.Info("gRPC uprobe: Invoke attached")
	}

	return nil
}

// closeHTTPProbe 分离所有 uprobe 并释放资源。
func (a *App) closeHTTPProbe() {
	for _, l := range a.httpProbeLinks {
		l.Close()
	}
	a.httpProbeLinks = nil
	if a.httpEventsRd != nil {
		a.httpEventsRd.Close()
		a.httpEventsRd = nil
	}
	a.httpProbeObjs.Close()
}

// consumeHTTPEvents 持续读取 HTTP 事件 Ring Buffer。
func (a *App) consumeHTTPEvents() {
	if a.httpEventsRd == nil {
		return
	}
	slog.Info("HTTP event consumer started")
	for {
		record, err := a.httpEventsRd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				slog.Info("HTTP ringbuf closed, exiting")
				return
			}
			slog.Info(fmt.Sprintf("HTTP ringbuf read failed: %v", err))
			continue
		}
		var evt httpEventRaw
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			slog.Info(fmt.Sprintf("HTTP event parse failed: %v", err))
			continue
		}

		statusCode := fmt.Sprintf("%d", evt.StatusCode)
		method := methodToString(evt.Method)
		durationMs := float64(evt.DurationNs) / 1e6

		path := strings.TrimRight(string(evt.Path[:]), "\x00")
		if path == "" {
			path = "/unknown"
		}

		slog.Info(fmt.Sprintf("HTTP: method=%s status=%s path=%s duration=%.2f ms",
			method, statusCode, path, durationMs))

		metrics.HTTPTotal.WithLabelValues(method, statusCode).Inc()
		metrics.HTTPLatency.WithLabelValues(method, statusCode).Observe(durationMs)
	}
}

// methodToString 将 int16 编码的 HTTP 方法转换为字符串。
func methodToString(m uint16) string {
	switch m {
	case 1:
		return "GET"
	case 2:
		return "POST"
	case 3:
		return "PUT"
	case 4:
		return "DELETE"
	case 5:
		return "HEAD"
	case 6:
		return "PATCH"
	default:
		return "UNKNOWN"
	}
}
