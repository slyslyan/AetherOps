package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"ebpf-autoheal/internal/analysis"
	"ebpf-autoheal/internal/config"
	apperrors "ebpf-autoheal/internal/errors"
	"ebpf-autoheal/internal/graph"
	mcppkg "ebpf-autoheal/internal/mcp"
	"ebpf-autoheal/internal/metrics"
	"ebpf-autoheal/internal/mitigation"
	"ebpf-autoheal/internal/policy"
	"ebpf-autoheal/internal/resolver"
)

// App 封装整个 eBPF 探针的生命周期。
type App struct {
	cfg        *config.Config
	graph      *graph.ServiceGraph
	history    *analysis.ServiceHistory
	policy     *policy.Engine
	mitigation *mitigation.Service
	mcpSrv     *mcppkg.Server
	resolver   *resolver.ServiceIdentity

	// eBPF 主探针（tcp_sendmsg kprobe/kretprobe）
	tracerObjs tracerObjects
	kpEnter    link.Link
	kpExit     link.Link
	mainRd     *ringbuf.Reader

	// eBPF 连接跟踪（tcp_conntrack）
	connObjs tcp_conntrackObjects
	kpConn   link.Link
	kpClose  link.Link
	connRd   *ringbuf.Reader

	// TC drop（eBPF + tc 命令回退）
	tcDropProg    *ebpf.Program
	tcDropLink    link.Link
	tcDropObjs    tc_dropObjects
	tcDropRules   map[string]time.Time
	tcDropRulesMu sync.Mutex
	tcDropTTL     time.Duration

	// HTTP uprobe
	httpProbeObjs  http_probeObjects
	httpProbeLinks []link.Link
	httpEventsRd   *ringbuf.Reader

	// TCP RTT (request-level round-trip time via tcp_sendmsg → tcp_recvmsg)
	rttObjs   tcp_rttObjects
	kpSendRtt link.Link
	kpRecvRtt link.Link
	rttRd     *ringbuf.Reader

	// 网络接口
	ifaceName string

	// HTTP Prometheus 服务
	httpSrv *http.Server

	ready chan struct{}
}

// NewApp 创建并初始化 App。
func NewApp() (*App, error) {
	cfg := config.LoadFromEnv()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock (%v): %w", err, apperrors.ErrRemoveMemlock)
	}

	svcResolver := resolver.NewServiceIdentity(nil)

	policyEngine := policy.NewEngine(os.Getenv("POLICY_FILE"))

	mitigationSvc := mitigation.NewService(cfg, policyEngine)

	ifaceName := os.Getenv("EBPF_IFACE")
	if ifaceName == "" {
		ifaceName = "ens33"
	}

	g := graph.NewServiceGraph()
	history := analysis.NewServiceHistory(100, cfg.HistoryExpireMin, cfg.HistoryMatchMinSim)

	return &App{
		cfg:         cfg,
		graph:       g,
		history:     history,
		policy:      policyEngine,
		mitigation:  mitigationSvc,
		resolver:    svcResolver,
		ifaceName:   ifaceName,
		tcDropRules: make(map[string]time.Time),
		tcDropTTL:   time.Duration(cfg.TCDropTTL) * time.Minute,
		ready:       make(chan struct{}),
	}, nil
}

// Start 启动所有 eBPF 探针和后台服务。
func (a *App) Start(ctx context.Context) error {
	// ===== 加载 eBPF 主探针 =====
	objs := tracerObjects{}
	if err := loadTracerObjects(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects (%v): %w", err, apperrors.ErrEBPFLoad)
	}
	a.tracerObjs = objs

	kpEnter, err := link.Kprobe("tcp_sendmsg", objs.tracerPrograms.KprobeTcpSendmsg, nil)
	if err != nil {
		a.tracerObjs.Close()
		return fmt.Errorf("attach kprobe/tcp_sendmsg (%v): %w", err, apperrors.ErrKprobeAttach)
	}
	a.kpEnter = kpEnter

	kpExit, err := link.Kretprobe("tcp_sendmsg", objs.tracerPrograms.KretprobeTcpSendmsg, nil)
	if err != nil {
		a.kpEnter.Close()
		a.tracerObjs.Close()
		return fmt.Errorf("attach kretprobe/tcp_sendmsg (%v): %w", err, apperrors.ErrKprobeAttach)
	}
	a.kpExit = kpExit

	rd, err := ringbuf.NewReader(objs.tracerMaps.Events)
	if err != nil {
		a.kpExit.Close()
		a.kpEnter.Close()
		a.tracerObjs.Close()
		return fmt.Errorf("create ringbuf reader (%v): %w", err, apperrors.ErrRingBufCreate)
	}
	a.mainRd = rd

	// ===== TC 丢包程序 =====
	if err := a.initTCDrop(); err != nil {
		slog.Info(fmt.Sprintf("eBPF TC init failed (falling back to tc command): %v", err))
	}

	// ===== HTTP uprobe =====
	if err := a.initHTTPProbe(a.cfg.HTTPProbeTarget); err != nil {
		slog.Info(fmt.Sprintf("HTTP probe init failed: %v", err))
	}

	// ===== tcp_conntrack =====
	connObjs := tcp_conntrackObjects{}
	if err := loadTcp_conntrackObjects(&connObjs, nil); err != nil {
		a.mainRd.Close()
		a.kpExit.Close()
		a.kpEnter.Close()
		a.tracerObjs.Close()
		return fmt.Errorf("load tcp_conntrack objects (%v): %w", err, apperrors.ErrEBPFLoad)
	}
	a.connObjs = connObjs

	kpConn, err := link.Kprobe("tcp_connect", connObjs.KprobeTcpConnect, nil)
	if err != nil {
		a.connObjs.Close()
		a.mainRd.Close()
		a.kpExit.Close()
		a.kpEnter.Close()
		a.tracerObjs.Close()
		return fmt.Errorf("attach kprobe/tcp_connect (%v): %w", err, apperrors.ErrKprobeAttach)
	}
	a.kpConn = kpConn

	kpClose, err := link.Kprobe("tcp_close", connObjs.KprobeTcpClose, nil)
	if err != nil {
		a.kpConn.Close()
		a.connObjs.Close()
		a.mainRd.Close()
		a.kpExit.Close()
		a.kpEnter.Close()
		a.tracerObjs.Close()
		return fmt.Errorf("attach kprobe/tcp_close (%v): %w", err, apperrors.ErrKprobeAttach)
	}
	a.kpClose = kpClose

	connRd, err := ringbuf.NewReader(connObjs.ConnEvents)
	if err != nil {
		a.kpClose.Close()
		a.kpConn.Close()
		a.connObjs.Close()
		a.mainRd.Close()
		a.kpExit.Close()
		a.kpEnter.Close()
		a.tracerObjs.Close()
		return fmt.Errorf("create conntrack ringbuf reader (%v): %w", err, apperrors.ErrRingBufCreate)
	}
	a.connRd = connRd

	// ===== TCP RTT（请求级往返延迟） =====
	rttObjs := tcp_rttObjects{}
	if err := loadTcp_rttObjects(&rttObjs, nil); err != nil {
		slog.Info(fmt.Sprintf("tcp_rtt load failed (RTT measurement unavailable): %v", err))
	} else {
		a.rttObjs = rttObjs

		kpSendRtt, err := link.Kprobe("tcp_sendmsg", rttObjs.KprobeTcpSendmsgRtt, nil)
		if err != nil {
			slog.Info(fmt.Sprintf("tcp_rtt kprobe/tcp_sendmsg attach failed: %v", err))
			a.rttObjs.Close()
		} else {
			a.kpSendRtt = kpSendRtt
			kpRecvRtt, err := link.Kretprobe("tcp_recvmsg", rttObjs.KretprobeTcpRecvmsgRtt, nil)
			if err != nil {
				slog.Info(fmt.Sprintf("tcp_rtt kretprobe/tcp_recvmsg attach failed: %v", err))
				a.kpSendRtt.Close()
				a.rttObjs.Close()
				a.kpSendRtt = nil
			} else {
				a.kpRecvRtt = kpRecvRtt
				rttRd, err := ringbuf.NewReader(rttObjs.RttEvents)
				if err != nil {
					slog.Info(fmt.Sprintf("tcp_rtt ringbuf create failed: %v", err))
					a.kpRecvRtt.Close()
					a.kpSendRtt.Close()
					a.rttObjs.Close()
					a.kpRecvRtt = nil
					a.kpSendRtt = nil
				} else {
					a.rttRd = rttRd
					slog.Info("tcp_rtt probes loaded — request-level RTT measurement active")
				}
			}
		}
	}

	// ===== HTTP 服务（Prometheus + 健康检查） =====
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	a.httpSrv = &http.Server{Addr: a.cfg.MetricsAddr, Handler: mux}
	go func() {
		if err := a.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Info(fmt.Sprintf("HTTP server error: %v", err))
		}
	}()

	// ===== MCP 服务 =====
	a.mcpSrv = mcppkg.NewServer(a.cfg.MCPAddr, a.graph, a.mitigation, a.policy, mcppkg.Config{
		ProfileDurationSec: a.cfg.ProfileDurationSec,
	})
	if err := a.mcpSrv.Start(); err != nil {
		slog.Info(fmt.Sprintf("MCP server start failed: %v", err))
	}

	slog.Info("eBPF-AutoHeal started!")
	slog.Info(fmt.Sprintf("   topology interval: %ds  |  analysis interval: %ds", a.cfg.TopologyPrintInterval, a.cfg.AnalysisInterval))
	slog.Info("   Prometheus: http://localhost:2112/metrics")
	slog.Info("   Health:     http://localhost:2112/healthz")

	close(a.ready)
	return nil
}

// Shutdown 优雅关闭所有组件。
func (a *App) Shutdown(ctx context.Context) {
	slog.Info("shutting down...")

	if a.mainRd != nil {
		a.mainRd.Close()
	}
	if a.connRd != nil {
		a.connRd.Close()
	}
	if a.rttRd != nil {
		a.rttRd.Close()
	}
	if a.kpRecvRtt != nil {
		a.kpRecvRtt.Close()
	}
	if a.kpSendRtt != nil {
		a.kpSendRtt.Close()
	}
	if a.rttObjs.tcp_rttPrograms.KprobeTcpSendmsgRtt != nil {
		a.rttObjs.Close()
	}
	if a.kpExit != nil {
		a.kpExit.Close()
	}
	if a.kpEnter != nil {
		a.kpEnter.Close()
	}
	if a.kpConn != nil {
		a.kpConn.Close()
	}
	if a.kpClose != nil {
		a.kpClose.Close()
	}
	if a.tracerObjs.tracerPrograms.KprobeTcpSendmsg != nil {
		a.tracerObjs.Close()
	}
	if a.connObjs.KprobeTcpConnect != nil {
		a.connObjs.Close()
	}
	a.removeAllTCRules()
	a.closeTCDrop()
	a.closeHTTPProbe()

	if a.mcpSrv != nil {
		a.mcpSrv.Shutdown(ctx)
	}
	if a.httpSrv != nil {
		a.httpSrv.Shutdown(ctx)
	}
	slog.Info("shutdown complete")
}

// RunMainLoop 运行主事件循环，阻塞直到 ctx 取消或 Ring Buffer 关闭。
func (a *App) RunMainLoop(ctx context.Context) error {
	<-a.ready

	go a.consumeConnEvents(ctx)
	go a.consumeHTTPEvents()
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
				suspects := analysis.AnalyzeRootCause(a.graph, a.cfg)
				if len(suspects) > 0 {
					slog.Info("Root cause analysis: high-latency suspects")
					for _, s := range suspects {
						slog.Info(fmt.Sprintf("  suspect: %s (score: %.2f, avg latency: %.2f ms, calls: %d)",
							s.Node, s.Score, s.AvgLat, s.CallCount))
					}
					a.mitigation.PerformMitigation(suspects, nil, nil)
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
			slog.Info(fmt.Sprintf("ringbuf read failed: %v", err))
			continue
		}
		metrics.AgentEvents.Inc()

		var raw netEventRaw
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			metrics.AgentErrors.Inc()
			slog.Info(fmt.Sprintf("parse failed: %v", err))
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
		fmt.Printf("PID=%d (%s) %s:%d -> %s:%d delay=%.2f ms\n",
			raw.Pid, comm, srcIP, raw.Sport, dstIP, raw.Dport, delayMs)
	}
}

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

// uint32ToIP 将小端序 uint32 转换为 net.IP。
func uint32ToIP(val uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, val)
	return ip
}
