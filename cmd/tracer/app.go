package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"ebpf-autoheal/internal/config"
	"ebpf-autoheal/internal/detection"
	apperrors "ebpf-autoheal/internal/errors"
	"ebpf-autoheal/internal/graph"
	mcppkg "ebpf-autoheal/internal/mcp"
	"ebpf-autoheal/internal/metrics"
	"ebpf-autoheal/internal/remediation"
	"ebpf-autoheal/internal/resolver"
)

// App 封装整个 eBPF 探针的生命周期。
type App struct {
	cfg        *config.Config
	graph      *graph.ServiceGraph
	history    *detection.ServiceHistory
	policy     *remediation.Engine
	mitigation *remediation.Service
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
	httpProbeObjs   http_probeObjects
	httpProbeLinks  []link.Link
	httpEventsRd    *ringbuf.Reader
	httpProbeActive bool
	httpProbeMu     sync.Mutex

	// Redis protocol trace
	redisObjs redis_traceObjects
	redisRd   *ringbuf.Reader

	// Protocol classifier
	protoClsObjs proto_classifierObjects
	protoClsRd   *ringbuf.Reader

	// Trace context extraction
	traceCtxObjs trace_contextObjects
	traceCtxRd   *ringbuf.Reader

	// TCP RTT（请求级往返延迟）
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
	policyEngine := remediation.NewEngine(os.Getenv("POLICY_FILE"))
	mitigationSvc := remediation.NewService(cfg, policyEngine)

	ifaceName := os.Getenv("EBPF_IFACE")
	if ifaceName == "" {
		ifaceName = "ens33"
	}

	g := graph.NewServiceGraph()
	history := detection.NewServiceHistory(100, cfg.HistoryExpireMin, cfg.HistoryMatchMinSim)

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

	// ===== HTTP uprobe（仅加载 eBPF 对象，不挂载；异常时按需动态挂载） =====
	if err := a.initHTTPProbe(a.cfg.HTTPProbeTarget); err != nil {
		slog.Info(fmt.Sprintf("HTTP probe init failed: %v", err))
	}
	go a.consumeHTTPEvents(ctx)

	// ===== tcp_conntrack（tracepoint sock/inet_sock_set_state） =====
	// Reference: iovisor/bcc libbpf-tools/tcpstates (BSD-2 License)
	connObjs := tcp_conntrackObjects{}
	if err := loadTcp_conntrackObjects(&connObjs, nil); err != nil {
		a.mainRd.Close()
		a.kpExit.Close()
		a.kpEnter.Close()
		a.tracerObjs.Close()
		return fmt.Errorf("load tcp_conntrack objects (%v): %w", err, apperrors.ErrEBPFLoad)
	}
	a.connObjs = connObjs

	tpConn, err := link.Tracepoint("sock", "inet_sock_set_state", connObjs.TpSockSetState, nil)
	if err != nil {
		a.connObjs.Close()
		a.mainRd.Close()
		a.kpExit.Close()
		a.kpEnter.Close()
		a.tracerObjs.Close()
		return fmt.Errorf("attach tracepoint/sock/inet_sock_set_state (%v): %w", err, apperrors.ErrKprobeAttach)
	}
	a.kpConn = tpConn // tracepoint link stored here; kpClose stays nil

	connRd, err := ringbuf.NewReader(connObjs.ConnEvents)
	if err != nil {
		a.kpConn.Close()
		a.connObjs.Close()
		a.mainRd.Close()
		a.kpExit.Close()
		a.kpEnter.Close()
		a.tracerObjs.Close()
		return fmt.Errorf("create conntrack ringbuf reader (%v): %w", err, apperrors.ErrRingBufCreate)
	}
	a.connRd = connRd

	// ===== TCP RTT（fentry tcp_close + kernel srtt_us） =====
	// Reference: cilium/ebpf examples/tcprtt (MIT License)
	rttObjs := tcp_rttObjects{}
	if err := loadTcp_rttObjects(&rttObjs, nil); err != nil {
		slog.Info(fmt.Sprintf("tcp_rtt load failed (RTT measurement unavailable): %v", err))
	} else {
		a.rttObjs = rttObjs

		fentryRtt, err := link.AttachTracing(link.TracingOptions{
			Program: rttObjs.TcpClose,
		})
		if err != nil {
			slog.Info(fmt.Sprintf("tcp_rtt fentry/tcp_close attach failed: %v", err))
			a.rttObjs.Close()
		} else {
			a.kpSendRtt = fentryRtt // reuse field for fentry link
			rttRd, err := ringbuf.NewReader(rttObjs.RttEvents)
			if err != nil {
				slog.Info(fmt.Sprintf("tcp_rtt ringbuf create failed: %v", err))
				a.kpSendRtt.Close()
				a.rttObjs.Close()
				a.kpSendRtt = nil
			} else {
				a.rttRd = rttRd
				slog.Info("tcp_rtt fentry loaded — kernel SRTT measurement active (cilium/ebpf tcprtt pattern)")
			}
		}
	}

	// ===== Redis 协议解析 =====
	redisObjs := redis_traceObjects{}
	if err := loadRedis_traceObjects(&redisObjs, nil); err != nil {
		slog.Info(fmt.Sprintf("redis_trace load failed (Redis protocol parsing unavailable): %v", err))
	} else {
		a.redisObjs = redisObjs
		kpRedis, err := link.Kprobe("tcp_sendmsg", redisObjs.KprobeRedisSendmsg, nil)
		if err != nil {
			slog.Info(fmt.Sprintf("redis_trace kprobe attach failed: %v", err))
			a.redisObjs.Close()
		} else {
			redisRd, err := ringbuf.NewReader(redisObjs.RedisEvents)
			if err != nil {
				slog.Info(fmt.Sprintf("redis_trace ringbuf create failed: %v", err))
				kpRedis.Close()
				a.redisObjs.Close()
			} else {
				a.redisRd = redisRd
				go a.consumeRedisEvents(ctx)
				slog.Info("redis_trace probe loaded — Redis RESP command parsing active")
				// 设置默认 Redis 端口
				portKey := uint32(0)
				defaultPort := uint16(6379)
				_ = redisObjs.RedisPorts.Put(&portKey, &defaultPort)
			}
		}
	}

	// ===== 协议分类器 =====
	pcObjs := proto_classifierObjects{}
	if err := loadProto_classifierObjects(&pcObjs, nil); err != nil {
		slog.Info(fmt.Sprintf("proto_classifier load failed: %v", err))
	} else {
		a.protoClsObjs = pcObjs
		kpPC, err := link.Kprobe("tcp_sendmsg", pcObjs.KprobeProtoClassify, nil)
		if err != nil {
			slog.Info(fmt.Sprintf("proto_classifier kprobe attach failed: %v", err))
			a.protoClsObjs.Close()
		} else {
			pcRd, err := ringbuf.NewReader(pcObjs.ProtoEvents)
			if err != nil {
				slog.Info(fmt.Sprintf("proto_classifier ringbuf create failed: %v", err))
				kpPC.Close()
				a.protoClsObjs.Close()
			} else {
				a.protoClsRd = pcRd
				go a.consumeProtoEvents(ctx)
				slog.Info("proto_classifier probe loaded")
			}
		}
	}

	// ===== Trace 上下文提取 =====
	tcObjs := trace_contextObjects{}
	if err := loadTrace_contextObjects(&tcObjs, nil); err != nil {
		slog.Info(fmt.Sprintf("trace_context load failed: %v", err))
	} else {
		a.traceCtxObjs = tcObjs
		kpTC, err := link.Kprobe("tcp_sendmsg", tcObjs.KprobeTraceContext, nil)
		if err != nil {
			slog.Info(fmt.Sprintf("trace_context kprobe attach failed: %v", err))
			a.traceCtxObjs.Close()
		} else {
			tcRd, err := ringbuf.NewReader(tcObjs.TraceContextEvents)
			if err != nil {
				slog.Info(fmt.Sprintf("trace_context ringbuf create failed: %v", err))
				kpTC.Close()
				a.traceCtxObjs.Close()
			} else {
				a.traceCtxRd = tcRd
				go a.consumeTraceEvents(ctx)
				slog.Info("trace_context probe loaded — distributed tracing context extraction active")
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

	// 启动自健康检查
	go a.runHealthCheck(ctx)

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
	if a.kpSendRtt != nil {
		a.kpSendRtt.Close()
	}
	if a.rttObjs.TcpClose != nil {
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
	if a.tracerObjs.tracerPrograms.KprobeTcpSendmsg != nil {
		a.tracerObjs.Close()
	}
	if a.connObjs.TpSockSetState != nil {
		a.connObjs.Close()
	}
	if a.redisRd != nil {
		a.redisRd.Close()
	}
	if a.protoClsRd != nil {
		a.protoClsRd.Close()
	}
	if a.protoClsObjs.KprobeProtoClassify != nil {
		a.protoClsObjs.Close()
	}
	if a.traceCtxRd != nil {
		a.traceCtxRd.Close()
	}
	if a.traceCtxObjs.KprobeTraceContext != nil {
		a.traceCtxObjs.Close()
	}
	if a.redisObjs.KprobeRedisSendmsg != nil {
		if a.redisObjs.KprobeRedisSendmsg != nil {
			a.redisObjs.Close()
		}
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

// adjustSamplingOnAnomaly 根据异常检测结果动态调整 eBPF 采样率。
func (a *App) adjustSamplingOnAnomaly(suspects []graph.Suspicion) {
	normalInterval := uint64(a.cfg.NormalSamplingIntervalNs)
	adaptiveInterval := uint64(a.cfg.AdaptiveSamplingIntervalNs)

	hasAnomaly := len(suspects) > 0 && suspects[0].Score > a.cfg.AdaptiveSamplingThreshold
	targetInterval := normalInterval
	if hasAnomaly {
		targetInterval = adaptiveInterval
	}

	key := uint32(0)

	// 更新主 tracer 采样率
	if a.tracerObjs.tracerMaps.SamplingConfig != nil {
		_ = a.tracerObjs.tracerMaps.SamplingConfig.Put(&key, &targetInterval)
	}

	// 更新 RTT 采样率
	if a.rttObjs.tcp_rttMaps.RttSamplingConfig != nil {
		_ = a.rttObjs.tcp_rttMaps.RttSamplingConfig.Put(&key, &targetInterval)
	}
}

// reportMetricsToPrometheus 将图的当前状态同步到 Prometheus 指标。
func (a *App) reportMetricsToPrometheus() {
	a.graph.RLock()
	defer a.graph.RUnlock()
	for _, e := range a.graph.Edges {
		metrics.AnomalyScore.WithLabelValues(e.Src, e.Dst).Set(e.AnomalyScore)
		metrics.RootCauseScore.WithLabelValues(e.Dst).Set(e.AnomalyScore)
	}
	for _, n := range a.graph.Nodes {
		metrics.NodeAvgLatency.WithLabelValues(n.ID).Set(n.AvgLat)
	}
}

// uint32ToIP 将小端序 uint32 转换为 net.IP。
func uint32ToIP(val uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, val)
	return ip
}
