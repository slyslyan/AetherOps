# eBPF-AutoHeal: Zero-Instrumentation Microservice Observability & Auto-Healing Platform

<p align="center">
  <img src="https://img.shields.io/badge/License-GPL-blue" alt="License">
  <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go" alt="Go Version">
  <img src="https://img.shields.io/badge/eBPF-Kernel%205.8+-orange?logo=linux" alt="eBPF Support">
  <img src="https://img.shields.io/badge/Kubernetes-Minikube%20v1.38-blueviolet?logo=kubernetes" alt="Kubernetes">
</p>

**eBPF-AutoHeal** is an eBPF-based zero-instrumentation microservice observability and auto-healing platform. It captures all TCP communication at the kernel level without any code modification, builds real-time call topology, pinpoints root causes using **adaptive thresholds, multi-dimensional anomaly scoring, and reverse random walk (PageRank)**. It then triggers kernel-level circuit breaking, Kubernetes Pod isolation/restart, collects CPU/memory flame graphs, goroutine/thread dumps, and packet captures at the failure scene, and finally sends alerts via Feishu/DingTalk webhooks — completing the full SRE closed-loop: **detect → diagnose → heal → preserve → notify**.

> 🇨🇳 中文文档：[项目日志](project-log.md) ｜ [演示与测试指南](testing.md) ｜ [项目简介](PROJECT_INTRO.md) ｜ [面试学习指南](STUDY_GUIDE.md) ｜ [AetherOps 认知平面完全指南](AETHEROPS_GUIDE.md) ｜ [面试问答准备](qs.md)

## Core Features
- **Zero-instrumentation capture**: Uses eBPF kprobe on `tcp_sendmsg` to automatically extract source/dest IP, port, latency (ns), process name (IPv4/IPv6 dual-stack)
- **Connection lifetime tracking**: eBPF kprobe on `tcp_connect` + `tcp_close` to measure real connection duration (RTT)
- **Service identity resolution**: Cgroup-aware resolver (K8s Pod name → container name → process name fallback) with 30s TTL cache
- **Dynamic baseline & adaptive thresholds**: Sliding window P95 + EMA baseline per edge, avoids fixed-threshold false positives
- **Multi-dimensional anomaly scoring**: Combines latency ratio, error rate, and call-volume drop detection
- **Reverse random walk root cause analysis**: Propagates suspicion upstream along inverted call graph to pinpoint cascade fault origin
- **Top-K fault clustering**: Groups suspect nodes with similar scores to hint at shared-infrastructure failures
- **Historical event learning**: Records fault patterns, matches new faults via Jaccard similarity with recommended actions
- **Kernel-level self-healing**: eBPF TC program for 100% packet-loss circuit breaking, with protected IP whitelist
- **K8s Pod isolation**: Auto-restarts suspect Pods via client-go
- **HTTP/gRPC protocol parsing**: Uprobe on `net/http.(*conn).readRequest`, `(*response).WriteHeader`, and `grpc.Invoke` for method, path, status code extraction
- **Failure scene preservation**: Auto-captures CPU flame graph, heap flame graph, goroutine/thread dump, tcpdump packet capture
- **Prometheus + Grafana observability**: Exposes call count, latency distribution, anomaly scores, self-healing events
- **Self-monitoring**: Agent health check endpoint (`/healthz`), event/error counters
- **Config-driven**: 13+ environment variables for tuning without code changes
- **Feishu/DingTalk alerting**: Sends root cause summary and flame graph filenames to IM group

## Architecture Overview
```
┌──────────────────────────────────────────┐
│           eBPF Kernel Probes             │
│  kprobe/tcp_sendmsg     (latency)        │
│  kprobe/tcp_connect     (conn start)     │
│  kprobe/tcp_close       (conn duration)  │
│  TC ingress             (packet drop)    │
│  uprobe (HTTP/gRPC)     (protocol parse) │
│  BPF Maps · Ring Buffer · CO-RE          │
└──────────────────┬───────────────────────┘
                   │ events (ringbuf)
┌──────────────────▼───────────────────────┐
│        Go Userspace Control Plane         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ Resolver │ │ Service  │ │ Root     │  │
│  │ (cgroup/ │──▶ Graph   │──▶ Cause    │  │
│  │  K8s)    │ │          │ │ Analysis │  │
│  └──────────┘ └──────────┘ └────┬─────┘  │
│  ┌──────────┐ ┌──────────┐      │        │
│  │Self-     │ │ Self-    │◀─────┘        │
│  │Monitor   │ │ Heal     │               │
│  └──────────┘ └──────────┘               │
│  ┌──────────┐ ┌──────────┐               │
│  │HTTP/gRPC │ │ TC Drop  │               │
│  │Consumer  │ │ Manager  │               │
│  └──────────┘ └──────────┘               │
└──────────────────┬───────────────────────┘
                   │ action
┌──────────────────▼───────────────────────┐
│     Kubernetes / External Systems         │
│  - Pod restart (client-go)                │
│  - Flame graphs / pprof dump              │
│  - tcpdump packet capture                 │
│  - Feishu / DingTalk webhook              │
│  - Prometheus /metrics endpoint           │
└───────────────────────────────────────────┘
```

## Quick Start

### Requirements
- Linux kernel >= 5.8 (BTF, CO-RE support)
- Go >= 1.24
- clang/llvm 18+
- Minikube v1.38+ (optional, for K8s features)
- Feishu/DingTalk webhook URL (optional, for alerts)

### Install Dependencies
```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev make gcc linux-tools-$(uname -r)
go install github.com/cilium/ebpf/cmd/bpf2go@latest
```

### Build & Run
```bash
git clone https://github.com/yourname/ebpf-autoheal.git
cd ebpf-autoheal

# Generate eBPF bindings
go generate ./cmd/tracer/...

# Build
go build -o ebpf-local ./cmd/tracer/

# Start (simulated latency mode for demo)
sudo SIMULATE_LATENCY=1 ./ebpf-local
```

### Quick Demo Closed-Loop
1. Start the probe, then in another terminal generate traffic:
   ```bash
   while true; do curl -s -o /dev/null http://127.0.0.1:6060/debug/pprof/; sleep 0.5; done
   ```
2. Wait ~30s for the dynamic baseline to stabilize (anomaly scores = 0).
3. Stop the curl loop (Ctrl+C) to simulate a call-volume drop fault.
4. Observe probe output:
   - Anomaly scores rise immediately
   - Root cause analysis prints suspects
   - Fault cluster grouping, history pattern matching
   - Self-healing triggers (local test skips rate-limit but generates flame graphs, dumps, pcap)
5. View Prometheus metrics:
   ```bash
   curl -s http://localhost:2112/metrics | grep anomaly
   ```
6. Check generated scene files:
   ```bash
   ls -la cpu-*.svg heap-*.svg goroutine-*.txt thread-*.txt capture-*.pcap
   ```

### Enable Feishu Notification
```bash
export FEISHU_WEBHOOK="https://open.feishu.cn/open-apis/bot/v2/hook/xxxxxxxxxx"
sudo SIMULATE_LATENCY=1 ./ebpf-local
```

### Deploy to Kubernetes (Optional)
```bash
# Build image
docker build -t ebpf-tracer:latest -f Dockerfile.agent .
# (Minikube) Load into cluster
minikube image load ebpf-tracer:latest
# Deploy DaemonSet
kubectl apply -f deploy/ebpf-tracer.yaml
# View logs
kubectl logs -n ebpf-system -l app=ebpf-tracer
```

## Project Structure
```
ebpf-autoheal/
├── bpf/
│   ├── net_trace.c              # TCP latency probe (kprobe/tcp_sendmsg)
│   ├── tcp_conntrack.c          # Connection lifetime tracking (kprobe/tcp_connect + tcp_close)
│   ├── tc_drop.c                # TC ingress packet drop program
│   ├── http_probe.c             # HTTP/gRPC uprobe programs
│   └── vmlinux.h                # Kernel type definitions (CO-RE)
├── cmd/tracer/
│   ├── main.go                  # Entry point, eBPF loading, event loop
│   ├── config.go                # Configuration system (13+ env vars)
│   ├── types.go                 # Shared types, structs, helpers
│   ├── graph.go                 # Service graph (nodes, edges, EMA, P95)
│   ├── analysis.go              # Root cause analysis engine
│   ├── mitigation.go            # Self-healing, K8s client, flame graphs, alerts
│   ├── resolver.go              # Cgroup-based service identity resolution
│   ├── http_probe.go            # HTTP/gRPC uprobe consumer
│   ├── tc_drop.go               # TC ingress BPF program management
│   ├── metrics.go               # Prometheus metric definitions
│   ├── metrics_helper.go        # Label cardinality guard
│   ├── analysis_test.go         # Unit tests for analysis algorithms
│   ├── tracer_bpfel.go          # Generated: net_trace BPF bindings
│   ├── tc_drop_bpfel.go         # Generated: tc_drop BPF bindings
│   ├── http_probe_bpfel.go      # Generated: http_probe BPF bindings
│   ├── tcp_conntrack_bpfel.go   # Generated: tcp_conntrack BPF bindings
│   └── *_bpfeb.go               # Big-endian variants
├── deploy/
│   └── ebpf-tracer.yaml         # DaemonSet deployment template
├── Dockerfile.agent             # Container build file
├── go.mod / go.sum
├── pprof-demo.go                # Local pprof test service
├── README.md
├── PROJECT_INTRO.md             # 项目简介（技术栈 + 核心功能）
├── STUDY_GUIDE.md               # 面试学习指南（算法详解 + 面试问答）
├── project-log.md               # 详细项目开发日志（中文）
├── qs.md                        # 面试问答准备（30 题）
├── 1.md                         # 面试优化建议
├── weilai.md                    # 未来扩展方向
└── testing.md                   # 演示与测试指南（中文）
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Kernel** | eBPF, kprobe/kretprobe, TC, uprobe, CO-RE, BPF maps, Ring Buffer, cgroupv2 |
| **Userspace** | Go, cilium/ebpf, bpf2go, Prometheus client, client-go |
| **Algorithms** | EMA (exponential moving average), sliding window P95, reverse random walk (PageRank), Jaccard similarity, Top-K clustering |
| **Deployment** | Docker, Kubernetes DaemonSet, hostNetwork/hostPID |
| **Notifications** | Feishu / DingTalk webhook |

## Interview Highlights
- Full zero-instrumentation: no SDK, no sidecar, no code changes
- IPv6 dual-stack handling, memory alignment, endianness — real kernel development issues
- Adaptive thresholds prevent false positives on normally-high-latency paths while detecting subtle faults like call-volume drops
- Graph algorithms + clustering + history learning — a tier above simple threshold-based detection
- Complete SRE closed-loop from kernel capture to IM alert

## Future Roadmap
- [ ] Feishu image message (upload flame graph PNG)
- [ ] Distributed tracing integration (W3C Trace Context)
- [ ] Multi-cluster topology aggregation
- [ ] Grafana deep dashboard (NodeGraph, heatmap, annotations)
- [ ] Non-privileged container (CAP_BPF, CAP_NET_ADMIN)
- [ ] Operator mode for lifecycle management
- [ ] AI-assisted fault prediction (LSTM/Transformer)

## License
This project is licensed under the [GPL v3.0](LICENSE) license.

---

<p align="center">
  Made with 🐝 by [Your Name] · 2026
</p>
