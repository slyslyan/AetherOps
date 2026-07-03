# eBPF-AutoHeal：零埋点微服务可观测与自愈平台

<p align="center">
  <img src="https://img.shields.io/badge/License-GPL-blue" alt="License">
  <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go" alt="Go Version">
  <img src="https://img.shields.io/badge/eBPF-Kernel%205.8+-orange?logo=linux" alt="eBPF Support">
  <img src="https://img.shields.io/badge/Kubernetes-Minikube%20v1.38-blueviolet?logo=kubernetes" alt="Kubernetes">
</p>

**eBPF-AutoHeal** 是一个基于 eBPF 的零埋点微服务可观测与自愈平台。它在内核层捕获所有 TCP 通信，无需修改代码即可构建实时调用拓扑，通过**自适应阈值、多维度异常评分和反向随机游走（PageRank）** 定位根因，触发内核级熔断、Kubernetes Pod 隔离/重启、采集故障现场 CPU/内存火焰图、goroutine/thread dump 和 tcpdump 包捕获，最后通过飞书/钉钉 webhook 发送告警——完成完整的 SRE 闭环：**检测 → 诊断 → 自愈 → 保留现场 → 通知**。

## 核心功能
- **零埋点捕获**：通过 eBPF kprobe 挂载 `tcp_sendmsg`，自动提取源/目的 IP、端口、延迟（ns）、进程名（IPv4/IPv6 双栈）
- **连接生命周期跟踪**：eBPF kprobe 挂载 `tcp_connect` + `tcp_close`，测量真实连接持续时间（RTT）
- **服务身份识别**：基于 cgroup 的解析器（K8s Pod 名 → 容器名 → 进程名逐级回退），30 秒 TTL 缓存
- **动态基线 & 自适应阈值**：滑动窗口 P95 + EMA 基线，避免固定阈值误报
- **多维度异常评分**：综合延迟比率、错误率、调用量下降检测
- **反向随机游走根因分析**：沿反向调用图向上传播怀疑度，定位级联故障源头
- **Top-K 故障聚类**：将相似分数的可疑节点分组，提示共享基础设施故障
- **历史事件学习**：记录故障模式，通过 Jaccard 相似度匹配新故障并推荐处理措施
- **内核级自愈**：eBPF TC 程序实现 100% 丢包熔断，支持受保护 IP 白名单
- **K8s Pod 隔离**：通过 client-go 自动重启可疑 Pod
- **HTTP/gRPC 协议解析**：通过 uprobe 挂载 `net/http` 请求/响应和 `grpc.Invoke` 提取方法、路径、状态码
- **故障现场保留**：自动捕获 CPU 火焰图、堆内存火焰图、goroutine/thread dump、tcpdump 包捕获
- **Prometheus + Grafana 可观测**：暴露调用次数、延迟分布、异常评分、自愈事件
- **自监控**：Agent 健康检查端点（`/healthz`）、事件/错误计数器
- **配置驱动**：13+ 环境变量可调，无需改代码
- **飞书/钉钉告警**：发送根因摘要和火焰图文件名到即时通讯群

## 架构概览
```
┌──────────────────────────────────────────┐
│           eBPF 内核探针                   │
│  kprobe/tcp_sendmsg     (延迟)           │
│  kprobe/tcp_connect     (连接开始)       │
│  kprobe/tcp_close       (连接时长)       │
│  TC ingress             (丢包)           │
│  uprobe (HTTP/gRPC)     (协议解析)       │
│  BPF Maps · Ring Buffer · CO-RE          │
└──────────────────┬───────────────────────┘
                   │ 事件 (ringbuf)
┌──────────────────▼───────────────────────┐
│        Go 用户态控制面                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ 解析器   │ │ 服务图   │ │ 根因     │  │
│  │ (cgroup/ │→│ 构建     │→│ 分析引擎 │  │
│  │  K8s)    │ │          │ │          │  │
│  └──────────┘ └──────────┘ └────┬─────┘  │
│  ┌──────────┐ ┌──────────┐      │        │
│  │ 自监控   │ │ 自愈引擎 │←─────┘        │
│  └──────────┘ └──────────┘               │
│  ┌──────────┐ ┌──────────┐               │
│  │HTTP/gRPC │ │ TC 丢包  │               │
│  │ 消费者   │ │ 管理器   │               │
│  └──────────┘ └──────────┘               │
└──────────────────┬───────────────────────┘
                   │ 执行
┌──────────────────▼───────────────────────┐
│     Kubernetes / 外部系统                  │
│  - Pod 重启 (client-go)                   │
│  - 火焰图 / pprof dump                    │
│  - tcpdump 包捕获                         │
│  - 飞书 / 钉钉 webhook                    │
│  - Prometheus /metrics 端点               │
└───────────────────────────────────────────┘
```

## 快速开始

### 环境要求
- Linux 内核 >= 5.8（支持 BTF、CO-RE）
- Go >= 1.24
- clang/llvm 18+
- Minikube v1.38+（可选，K8s 功能需要）
- 飞书/钉钉 webhook URL（可选，告警需要）

### 安装依赖
```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev make gcc linux-tools-$(uname -r)
go install github.com/cilium/ebpf/cmd/bpf2go@latest
```

### 构建与运行
```bash
git clone https://github.com/yourname/ebpf-autoheal.git
cd ebpf-autoheal

# 生成 eBPF 绑定
go generate ./cmd/tracer/...

# 构建
go build -o ebpf-local ./cmd/tracer/

# 启动（模拟延迟模式，用于演示）
sudo SIMULATE_LATENCY=1 ./ebpf-local
```

### 快速演示闭环
1. 启动探针后，在另一个终端产生流量：
   ```bash
   while true; do curl -s -o /dev/null http://127.0.0.1:6060/debug/pprof/; sleep 0.5; done
   ```
2. 等待约 30 秒让动态基线稳定（异常评分归零）
3. 停止 curl 循环（Ctrl+C）模拟调用量下降故障
4. 观察探针输出：
   - 异常评分立即上升
   - 根因分析打印可疑节点
   - 故障聚类分组、历史模式匹配
   - 自愈触发（本地测试跳过限流，生成火焰图、dump、pcap）
5. 查看 Prometheus 指标：
   ```bash
   curl -s http://localhost:2112/metrics | grep anomaly
   ```
6. 检查生成的故障现场文件：
   ```bash
   ls -la cpu-*.svg heap-*.svg goroutine-*.txt thread-*.txt capture-*.pcap
   ```

### 启用飞书通知
```bash
export FEISHU_WEBHOOK="https://open.feishu.cn/open-apis/bot/v2/hook/xxxxxxxxxx"
sudo SIMULATE_LATENCY=1 ./ebpf-local
```

### 部署到 Kubernetes（可选）
```bash
# 构建镜像
docker build -t ebpf-tracer:latest -f Dockerfile.agent .
# (Minikube) 导入集群
minikube image load ebpf-tracer:latest
# 部署 DaemonSet
kubectl apply -f deploy/ebpf-tracer.yaml
# 查看日志
kubectl logs -n ebpf-system -l app=ebpf-tracer
```

## 项目结构
```
ebpf-autoheal/
├── bpf/
│   ├── net_trace.c              # TCP 延迟探针 (kprobe/tcp_sendmsg)
│   ├── tcp_conntrack.c          # 连接生命周期跟踪 (kprobe/tcp_connect + tcp_close)
│   ├── tc_drop.c                # TC ingress 丢包程序
│   ├── http_probe.c             # HTTP/gRPC uprobe 程序
│   └── vmlinux.h                # 内核类型定义 (CO-RE)
├── cmd/tracer/
│   ├── main.go                  # 入口，eBPF 加载，事件循环
│   ├── config.go                # 配置系统 (13+ 环境变量)
│   ├── types.go                 # 共享类型与结构体
│   ├── graph.go                 # 服务图 (节点、边、EMA、P95)
│   ├── analysis.go              # 根因分析引擎
│   ├── mitigation.go            # 自愈、K8s 客户端、火焰图、告警
│   ├── resolver.go              # 基于 cgroup 的服务身份解析
│   ├── http_probe.go            # HTTP/gRPC uprobe 消费者
│   ├── tc_drop.go               # TC ingress BPF 程序管理
│   ├── metrics.go               # Prometheus 指标定义
│   ├── metrics_helper.go        # 标签基数守卫
│   ├── analysis_test.go         # 分析算法单元测试
│   ├── tracer_bpfel.go          # 自动生成的 net_trace BPF 绑定
│   ├── tc_drop_bpfel.go         # 自动生成的 tc_drop BPF 绑定
│   ├── http_probe_bpfel.go      # 自动生成的 http_probe BPF 绑定
│   ├── tcp_conntrack_bpfel.go   # 自动生成的 tcp_conntrack BPF 绑定
│   └── *_bpfeb.go               # 大端变体
├── deploy/
│   └── ebpf-tracer.yaml         # DaemonSet 部署模板
├── Dockerfile.agent             # 容器构建文件
├── go.mod / go.sum
├── pprof-demo.go                # 本地 pprof 测试服务
└── README.md
```

## 技术栈

| 层 | 技术 |
|----|------|
| **内核** | eBPF, kprobe/kretprobe, TC, uprobe, CO-RE, BPF maps, Ring Buffer, cgroupv2 |
| **用户态** | Go, cilium/ebpf, bpf2go, Prometheus client, client-go |
| **算法** | EMA (指数移动平均), 滑动窗口 P95, 反向随机游走 (PageRank), Jaccard 相似度, Top-K 聚类 |
| **部署** | Docker, Kubernetes DaemonSet, hostNetwork/hostPID |
| **通知** | 飞书 / 钉钉 webhook |

## 未来计划
- [ ] 飞书图片消息（上传火焰图 PNG）
- [ ] 分布式追踪集成（W3C Trace Context）
- [ ] 多集群拓扑聚合
- [ ] Grafana 深度面板（NodeGraph、热力图、标注）
- [ ] 非特权容器（CAP_BPF、CAP_NET_ADMIN）
- [ ] Operator 模式管理生命周期
- [ ] AI 辅助故障预测（LSTM/Transformer）

## License
This project is licensed under the [GPL v3.0](LICENSE) license.

---

<p align="center">
  Made with 🐝 · 2026
</p>
