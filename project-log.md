
# eBPF 无侵入微服务可观测与自愈平台 — 最终项目文档

> **项目名称**: eBPF-AutoHeal  
> **核心目标**: 0 侵入全局监控 + 图算法根因定位 + 内核级自愈 + 现场保全 + 飞书通知  
> **开发者**: [沈乐琰]  
> **开始日期**: 2026-05-02  
> **当前状态**: 全功能闭环验证通过，包含自适应阈值、多维度异常、Top‑K 故障集群、历史事件学习、飞书告警通知、eBPF TC 丢包、HTTP/gRPC 协议解析、连接生命周期跟踪、cgroup 服务身份解析

---

## 目录

- [eBPF 无侵入微服务可观测与自愈平台 — 最终项目文档](#ebpf-无侵入微服务可观测与自愈平台--最终项目文档)
  - [目录](#目录)
  - [1. 项目概述](#1-项目概述)
  - [2. 环境搭建](#2-环境搭建)
    - [2.1 基础信息](#21-基础信息)
    - [2.2 安装步骤](#22-安装步骤)
    - [2.3 遇到的初始问题及解决](#23-遇到的初始问题及解决)
  - [3. 第一阶段：eBPF 破冰](#3-第一阶段ebpf-破冰)
  - [4. 第二阶段：网络拦截突破](#4-第二阶段网络拦截突破)
  - [5. 第三阶段：图算法根因分析](#5-第三阶段图算法根因分析)
  - [6. 第四阶段：自愈闭环与现场保全](#6-第四阶段自愈闭环与现场保全)
  - [7. 第五阶段：根因分析算法增强](#7-第五阶段根因分析算法增强)
  - [8. 第六阶段：飞书/钉钉通知](#8-第六阶段飞书钉钉通知)
  - [9. K8s 适配与 Pod 隔离](#9-k8s-适配与-pod-隔离)
  - [10. Prometheus + Grafana 可视化](#10-prometheus--grafana-可视化)
  - [11. 故障现场保全](#11-故障现场保全)
  - [12. 第七阶段：工程化与深度增强](#12-第七阶段工程化与深度增强)
    - [12.1 模块拆分与重构](#121-模块拆分与重构)
    - [12.2 eBPF TC 程序替代 tc 命令](#122-ebpf-tc-程序替代-tc-命令)
    - [12.3 HTTP/gRPC 协议解析](#123-httpgrpc-协议解析)
    - [12.4 连接生命周期跟踪](#124-连接生命周期跟踪)
    - [12.5 BPF 层面事件采样去重](#125-bpf-层面事件采样去重)
    - [12.6 Cgroup 服务身份解析](#126-cgroup-服务身份解析)
    - [12.7 配置系统替换魔法数字](#127-配置系统替换魔法数字)
    - [12.8 优雅关闭与自监控](#128-优雅关闭与自监控)
    - [12.9 单元测试](#129-单元测试)
  - [13. 最终完整代码](#13-最终完整代码)
  - [14. 常见问题与解决方案](#14-常见问题与解决方案)
  - [15. 演示与测试指南](#15-演示与测试指南)
    - [15.1 本地完整闭环演示](#151-本地完整闭环演示)
    - [15.2 验证 K8s Pod 隔离](#152-验证-k8s-pod-隔离)
  - [16. 未来扩展方向](#16-未来扩展方向)

---

## 1. 项目概述

本项目利用 eBPF 技术在 Linux 内核层面对微服务间 TCP 通信进行零侵入拦截，构建实时调用拓扑，并结合**自适应阈值（滑动窗口 P95）**、**多维度异常分数**、**反向随机游走（Fault Propagation Rank）**、**Top‑K 故障集群**以及**历史事件学习**等算法进行根因定位。故障确认后立即触发内核级 TC 限流、Kubernetes Pod 隔离/重启，并自动收集 CPU 火焰图、内存火焰图、Goroutine/线程 dump 和网络抓包作为现场证据，最后通过飞书 Webhook 发送告警通知。整体实现 **发现→定位→自愈→现场保全→通知** 的 SRE 闭环。

**关键技术栈**：
- eBPF：C 语言，cilium/ebpf + bpf2go，支持 CO-RE，兼容 IPv4/IPv6 双栈
- eBPF 程序类型：kprobe/kretprobe、TC、uprobe
- 用户态：Go 语言，图算法、K8s API、Prometheus 指标、飞书 Webhook
- 基础设施：Minikube (K8s)、Docker、Prometheus、Grafana（预留）

---

## 2. 环境搭建

### 2.1 基础信息
- **宿主机**: Ubuntu 24.04 Server (内核 6.8.0-110-generic)
- **Go 版本**: go1.24.1
- **关键组件**:
  - clang 18.1.3, llvm 18.1.3
  - bpftool v7.7.0
  - libbpf 1.3.0
  - cilium/ebpf v0.21.0
  - Minikube v1.38.1 (Docker 驱动)
  - Prometheus client_golang

### 2.2 安装步骤
```bash
sudo apt update
sudo apt install clang llvm libbpf-dev make gcc
sudo apt install linux-tools-$(uname -r)
go install github.com/cilium/ebpf/cmd/bpf2go@latest
minikube start --driver=docker --cpus=2 --memory=2048mb \
  --image-mirror-country=cn \
  --image-repository=registry.cn-hangzhou.aliyuncs.com/google_containers \
  --base-image=registry.cn-hangzhou.aliyuncs.com/google_containers/kicbase:v0.0.50
```

### 2.3 遇到的初始问题及解决
| 问题 | 原因 | 解决方案 |
|------|------|----------|
| `bpftool` 虚拟包无法直接安装 | Ubuntu 24.04 中 bpftool 由内核相关包提供 | `sudo apt install linux-tools-$(uname -r)` |
| `go generate` 报 `asm/types.h` 缺失 | 系统头文件路径不完整 | 生成 `vmlinux.h`，通过 `-I` 指定头文件路径 |
| `bpf2go` 类型收集失败 (`collect C types: not found`) | DWARF 被 strip | 添加 `-no-strip` 参数，或手动在 Go 中定义结构体 |
| `kprobe/do_execve` 挂载失败 | 内核 6.8 中符号未直接暴露 | 改用 tracepoint `syscalls:sys_enter_execve` |

---

## 3. 第一阶段：eBPF 破冰

**目标**：验证 eBPF 工具链，捕获系统 `execve` 调用。

**关键文件**：`bpf/exec_trace.c`（tracepoint `syscalls/sys_enter_execve`）  
**运行结果**：
```
✅ eBPF 探针已启动！开始监控 execve 调用...
🔍 PID=6698 进程=bash 正在执行新程序
```
✅ eBPF 工具链打通，Ring Buffer 通信正常。

---

## 4. 第二阶段：网络拦截突破

**目标**：挂钩 `tcp_sendmsg`，零侵入捕获 TCP 四元组 + 延迟。

**关键挑战**：
- IPv6 双栈：Go 程序默认使用 AF_INET6，真实 IPv4 地址藏在 `skc_v6_rcv_saddr` 尾部 4 字节
- 字节序：源端口为主机序，目标端口为网络序，需 `__builtin_bswap16`
- 内存对齐：C 结构体显式 padding 至 48 字节，Go 端严格匹配

**最终方案**：
- kprobe 入口通过 `BPF_CORE_READ_INTO` 读取 `struct sock *sk` 四元组并存入 BPF map
- kretprobe 出口从 map 取出四元组，计算延迟，通过 Ring Buffer 发送

**运行结果**：
```
🌐 PID=12003 (kube-apiserver) 192.168.49.2:8443 -> 10.244.0.2:51880 延迟=0.06 ms
🌐 PID=11991 (etcd) 127.0.0.1:2379 -> 127.0.0.1:51672 延迟=0.04 ms
```
✅ 零侵入 TCP 四元组 + 延迟采集成功。

---

## 5. 第三阶段：图算法根因分析

**图结构**：节点为 `IP:Port` 或进程名，边记录调用次数、总延迟、错误次数、EMA 基线、异常分数。

**算法设计**：
1. **EMA 动态基线**：每条边使用指数移动平均（α=0.2）学习正常延迟。
2. **异常检测**：当前平均延迟与 EMA 比值超过 1.5 倍或绝对延迟超过 200ms 时标记为异常边。
3. **故障传播排名**：在反向图（被调用者→调用者）上执行带重启的随机游走，计算每个节点的嫌疑概率。
4. 输出 Top 3 嫌疑节点。

**验证**：模拟延迟 2000ms，算法准确地标记出高延迟节点。

---

## 6. 第四阶段：自愈闭环与现场保全

- **tc 限流**：对嫌疑 IP 执行 100% 丢包（受保护 IP 列表防止误杀集群）
- **K8s Pod 隔离**：通过 client-go 查找嫌疑 IP 对应的 Pod 并删除（触发重建）
- **Prometheus 指标**：暴露调用次数、延迟直方图、异常分数、根因分数、自愈次数
- **故障现场保全**：
  - CPU 火焰图、内存火焰图
  - Goroutine dump、线程 dump
  - tcpdump 抓包
- **验证**：使用本地 pprof 测试服务，自愈时自动生成上述文件。

---

## 7. 第五阶段：根因分析算法增强

**新增特性**：
1. **自适应阈值**：每条边维护最近 30 次延迟的滑动窗口，动态计算 P95 作为阈值，不再使用固定 200ms。
2. **多维度异常分数**：
   - 延迟因子：AvgLat / P95
   - 错误率因子：1 + errors/count
   - 调用量骤降因子：通过 `LastCount` 计算分析窗口内的新增调用量，维护调用速率 EMA，检测骤降
   - 综合分数 = latRatio * errorFactor + CallAnomaly * 2.0
3. **Top‑K 故障集群**：分数差异 < 15% 的嫌疑节点归为同一故障集群，提示共享基础设施。
4. **历史事件学习**：保存最近 20 次根因结果，新故障时进行 Jaccard 相似度匹配，推荐操作。

**验证**：
- 恒定高延迟下异常分数为 0（防止误报）
- 停止 curl 循环后调用量骤降，异常分数立即上升，触发集群分析和历史匹配。

---

## 8. 第六阶段：飞书/钉钉通知

**实现**：通过环境变量 `FEISHU_WEBHOOK` 配置 Webhook 地址，自愈触发后自动发送根因分析结果和火焰图文件名。

**消息示例**：
```
【eBPF 根因告警】
时间: 22:30:15
嫌疑节点:
- 127.0.0.1:6060 (分数: 3200.00, 平均延迟: 2000.00 ms, 调用次数: 45)
火焰图文件: cpu-127.0.0.1-1712345678.svg heap-127.0.0.1-1712345678.svg 
请及时处理。
```

**使用**：
```bash
export FEISHU_WEBHOOK="https://open.feishu.cn/open-apis/bot/v2/hook/xxxxxxxxxx"
sudo KUBECONFIG=... SIMULATE_LATENCY=1 ./ebpf-local
```

✅ 飞书通知已集成完毕。

---

## 9. K8s 适配与 Pod 隔离

- **DaemonSet 部署**：hostNetwork: true, hostPID: true, privileged: true（后续可改为精确 capabilities）
- **client-go 集成**：通过 `getPodByIP` 查找 Pod，`restartPod` 删除 Pod 触发重建
- **启动测试**：通过 `TEST_POD_IP` 环境变量可在启动时立即验证 Pod 隔离功能

---

## 10. Prometheus + Grafana 可视化

**暴露端点**：`:2112/metrics`

**核心指标**：
- `ebpf_edge_latency_ms` (Histogram)
- `ebpf_edge_calls_total`, `ebpf_edge_errors_total`
- `ebpf_edge_anomaly_score`, `ebpf_node_avg_latency_ms`
- `ebpf_root_cause_score`, `ebpf_mitigation_total`

**Grafana 建议面板**：NodeGraph、延迟热力图、异常分数趋势、自愈事件时间线。

---

## 11. 故障现场保全

**收集内容**：
- CPU 火焰图 (`/debug/pprof/profile?seconds=10`)
- 内存火焰图 (`/debug/pprof/heap`)
- Goroutine dump (`/debug/pprof/goroutine?debug=2`)
- 线程 dump (`/debug/pprof/threadcreate?debug=1`)
- 网络抓包 (`tcpdump`，过滤目标 IP，保存为 pcap)

所有文件以 `<类型>-<IP>-<时间戳>` 格式保存。

---

## 12. 第七阶段：工程化与深度增强

### 12.1 模块拆分与重构

**变更**：将 950 行单体 `main.go` 拆分为 8 个模块文件，职责清晰：

| 文件 | 职责 |
|------|------|
| `main.go` | 入口，eBPF 加载，主事件循环 |
| `config.go` | 配置系统（13+ 环境变量），冷却期管理 |
| `types.go` | 共享类型，eBPF 事件结构体定义 |
| `graph.go` | 服务图结构（节点、边、EMA、P95） |
| `analysis.go` | 根因分析引擎（异常检测、PageRank、集群、历史） |
| `mitigation.go` | 自愈操作，K8s 客户端，火焰图，飞书通知 |
| `metrics.go` | Prometheus 指标注册 |
| `metrics_helper.go` | Prometheus 标签基数保护 |

**效果**：代码可维护性大幅提升，每个文件职责单一，便于测试和扩展。

### 12.2 eBPF TC 程序替代 tc 命令

**变更**：`bpf/tc_drop.c` + `cmd/tracer/tc_drop.go`

- 编写 eBPF TC 程序，挂载到网络接口 ingress 方向
- 通过 BPF map 存储待丢弃的 IP 列表
- 使用 `link.AttachTCX()` 替代 `exec.Command("tc", ...)` 调用外部命令
- 保留回退逻辑：若 BPF TC 挂载失败，自动降级到 tc 命令

**关键技术点**：
- `link.AttachTCX()` 接口（cilium/ebpf v0.21.0）
- BPF map `tc_drop_ips` 在 TC 程序和用户态之间共享
- ebpf 程序返回 `TC_ACT_SHOT` 丢弃匹配包，`TC_ACT_OK` 放行

**效果**：
- 丢包逻辑完全在内核态完成，无需 fork 外部进程
- 延迟从毫秒级降至微秒级
- 面试亮点：对比"用户态 tc 命令"和"内核态 eBPF TC"的性能差异

### 12.3 HTTP/gRPC 协议解析

**变更**：`bpf/http_probe.c` + `cmd/tracer/http_probe.go`

- 通过 uprobe 挂载 Go 运行时函数：
  - `net/http.(*conn).readRequest` — 捕获 HTTP 方法、路径、Host
  - `net/http.(*response).WriteHeader` — 捕获状态码、计算请求耗时
  - `google.golang.org/grpc.(*ClientConn).Invoke` — 捕获 gRPC 调用
- 处理 Go ABI 寄存器传参约定（RAX=arg0, RBX=arg1, RCX=arg2），不是标准的 x86_64 的 RDI/RSI
- 解析结果通过独立 Ring Buffer 传输，不影响 TCP 监控主流程

**效果**：
- 调用拓扑从 TCP 四元组升级为 `GET /api/order` 级别的语义信息
- Prometheus 指标增加 method、status code 维度
- 支持 HTTP/1.1 和 gRPC

### 12.4 连接生命周期跟踪

**变更**：`bpf/tcp_conntrack.c`

- 新增 eBPF 程序 `kprobe/tcp_connect` 和 `kprobe/tcp_close`
- 在 `tcp_connect` 入口记录连接元组和起始时间戳，存入 `conn_track` map
- 在 `tcp_close` 从 map 取出起始时间，计算连接持续时间
- 独立 Ring Buffer `conn_events` 传输连接事件
- 独立采样器（1s 间隔）控制事件频率

**效果**：
- 获取真实 TCP 连接建立→关闭的端到端耗时（RTT）
- 区别于 `tcp_sendmsg` 的缓冲区拷贝延迟，反映真实网络质量
- 可用于检测连接泄漏、长时间未关闭等异常

### 12.5 BPF 层面事件采样去重

**变更**：`bpf/net_trace.c` 和 `bpf/tcp_conntrack.c`

- 新增 `rate_limit` BPF map（每个流一个条目）
- 基于流五元组的哈希键，记录上次发出事件的时间戳
- 默认 100ms 间隔（`sampling_interval_ns = 100000000`）
- 同一流在间隔内的事件被跳过，仅更新 map 中的时间戳

**效果**：
- 高频连接的 event 量减少 99%+
- 降低用户态处理压力，同时保留每个流的延迟采样

### 12.6 Cgroup 服务身份解析

**变更**：`cmd/tracer/resolver.go`

- `ServiceIdentity` 结构体，带 30s TTL 的 PID→服务名缓存
- 解析优先级：K8s Pod 名 > 容器名 > 进程名
- `resolveFromCgroup()` — 解析 `/proc/pid/cgroup`，支持：
  - K8s 格式：`/kubepods/burstable/pod<uid>/<container-id>` → 查 K8s API 获取 Pod 名
  - Docker 格式：`/docker/<container-id>` → 返回 `container-<cid>`
- `resolveFromCmdline()` — 从 `/proc/pid/cmdline` 提取可执行文件名

**效果**：
- 调用拓扑中的节点名从 `comm`（如 `curl`）升级为 `pod-order-service-xxx` 或 `container-abc123`
- 在 K8s 环境中定位粒度从进程级提升到 Pod 级

### 12.7 配置系统替换魔法数字

**变更**：`cmd/tracer/config.go`

- `Config` 结构体包含 13+ 可调参数，全部通过环境变量覆盖
- 移除 `analysis.go` 中所有硬编码常量（P95 倍数、最小阈值、QPS 参数等）
- 新增 `labelCardinalityGuard` 防止 Prometheus 标签基数爆炸
- 新增 `mitCooldown` 机制替代永不清理的 `processedNodes` map

**效果**：
- 无需修改代码即可调优阈值、间隔、权重
- 冷却期自动过期，防止内存泄漏
- 标签基数上限保护 Prometheus 实例

### 12.8 优雅关闭与自监控

**变更**：`cmd/tracer/main.go` + `cmd/tracer/metrics.go`

- 信号处理器改为关闭 Ring Buffer Reader，主循环自然退出
- 新增 `/healthz` HTTP 端点返回 `{"status":"ok"}`
- 新增自监控指标：`ebpf_agent_events_total`、`ebpf_agent_errors_total`、`ebpf_agent_up`
- HTTP Server 使用 mux 同时处理 `/metrics` 和 `/healthz`

**效果**：
- 支持 Kubernetes liveness/readiness probe
- 探针自身的健康状况可观测
- 优雅退出确保资源正确释放

### 12.9 单元测试

**变更**：`cmd/tracer/analysis_test.go`

- 8 个测试用例覆盖核心算法：
  - `TestPercentile` — P95 分位数计算
  - `TestJaccardSimilarity` — 历史匹配
  - `TestClusterSuspects` — 故障集群
  - `TestIPToUint32` — IP 转换
  - `TestNewServiceGraph` / `TestServiceGraphAddCall` — 图操作
  - `TestAnalyzeRootCauseNoAnomaly` — 无异常时输出空
  - `TestEMAProgression` — EMA 基线演进

---

## 13. 最终完整代码

项目结构：
```
ebpf-autoheal/
├── bpf/
│   ├── net_trace.c              # TCP 延迟探针（kprobe/tcp_sendmsg）
│   ├── tcp_conntrack.c          # 连接生命周期（kprobe/tcp_connect + tcp_close）
│   ├── tc_drop.c                # TC 入口丢包程序
│   ├── http_probe.c             # HTTP/gRPC uprobe 程序
│   └── vmlinux.h                # 内核类型定义
├── cmd/tracer/
│   ├── main.go                  # 入口，eBPF 加载，事件循环
│   ├── config.go                # 配置系统
│   ├── types.go                 # 共享类型
│   ├── graph.go                 # 服务图
│   ├── analysis.go              # 根因分析引擎
│   ├── mitigation.go            # 自愈，K8s，火焰图，通知
│   ├── resolver.go              # Cgroup 服务身份解析
│   ├── http_probe.go            # HTTP/gRPC 消费者
│   ├── tc_drop.go               # TC 管理
│   ├── metrics.go               # Prometheus 指标
│   ├── metrics_helper.go        # 标签基数保护
│   ├── analysis_test.go         # 单元测试
│   ├── tracer_bpfel.go          # 生成：net_trace 绑定
│   ├── tc_drop_bpfel.go         # 生成：tc_drop 绑定
│   ├── http_probe_bpfel.go      # 生成：http_probe 绑定
│   ├── tcp_conntrack_bpfel.go   # 生成：tcp_conntrack 绑定
│   └── *_bpfeb.go               # 大端变体
├── deploy/
│   └── ebpf-tracer.yaml         # DaemonSet 部署
├── Dockerfile.agent             # 容器构建
├── go.mod, go.sum
├── pprof-demo.go                # 本地 pprof 测试服务
├── README.md
├── PROJECT_INTRO.md             # 项目简介（技术栈 + 核心功能）
├── STUDY_GUIDE.md               # 面试学习指南（算法详解 + 面试问答）
├── project-log.md               # 详细项目开发日志
├── qs.md                        # 面试问答准备（30 题）
├── 1.md                         # 面试优化建议
├── weilai.md                    # 未来扩展方向
└── testing.md                   # 演示与测试指南
```

`cmd/tracer/` 集成功能：
- eBPF 采集（kprobe/kretprobe）+ 连接跟踪（kprobe/tcp_connect + tcp_close）
- 事件采样去重（BPF map 级别）
- EMA + 自适应阈值 + 多维度异常 + 故障传播排名
- Top‑K 故障集群 + 历史事件学习
- eBPF TC 丢包（回退 tc 命令）
- HTTP/gRPC 协议解析（uprobe）
- Cgroup 服务身份解析（K8s Pod / Docker / 进程名）
- K8s Pod 隔离（client-go）
- CPU/内存火焰图 + Goroutine/线程 dump + 抓包
- Prometheus 指标暴露 + 健康检查
- 配置系统（13+ 环境变量）
- 标签基数保护
- 飞书 Webhook 通知
- 模拟延迟开关
- 单元测试（8 个用例）

---

## 14. 常见问题与解决方案

| 编号 | 问题现象 | 原因 | 解决方案 |
|------|----------|------|----------|
| E01 | `go generate` 报 `asm/types.h` 缺失 | 内核头文件路径不完整 | 生成 `vmlinux.h` 并添加 `-I` 路径 |
| E02 | `collect C types: not found` | DWARF 被 strip | 使用 `-no-strip` 或手写 Go 结构体 |
| E03 | kretprobe 中读取 sk 为 0 | 寄存器参数在出口已失效 | 在 kprobe 入口保存四元组，出口仅计算延迟 |
| E04 | 四元组全 0，延迟正常 | Go 程序使用 IPv6 双栈 | 判断 `skc_family`，从 `skc_v6_daddr` 尾部提取 IPv4 |
| E05 | IP 显示混乱 (如 2.49.168.192) | 字节序错误 | 使用 `binary.LittleEndian.PutUint32` 正确还原 |
| E06 | kubectl 报 `no route to host` | 自愈误杀 Minikube 控制平面 IP | 添加 `protectedIPs` 列表，限流前检查 |
| E07 | sudo 运行时找不到 kubeconfig | `sudo` 下 `HomeDir()` 返回 `/root` | 显式传递 `KUBECONFIG` 环境变量或代码中指定用户 kubeconfig 路径 |
| E08 | 火焰图抓取失败 (connection refused) | 目标服务未开启 pprof | 部署 pprof 测试服务验证，或确保目标服务导入了 `net/http/pprof` |
| E09 | 调用量骤降检测始终为 0 | 使用累计 Count 而非增量 | 增加 `LastCount` 字段，计算 `deltaCount` 得到真实 QPS |
| E10 | 飞书通知未发送 | 未设置 Webhook 地址或网络不通 | 检查环境变量 `FEISHU_WEBHOOK`，确保能访问飞书开放平台 |
| E11 | `PT_REGS_PARM2` 编译失败 | `-target bpf` 下宏未定义 | Go ABI 用 RAX/RBX/RCX 传参，直接读 `ctx->bx`、`ctx->cx` |
| E12 | `link.TCX()` 未定义 | cilium/ebpf v0.21.0 使用不同 API | 改用 `link.AttachTCX()` |

---

## 15. 演示与测试指南

### 15.1 本地完整闭环演示
1. **清理旧 tc 规则**：
   ```bash
   sudo tc qdisc del dev ens33 root 2>/dev/null
   ```
2. **启动 pprof 测试服务**（若未运行）：
   ```bash
   cd ~/ebpf-autoheal && go run pprof-demo.go &
   ```
3. **(可选) 配置飞书通知**：
   ```bash
   export FEISHU_WEBHOOK="你的飞书机器人Webhook地址"
   ```
4. **启动探针（模拟延迟模式）**：
   ```bash
   sudo KUBECONFIG=/home/sly/.kube/config SIMULATE_LATENCY=1 ./ebpf-local
   ```
5. **产生持续流量**（另一终端）：
   ```bash
   while true; do curl -s -o /dev/null http://127.0.0.1:6060/debug/pprof/; sleep 0.5; done
   ```
6. **等待 30 秒**，观察拓扑输出（EMA、P95 均稳定）。
7. **测试调用量骤降**：按 `Ctrl+C` 停止 curl 循环。
8. **等待 15~30 秒**，探针将输出：
   - 异常分数非零
   - 根因分析嫌疑节点
   - 故障集群分组
   - 历史模式匹配（多次测试后出现）
   - 自愈动作（tc 限流跳过，现场保全生成文件）
   - 飞书消息推送（若已配置）
9. **查看 Prometheus 指标**：
   ```bash
   curl -s http://localhost:2112/metrics | grep anomaly
   ```
10. **检查现场保全文件**：
    ```bash
    ls -la *.svg *.txt *.pcap
    ```
11. **查看连接跟踪事件**（日志中出现 `CONN client/server` 行）：
    ```
    CONN client 127.0.0.1:54321 -> 10.244.0.2:80 duration=1234.56 ms pid=12345 (curl)
    ```

### 15.2 验证 K8s Pod 隔离
1. 创建测试 Deployment：
   ```bash
   kubectl create deployment demo-app --image=nginx:alpine
   ```
2. 获取 Pod IP：
   ```bash
   kubectl get pod -o wide -l app=demo-app
   ```
3. 启动探针并指定测试 IP：
   ```bash
   sudo KUBECONFIG=/home/sly/.kube/config SIMULATE_LATENCY=1 TEST_POD_IP=10.244.0.x ./ebpf-local
   ```
4. 启动日志立即显示 Pod 重启成功，同时 Pod 被删除重建。

---

## 16. 未来扩展方向

- **飞书图片消息**：将火焰图 SVG 转换为 PNG 并上传，发送图片消息
- **分布式追踪集成**：解析 W3C Trace Context，补全追踪断层
- **多集群/多节点聚合**：DaemonSet + 中心端全局拓扑
- **Grafana 深度集成**：自动渲染调用拓扑和故障标记
- **非特权容器化**：CAP_BPF + CAP_NET_ADMIN 替代 privileged
- **Operator 模式**：自动管理 eBPF 程序加载、升级、配置
- **AI 辅助故障预测**：LSTM/Transformer 学习时序预测异常

---

---

## 13. 第八阶段：AetherOps — AI 驱动智能运维 Agent

### 13.1 升级目标
在 ebpf-autoheal 的"感知 + 简单自愈"基础上，构建四层闭环 AIOps 系统：

| 层 | 技术 | 说明 |
|----|------|------|
| **感知层** | 已有 eBPF + Go | 不变 |
| **认知层** | Python + causal-learn + LLM + LangGraph | 因果推断 + 多模态 LLM 诊断 + 认知工作流编排 |
| **安全执行层** | Go Blast Radius + 分级自愈 | 影响面评估 + 低/中/高三级策略 |
| **进化层** | Milvus RAG + DSPy | 历史案例向量检索 + 自动 Prompt 优化 |

### 13.2 新增文件结构

```
ebpf-autoheal/
├── proto/aetherops.proto          # gRPC 服务定义
├── proto/gen/                     # 生成的 Go protobuf 代码
│
├── cmd/tracer/
│   ├── grpc_server.go             # ★ gRPC 服务端（Topology + Remediation）
│   ├── blast_radius.go            # ★ Blast Radius 模拟 + 分级执行
│   └── main.go (已修改)           # 新增 gRPC 启动和事件发布
│
├── aetherops/                     # ★ Python 认知核心（新增）
│   ├── pyproject.toml             # Poetry 项目定义
│   ├── Dockerfile                 # 容器构建
│   ├── workflow.yaml              # LangGraph 工作流配置
│   ├── main.py                    # 入口（daemon / single workflow）
│   ├── core/
│   │   ├── grpc_client.py        # Go 数据面 gRPC 客户端
│   │   ├── causal_inference.py   # causal-learn 因果发现（LPCMCI/PC/LiNGAM）
│   │   ├── llm_diagnosis.py      # 多模态 LLM 诊断 Agent
│   │   ├── metrics_fetcher.py    # Prometheus 指标拉取
│   │   └── risk_client.py        # 风险评估调用
│   ├── workflows/
│   │   └── langgraph_workflow.py # LangGraph 认知工作流编排
│   ├── rag/
│   │   ├── store.py              # Milvus 向量存储
│   │   └── retriever.py          # 历史案例检索 + 上下文注入
│   └── dspy/
│       └── optimizer.py          # DSPy Prompt 自动优化
│
├── deploy/
│   ├── aetherops-core.yaml       # K3s Deployment: Python core
│   ├── aetherops-neo4j.yaml      # K3s Deployment: Neo4j
│   ├── aetherops-milvus.yaml     # K3s Deployment: Milvus + etcd + minio
│   └── aetherops-install.sh      # 一键部署脚本
│
└── docker-compose.aetherops.yml  # 完整 Docker Compose
```

### 13.3 gRPC 通信协议

Python 认知层 ↔ Go 数据层通过 gRPC + Protobuf 通信：

| 方法 | 方向 | 说明 |
|------|------|------|
| `GetTopology` | Go → Python | 返回当前 ServiceGraph 快照 |
| `SubscribeAnomalyEvents` | Go → Python (stream) | 流式推送异常事件 |
| `EvaluateRemediation` | Python → Go | 评估修复操作的爆炸半径 |
| `ExecuteRemediation` | Python → Go | 执行分级修复操作 |

### 13.4 LangGraph 认知工作流

```
Anomaly Event
    │
    ▼
fetch_topology ───► fetch_metrics ───► causal_inference
                                           │
                                           ▼
                                    llm_diagnosis
                                      │      │
                           confidence < 0.6  │ confidence >= 0.6
                                  │          │
                        (re-analyze loop)    ▼
                                      risk_assessment
                                           │
                                           ▼
                                    execute_remediation
                                           │
                                           ▼
                                    store_to_rag ──► dspy_optimize
```

### 13.5 分级自愈策略

| 风险等级 | 操作示例 | 执行方式 | 类比 |
|----------|---------|---------|------|
| **LOW** | TC 限流、Scale Up | 自动执行 | 堵住漏水口 |
| **MEDIUM** | Pod 重启 | TEE 沙盒模拟 + 审计日志 | 在实验室做手术 |
| **HIGH** | 配置变更、镜像回滚 | 生成 GitOps PR，等待审批 | 需要家属签字 |

### 13.6 启动方式

```bash
# 1. Go 数据面（已有）
sudo SIMULATE_LATENCY=1 ./ebpf-local

# 2. Python 认知层
cd aetherops && poetry install && LLM_API_KEY=sk-xxx python -m aetherops.main --daemon

# 3. 或者用 Docker Compose 完整启动
docker compose -f docker-compose.aetherops.yml up -d

# 4. 在 K3s 上部署
bash deploy/aetherops-install.sh
```

---

> **最后更新**: 2026-06-30  
> **项目状态**: 第八阶段完成 — AetherOps AI 智能运维 Agent 架构设计实现，涵盖因果推断、LLM 诊断、LangGraph 编排、Blast Radius、分级自愈、RAG 知识库、DSPy Prompt 优化，完整四层 AIOps 闭环。
