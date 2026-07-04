# AetherOps — AI-Driven Intelligent Operations Agent

<p align="center">
  <img src="https://img.shields.io/badge/License-GPL-blue" alt="License">
  <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go" alt="Go Version">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?logo=python" alt="Python Version">
  <img src="https://img.shields.io/badge/eBPF-Kernel%205.8+-orange?logo=linux" alt="eBPF Support">
  <img src="https://img.shields.io/badge/Kubernetes-K3s-blueviolet?logo=kubernetes" alt="Kubernetes">
</p>

**AetherOps** 是一个 AI 驱动的智能运维 Agent 系统。它通过 eBPF 在内核层零侵入捕获所有 TCP 通信，构建实时调用拓扑，用图算法定位故障根因，再通过 **Supervisor + 5 Expert Agents** 的多 Agent 架构进行因果推理、LLM 诊断和分级自愈——实现完整的 AIOps 闭环：**发现 → 诊断 → 自愈 → 验证 → 学习**。

## 系统架构

```
┌──────────────────────────────────────────────────────────────┐
│                    Go 数据面 (Data Plane)                       │
│                                                              │
│   eBPF kprobe → Ring Buffer → ServiceGraph                   │
│   → 异常检测 → 根因分析 → 内核级自愈                          │
│   → Prometheus 指标 + MCP Server (:50052)                    │
│                                                              │
│   语言: Go    部署: K3s DaemonSet                             │
└──────────────────────────┬───────────────────────────────────┘
                           │
                    MCP 协议 (JSON-RPC 2.0 over HTTP SSE)
                           │
┌──────────────────────────▼───────────────────────────────────┐
│               Python 认知面 (Cognitive Plane)                   │
│                                                              │
│   Supervisor + 5 Expert Agents                               │
│   → Topology Analyst | Causal Analyst | LLM Diagnostician    │
│   → Risk Assessor | Remediation Executor                     │
│   → 恢复验证 + MTTR 报告 → RAG 知识库                         │
│                                                              │
│   语言: Python   部署: K3s Deployment                         │
└──────────────────────────────────────────────────────────────┘
```

### 为什么分两个子系统？

| 维度 | Go 数据面 | Python 认知面 |
|------|-----------|---------------|
| **职责** | 实时数据采集 + 快速响应 | 智能分析 + 复杂决策 |
| **延迟要求** | 微秒~毫秒级 | 秒~分钟级 |
| **依赖** | 仅内核 + K8s | LLM、因果发现库等 |
| **部署形态** | DaemonSet（每节点一个） | Deployment（几个副本） |
| **失败影响** | 丢实时数据 | 丢分析能力，不影响自愈 |

**核心原则**：数据面可以脱离认知面独立运行——即使 Python 端挂了，Go 端的内核级自愈（TC 丢包、K8s 重启）依然正常工作。认知面只是让决策更聪明，不是生死依赖。

## 核心功能

### Go 数据面 (eBPF 实时监控)

- **零埋点 TCP 采集**：eBPF kprobe 挂载 `tcp_sendmsg`，自动提取源/目的 IP、端口、延迟、进程名
- **连接生命周期跟踪**：kprobe `tcp_connect` + `tcp_close` 测量真实连接持续时间
- **服务身份识别**：基于 cgroup 解析 K8s Pod 名，30 秒 TTL 缓存
- **动态基线 & 自适应阈值**：滑动窗口 P95 + EMA 指数移动平均
- **多维度异常评分**：延迟比率 + 错误率 + 调用量骤降三因子综合打分
- **反向随机游走根因分析**：PageRank 变体，沿反向调用图传播怀疑度
- **HTTP/gRPC 协议解析**：uprobe 挂载 `net/http` 和 `grpc.Invoke`
- **内核级自愈**：eBPF TC 程序实现微秒级丢包熔断
- **K8s Pod 隔离**：client-go 自动重启可疑 Pod
- **故障现场保留**：CPU 火焰图、堆内存火焰图、goroutine/thread dump、tcpdump 抓包
- **策略引擎 (Policy Guard)**：OPA 风格安全策略，防止误操作
- **MCP 协议服务**：通过 MCP (Model Context Protocol) 暴露拓扑查询、爆炸半径评估、策略检查等工具
- **gRPC 服务**：兼容 gRPC 客户端的拓扑订阅和异常事件流
- **飞书/钉钉告警**：推送根因摘要和故障现场文件信息

### Python 认知面 (AetherOps AI Agent)

- **Supervisor + 5 Expert Agents**：状态驱动的多 Agent 工作流
  - **Topology Analyst**：获取服务拓扑快照
  - **Causal Analyst**：LPCMCI 因果发现算法，从关联中推断因果关系
  - **LLM Diagnostician**：AI 诊断（兼容 OpenAI 协议，支持 DeepSeek/通义千问等）
  - **Risk Assessor**：爆炸半径评估，风险量化
  - **Remediation Executor**：分级自愈执行 + 恢复验证
- **多轮诊断**：LLM 可主动请求更多数据（指标/日志/配置），3 轮内提升置信度
- **告警关联与去重**：三层关联（时间窗口去重 → 因果分组 → 风暴抑制）
- **反馈循环**：审计日志、审批流程、自动回退
- **RAG 知识库**：基于 Milvus 的故障模式检索，每次修复结果存入向量数据库供后续参考
- **Chaos Engineering**：6 种故障注入（延迟/Pod 删除/CPU 压力等），本地模拟 + K8s Chaos Mesh
- **基准评测**：30 个标注故障场景，自动评估根因定位准确率和 MTTR
- **Web 仪表盘**：Streamlit 可视化，展示架构图、工作流追踪、MTTR 趋势

### 分级自愈策略

| 风险等级 | 条件 | 执行方式 |
|----------|------|----------|
| LOW | 爆炸半径小、错误预算充足 | 自动执行 |
| MEDIUM | 影响有限、但有一定风险 | 通知 SRE，60s 无拒绝则执行 |
| HIGH | 影响多个服务 | 只告警、不执行，需人工审批 |

## 快速开始

### 环境要求
- Linux 内核 >= 5.8（支持 BTF、CO-RE）
- Go >= 1.24 + clang/llvm 18+
- Python >= 3.11
- Poetry（Python 依赖管理）
- Minikube v1.38+（可选，K8s 功能需要）

### 本地运行（数据面）

```bash
# 编译 eBPF 探针
go generate ./cmd/tracer/...
go build -o ebpf-local ./cmd/tracer/

# 启动（模拟延迟模式）
sudo SIMULATE_LATENCY=1 ./ebpf-local
```

### 运行 AI Agent（认知面）

```bash
# 安装 Python 依赖
cd aetherops
poetry install

# Demo 模式（无需 Go 后端，模拟数据演示完整工作流）
poetry run python -m aetherops.main --workflow

# 守护模式（连接 Go 数据面的 MCP 服务）
export LLM_API_KEY=sk-xxx
poetry run python -m aetherops.main --daemon
```

### Docker Compose 全栈部署

```bash
docker compose -f docker-compose.aetherops.yml up -d
```

启动以下服务：
- AetherOps Core（Python 认知面）
- Neo4j（依赖关系图存储）
- Milvus + Etcd + MinIO（RAG 向量存储）
- Prometheus + Grafana（可观测性）

### 配置参数（环境变量）

关键调优参数，全部通过环境变量设置：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CFG_P95_MULTIPLIER` | 1.2 | 异常延迟阈值 = P95 × 此倍数 |
| `CFG_MIN_LAT_MS` | 10 | 最小延迟阈值(ms)，防止噪声误报 |
| `CFG_CALL_QPS_DROP_RATIO` | 0.3 | QPS 降至基线此比例时触发异常 |
| `CFG_CALL_ANOMALY_WEIGHT` | 2.0 | 调用量异常在综合分数中的权重 |
| `CFG_ANALYSIS_INTERVAL` | 15 | 分析间隔(秒) |
| `CFG_MITIGATION_COOLDOWN_SEC` | 120 | 同一节点自愈冷却时间(秒) |
| `CFG_PROFILE_DURATION` | 10 | pprof 火焰图采集时长(秒) |
| `CFG_MAX_SUSPECTS` | 5 | 根因分析最大嫌疑节点数 |

## 项目结构

```
├── bpf/                            # ★ eBPF 内核探针 (C)
│   ├── net_trace.c                 # TCP 延迟探针 (kprobe/tcp_sendmsg)
│   ├── tcp_conntrack.c             # 连接跟踪 (kprobe/tcp_connect + tcp_close)
│   ├── tc_drop.c                   # TC 入口丢包程序
│   ├── http_probe.c                # HTTP/gRPC uprobe
│   └── vmlinux.h                   # 内核类型定义 (CO-RE)
│
├── cmd/tracer/                     # ★ Go 数据面
│   ├── main.go                     # 入口 + eBPF 加载 + 事件循环
│   ├── analysis.go                 # 根因分析引擎（反向随机游走）
│   ├── graph.go                    # 服务拓扑图 (节点/边/EMA/P95)
│   ├── mitigation.go               # 自愈操作 (TC/K8s/火焰图/通知)
│   ├── policy_engine.go            # OPA 风格策略引擎
│   ├── blast_radius.go             # 爆炸半径评估
│   ├── grpc_server.go              # gRPC 服务 (拓扑/异常事件流)
│   ├── mcp_server.go               # ★ MCP 协议服务 (JSON-RPC 2.0 over SSE)
│   ├── resolver.go                 # cgroup 服务身份解析
│   ├── http_probe.go               # HTTP/gRPC uprobe 消费
│   └── ...
│
├── aetherops/                      # ★ Python 认知面 (AetherOps)
│   ├── main.py                     # 守护进程入口 (MCP/gRPC 双通道)
│   ├── demo.py                     # 3 分钟演示脚本
│   ├── dashboard.py                # Streamlit 可视化仪表盘
│   ├── workflow.yaml               # 工作流配置
│   │
│   ├── core/                       # 核心模块
│   │   ├── mcp_client.py           # ★ MCP 客户端
│   │   ├── llm_diagnosis.py        # ★ LLM 诊断 (5 种故障模式)
│   │   ├── multi_turn_diagnosis.py # 多轮诊断
│   │   ├── alert_correlation.py    # 告警关联与去重
│   │   ├── causal_inference.py     # LPCMCI 因果发现
│   │   ├── risk_client.py          # 风险评估客户端
│   │   ├── socratic_debugger.py    # 苏格拉底式调试器
│   │   ├── feedback.py             # 反馈循环与审计
│   │   └── metrics_fetcher.py      # Prometheus 指标采集
│   │
│   ├── workflows/
│   │   └── langgraph_workflow.py   # ★ Supervisor + 5 Agent 工作流
│   │
│   ├── rag/                        # RAG 知识库
│   │   ├── retriever.py
│   │   └── store.py
│   │
│   ├── chaos/                      # 混沌工程
│   │   └── engine.py
│   │
│   ├── benchmark/                  # 基准评测
│   │   ├── scenarios.py            # 30 个标注故障场景
│   │   ├── evaluator.py            # 评测引擎
│   │   └── run.py                  # 命令行入口
│   │
│   ├── dspy/                       # DSPy 优化
│   │   └── optimizer.py
│   │
│   └── proto/                      # gRPC protobuf
│
├── proto/                          # gRPC 协议定义
│   ├── aetherops.proto
│   └── gen/                        # 生成的 Go 代码
│
├── deploy/                         # K8s 部署清单
│   ├── ebpf-tracer.yaml            # Go 数据面 DaemonSet
│   ├── aetherops-core.yaml         # Python 认知面 Deployment
│   ├── aetherops-neo4j.yaml        # Neo4j 图数据库
│   ├── aetherops-milvus.yaml       # Milvus 向量数据库
│   ├── aetherops-install.sh        # 一键安装脚本
│   └── example-policies.json       # 策略配置示例
│
├── Dockerfile.agent                # Go 数据面容器构建
├── docker-compose.aetherops.yml    # 全栈 Docker Compose
├── proto/aetherops.proto           # gRPC 协议定义
│
├── stress.py                       # 压力测试脚本
└── pprof-demo.go                   # 本地 pprof 测试服务
```

## 技术栈

| 层 | 技术 |
|----|------|
| **内核** | eBPF, kprobe/kretprobe, TC, uprobe, CO-RE, BPF maps, Ring Buffer, cgroupv2 |
| **数据面** | Go 1.24, cilium/ebpf, bpf2go, Prometheus client, client-go |
| **认知面** | Python 3.11, LangGraph, LangChain, DSPy, causal-learn |
| **AI** | 兼容 OpenAI 协议 (DeepSeek / 通义千问等), 断路器, 注入防护 |
| **通信** | MCP 协议 (JSON-RPC 2.0 over HTTP SSE), gRPC (备选) |
| **算法** | EMA, 滑动窗口 P95, 反向随机游走 (PageRank), LPCMCI 因果发现 |
| **存储** | Neo4j (图), Milvus (向量), Prometheus (指标) |
| **部署** | Docker, K3s, Kubernetes DaemonSet/Deployment, Helm |
| **通知** | 飞书 / 钉钉 webhook |

## 基准评测结果

30 个标注故障场景，覆盖 5 种故障模式 + 2 个边界用例：

| 模式 | 场景数 | 根因准确率 | 操作准确率 |
|------|--------|-----------|-----------|
| 数据库慢查询 | 6 | 83.3% | 83.3% |
| 缓存雪崩 | 5 | 80.0% | 80.0% |
| 网络拥塞 | 5 | 80.0% | 60.0% |
| 资源耗尽 | 7 | 85.7% | 85.7% |
| 热点/低效算法 | 5 | 80.0% | 80.0% |
| **总计** | **30** | **86.7%** | **80.0%** |

> 运行评测：`python -m aetherops.benchmark.run`

## 文档

| 文档 | 说明 |
|------|------|
| [AetherOps 完整指南](docs/AETHEROPS_GUIDE.md) | 架构详解、面试指南、测试手册 |
| [测试指南](docs/testing.md) | 本地功能完整测试步骤 |
| [项目简介](docs/PROJECT_INTRO.md) | 项目快速概览 |

## License

This project is licensed under the [GPL v3.0](LICENSE) license.
