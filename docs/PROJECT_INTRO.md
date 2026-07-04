# AetherOps — AI-Driven Intelligent Operations Agent

## 项目是什么

AetherOps 是一个 AI 驱动的智能运维 Agent 系统，由**两层架构**组成：

1. **Go 数据面** — 基于 eBPF 的零侵入 TCP 采集与内核级自愈，构建实时服务调用拓扑
2. **Python 认知面** — Supervisor + 5 Expert Agents 架构，进行因果推理、LLM 诊断、分级自愈

两层通过 **MCP 协议**（JSON-RPC 2.0 over HTTP SSE）通信。数据面可脱离认知面独立运行，保证基础自愈能力不依赖 AI 组件。

## 技术栈

| 层 | 技术 |
|----|------|
| **内核** | eBPF、kprobe/kretprobe、TC、uprobe、CO-RE、BPF Map、Ring Buffer |
| **数据面** | Go 1.24、cilium/ebpf、bpf2go、Prometheus client_golang、client-go |
| **认知面** | Python 3.11、LangGraph、LangChain、causal-learn、DSPy |
| **AI** | 兼容 OpenAI 协议（DeepSeek V4 Flash / 通义千问等） |
| **通信** | MCP 协议（主）、gRPC（备选） |
| **算法** | EMA 指数移动平均、滑动窗口 P95、反向随机游走（PageRank）、LPCMCI 因果发现 |
| **存储** | Neo4j（依赖图）、Milvus（RAG 向量）、Prometheus（指标） |
| **部署** | Docker、K3s、Kubernetes DaemonSet/Deployment |

## 核心功能

### Go 数据面
- **零侵入 TCP 采集**：eBPF kprobe 挂载 `tcp_sendmsg`，自动提取四元组 + 延迟 + 进程名
- **自适应阈值**：每条边维护滑动窗口 P95 + EMA 基线，无固定阈值
- **多维度异常评分**：延迟比率 + 错误率 + 调用量骤降三因子打分
- **反向随机游走**：PageRank 变体定位级联故障根因
- **内核级自愈**：eBPF TC 丢包熔断、K8s Pod 自动重启
- **故障现场保全**：CPU/内存火焰图、goroutine/thread dump、tcpdump
- **MCP + gRPC 双协议服务**：暴露拓扑、策略、自愈工具
- **OPA 风格策略引擎**：安全策略防止误操作

### Python 认知面 (AetherOps)
- **Supervisor + 5 Expert Agents**：状态驱动多 Agent 工作流
- **LLM 诊断**：5 种故障模式 + 多轮诊断（3 轮）+ 启发式回退
- **因果发现**：LPCMCI 算法从关联中推断因果关系
- **爆炸半径评估**：量化自愈操作的风险
- **分级自愈**：LOW 自动 / MEDIUM TEE / HIGH 人工审批
- **告警关联**：三层去重 + 因果分组 + 风暴抑制
- **RAG 知识库**：Milvus 存储故障模式，支持历史检索
- **Chaos Engineering**：6 种故障注入，30 场景基准评测
- **反馈循环**：审计日志、回退机制、审批流程
- **Web 仪表盘**：Streamlit 可视化

## 核心数据流

```
用户请求 → 服务 A → 服务 B
                │
                ▼
     ┌─────────────────────┐
     │ eBPF kprobe         │ ← 内核态捕获 TCP
     └─────────┬───────────┘
               │ Ring Buffer
     ┌─────────▼───────────┐
     │ Go: ServiceGraph    │ ← 调用拓扑 + EMA/P95
     └─────────┬───────────┘
               │ 定时分析
     ┌─────────▼───────────┐
     │ Go: 异常检测+根因分析 │ ← 反向随机游走
     └─────────┬───────────┘
               │ MCP 协议
     ┌─────────▼───────────┐
     │ Python: Supervisor   │ ← 路由到 Expert Agents
     └─────────┬───────────┘
               │
     ┌─────────▼───────────┐
     │ 因果发现 → LLM 诊断  │ ← 根因判断
     ├─────────────────────┤
     │ 爆炸半径评估         │ ← 风险量化
     ├─────────────────────┤
     │ 分级自愈 + 恢复验证  │ ← 执行 + 确认
     └─────────────────────┘
               │
               ▼
        MTTR 报告 + RAG 存储
```

## 快速启动

### 数据面（需要 Linux eBPF 环境）
```bash
go generate ./cmd/tracer/...
go build -o ebpf-local ./cmd/tracer/
sudo SIMULATE_LATENCY=1 ./ebpf-local
```

### 认知面（Demo 模式，无需 Go 后端）
```bash
cd aetherops && poetry install
# 或使用 pip 直接安装：
# pip install --break-system-packages -e .
poetry run python -m aetherops.main --workflow
```

### 全栈（Docker Compose）
```bash
docker compose -f docker-compose.aetherops.yml up -d
```

## 项目结构

```
bpf/                 # eBPF C 内核探针
cmd/tracer/          # Go 数据面（eBPF加载、拓扑、分析、自愈、MCP/gRPC服务）
aetherops/           # Python 认知面（Agent 工作流、LLM诊断、因果发现、RAG、Chaos）
proto/               # gRPC 协议定义
deploy/              # K3s 部署清单
```
