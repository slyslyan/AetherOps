# AetherOps — 完整面试指南 & 测试手册

> 目标：让你彻底理解整个项目（Go eBPF 数据平面 + Python AetherOps 认知平面），
> 学会如何测试，面试时任何角度的问题都能回答。
>
> 适用岗位：SRE / AIOps / 可观测性 / 基础设施 / 后端开发

---

## 目录

1. [项目全景：两个子系统](#1-项目全景两个子系统)
2. [架构总览](#2-架构总览)
3. [Go 数据平面（eBPF）快速回顾](#3-go-数据平面ebpf快速回顾)
4. [Python 认知平面（AetherOps）核心架构](#4-python-认知平面aetherops核心架构)
5. [MCP 协议详解](#5-mcp-协议详解)
6. [Supervisor + 5 Expert Agents](#6-supervisor--5-expert-agents)
7. [因果发现（Causal Discovery）](#7-因果发现causal-discovery)
8. [LLM 诊断与故障模式库](#8-llm-诊断与故障模式库)
9. [MTTR 与恢复验证](#9-mttr-与恢复验证)
10. [多轮诊断（Multi-Turn Diagnosis）](#95-多轮诊断multi-turn-diagnosis)
11. [告警关联与去重（Alert Correlation）](#96-告警关联与去重alert-correlation)
12. [反馈循环与审计（Feedback Loop）](#97-反馈循环与审计feedback-loop)
13. [Chaos Engineering（Chaos Mesh 集成）](#98-chaos-engineeringchaos-mesh-集成)
14. [Incident Benchmark（故障基准评测）](#99-incident-benchmark故障基准评测)
15. [Web Dashboard（Streamlit）](#910-web-dashboardstreamlit)
16. [JudgeX 集成](#10-judgex-集成)
17. [如何测试](#11-如何测试)
18. [面试深挖 30 题](#12-面试深挖-30-题)
19. [文件清单速查](#13-文件清单速查)

---

## 1. 项目全景：两个子系统

整个项目由两个独立的子系统组成，通过 **MCP 协议** 通信：

```
┌──────────────────────────────────────────────────────────────┐
│                    Go 数据平面 (Data Plane)                     │
│                                                              │
│   eBPF kprobe → Ring Buffer → ServiceGraph                   │
│   → 异常检测 → 根因分析 → 自愈操作                            │
│   → Prometheus 指标 + MCP Server (:50052)                    │
│   → gRPC Server (:50051)                                     │
│                                                              │
│   语言: Go              部署: K3s DaemonSet                   │
│   功能: 实时 TCP 数据采集、内核级自愈                          │
└──────────────────────────┬───────────────────────────────────┘
                           │
                    MCP 协议 (JSON-RPC 2.0 over HTTP SSE)
                           │
┌──────────────────────────▼───────────────────────────────────┐
│                  Python 认知平面 (Cognitive Plane)               │
│                                                              │
│   Supervisor + 5 Expert Agents                               │
│   → Topology Analyst | Causal Analyst | LLM Diagnostician    │
│   → Risk Assessor | Remediation Executor                     │
│   → 恢复验证 + MTTR 报告                                     │
│                                                              │
│   语言: Python         部署: K3s Deployment                   │
│   功能: 因果推理、LLM 诊断、爆炸半径评估、分级自愈              │
└──────────────────────────────────────────────────────────────┘
```

### 为什么分两个子系统？

| 维度 | Go 数据平面 | Python 认知平面 |
|------|-------------|-----------------|
| **职责** | 实时数据 + 快速响应 | 智能分析 + 复杂决策 |
| **延迟要求** | 微秒~毫秒级 | 秒~分钟级 |
| **需要什么** | 性能、低内存 | 生态（LLM、因果库） |
| **部署形态** | DaemonSet（每节点一个） | Deployment（几个副本） |
| **失败影响** | 丢实时数据 | 丢分析能力，不影响自愈 |

**核心原则**：数据平面可以脱离认知平面独立运行——即使 Python 端挂了，Go 端的内核级自愈（TC 丢包、K8s 重启）依然正常工作。认知平面只是让决策更聪明，不是生死依赖。

---

## 2. 架构总览

### 2.1 完整数据流

```
用户请求 → 服务 A → 服务 B
                │
                ▼
     ┌─────────────────────┐
     │ eBPF kprobe         │ ← 内核态捕获 TCP 通信
     │ tcp_sendmsg         │
     └─────────┬───────────┘
               │ Ring Buffer
     ┌─────────▼───────────┐
     │ Go: ServiceGraph    │ ← 维护调用拓扑
     │ EMA + P95 基线      │    自适应阈值
     └─────────┬───────────┘
               │ 定时分析 (15s)
     ┌─────────▼───────────┐
     │ Go: 异常检测         │ ← 多维度异常评分
     │ 反向随机游走根因分析  │
     └─────────┬───────────┘
               │ MCP (get_topology / evaluate_remediation)
     ┌─────────▼───────────┐
     │ Python: Supervisor   │ ← 动态路由到专家 Agent
     └─────────┬───────────┘
               │
     ┌─────────▼───────────┐
     │ 因果发现 (LPCMCI)    │ ← 从关联到因果
     ├─────────────────────┤
     │ LLM 诊断             │ ← 根因判断 + 建议
     ├─────────────────────┤
     │ 爆炸半径评估          │ ← 风险量化
     ├─────────────────────┤
     │ 分级自愈 + 恢复验证   │ ← 执行 + 确认
     └─────────────────────┘
               │
               ▼
        MTTR 报告 + RAG 存储
```

### 2.2 关键设计决策

| 决策 | 选择 | 为什么 |
|------|------|--------|
| 数据平面语言 | Go | eBPF 生态 Go 最好（cilium/ebpf），性能好 |
| 认知平面语言 | Python | LLM/因果发现/ML 生态都在 Python |
| 通信协议 | MCP | 标准化 JSON-RPC 2.0，比 gRPC 更简单、SSE 推送 |
| 认知架构 | Supervisor + 5 Agents | 模块化，每步可独立升级 |
| 路由逻辑 | 状态驱动 | 检查缺什么就补什么，而非固定流水线 |
| LLM 诊断 | 可回退 | LLM 不可用时走启发式算法 |

---

## 3. Go 数据平面（eBPF）快速回顾

> 以下为面试关键点总结，详细原理可参考内核文档或 eBPF 相关书籍。

### 3.1 eBPF 探针

| 文件 | 探针类型 | 功能 |
|------|----------|------|
| `bpf/net_trace.c` | kprobe/kretprobe `tcp_sendmsg` | TCP 延迟采集 |
| `bpf/tcp_conntrack.c` | kprobe `tcp_connect` / `tcp_close` | 连接持续时间 |
| `bpf/tc_drop.c` | TC ingress | 内核级丢包限流 |
| `bpf/http_probe.c` | uprobe Go HTTP/gRPC | 协议级解析 |

### 3.2 异常检测

```
每条边 (src→dst) 的异常分数：
  score = latRatio × errorFactor + callDropScore × CFG_CALL_ANOMALY_WEIGHT

  latRatio = avgLat / max(P95 × CFG_P95_MULTIPLIER, CFG_MIN_LAT_MS)  // 延迟比率
  errorFactor = 1 + errors/count                                       // 错误放大
  callDropScore = (EMA - currentQPS) / EMA                             // 调用量骤降

所有阈值通过环境变量调优（默认值）：
  CFG_P95_MULTIPLIER=1.2      延迟倍数阈值（调低至 1.01 更敏感）
  CFG_MIN_LAT_MS=10           最小延迟阈值（调至 0 关闭下限）
  CFG_CALL_ANOMALY_WEIGHT=2.0 调用量异常权重
  CFG_ANALYSIS_INTERVAL=15    分析间隔（秒）
  CFG_MITIGATION_COOLDOWN_SEC=120 自愈冷却时间（秒）
```

### 3.3 反向随机游走

```
输入：异常节点集合
算法：15% 概率重启 + 85% 概率沿入边反向传播
输出：每个节点的嫌疑分数
作用：从下游异常→定位上游根因
```

### 3.4 面试高频点

- **为什么用 Ring Buffer 而不是 Perf Buffer？** 保序、内存可预测
- **为什么用 P95 而不是平均/ P99？** 抗噪 vs 敏感度的平衡
- **为什么用 EMA？** 轻量（O(1)）、对近期趋势敏感
- **IP 为什么显示为 2.49.168.192？** 字节序问题，网络序 vs 主机序
- **kretprobe 中读不到 sk 参数？** 返回时寄存器已销毁，靠 BPF map 传值
- **Go ABI 和标准 ABI 区别？** Go 参数传 RAX/RBX/RCX 而非 RDI/RSI/RDX

---

## 4. Python 认知平面（AetherOps）核心架构

### 4.1 目录结构

```
aetherops/
├── __init__.py
├── main.py                       # 守护进程入口（MCP/gRPC 双通道）
├── demo.py                       # 3 分钟演示脚本
├── dashboard.py                  # Streamlit 可视化仪表盘
│
├── core/
│   ├── mcp_client.py             # ★ MCP 客户端（与 Go 数据面通信）
│   ├── llm_diagnosis.py          # ★ LLM 诊断（5 种故障模式）
│   ├── multi_turn_diagnosis.py   # 多轮诊断（LLM 可请求更多数据）
│   ├── causal_inference.py       # LPCMCI 因果发现
│   ├── alert_correlation.py      # 告警关联与去重
│   ├── feedback.py               # 反馈循环与审计日志
│   ├── risk_client.py            # 风险评估客户端
│   ├── metrics_fetcher.py        # Prometheus 指标采集
│   └── grpc_client.py            # gRPC 客户端（备选通信）
│
├── workflows/
│   └── workflow.py                 # ★ Supervisor + 5 Agent 工作流
│
├── rag/
│   ├── retriever.py              # RAG 检索器
│   └── store.py                  # Milvus 向量存储管理
│
├── chaos/
│   └── engine.py                 # 混沌工程引擎
│
├── benchmark/
│   ├── scenarios.py              # 30 个标注故障场景
│   ├── evaluator.py              # 评测引擎
│   └── run.py                    # 命令行入口
│
├── dspy/
│   └── optimizer.py              # DSPy Prompt 优化
│
└── proto/
    └── aetherops_pb2*.py         # 生成的 protobuf 代码
```

### 4.2 关键文件职责

| 文件 | 重要性 | 职责 |
|------|--------|------|
| `mcp_client.py` | ⭐⭐⭐⭐⭐ | 与 Go 数据面通信的桥梁 |
| `workflow.py` | ⭐⭐⭐⭐⭐ | 整个认知平面的心脏 |
| `llm_diagnosis.py` | ⭐⭐⭐⭐⭐ | LLM 诊断决策 |
| `causal_inference.py` | ⭐⭐⭐⭐ | LPCMCI 因果发现 |
| `alert_correlation.py` | ⭐⭐⭐⭐ | 告警关联去重 |
| `demo.py` | ⭐⭐⭐⭐ | 演示 + 快速验证 |
| `workflow.yaml` | ⭐⭐⭐ | 已删除，配置逻辑直接编码在 Python 代码中 |

### 4.3 AetherOps 工作流状态

```python
state = {
    # 输入
    "anomaly_event": {             # 来自 Go 的异常事件
        "node_id": "service:8080",
        "anomaly_score": 87.5,
        "avg_latency_ms": 2500.0,
        "suspect_chain": ["svc-a", "svc-b"],
        "timestamp_unix_nano": ...
    },
    "anomaly_detected_at": ...      # 检测时间（用于 MTTR）

    # 中间产物
    "topology_snapshot": None,      # Agent 1: 拓扑快照
    "metrics_data": None,           # Agent 2: Prometheus 指标
    "causal_graph": None,           # Agent 2: 因果图
    "diagnosis_report": None,       # Agent 3: 诊断报告
    "diagnosis_confidence": 0.0,    # Agent 3: 置信度
    "risk_report": None,            # Agent 4: 风险评估
    "execution_result": None,       # Agent 5: 执行结果
    "topology_before": None,        # 自愈前的拓扑（用于对比）
    "recovery_report": None,        # 恢复验证报告

    # 路由控制
    "next_agent": "topology_analyst",  # Supervisor 路由目标
    "completed": False,
    "workflow_error": None,
}
```

---

## 5. MCP 协议详解

### 5.1 什么是 MCP？

MCP（Model Context Protocol）是 Anthropic 推出的标准化 AI 工具协议。它定义了一种通用的方式让 AI 应用调用外部工具。

简单类比：
- **HTTP 是浏览器获取网页的协议**
- **MCP 是 AI 获取工具/数据的协议**

### 5.2 MCP vs gRPC 对比

| 维度 | MCP | gRPC（本项目的旧方案） |
|------|-----|----------------------|
| 传输 | HTTP + SSE | HTTP/2 |
| 序列化 | JSON（人类可读） | Protobuf（二进制） |
| 接口定义 | 运行时 tools/list | `.proto` 文件 |
| 流式推送 | SSE 原生支持 | 需要 Streaming API |
| 工具发现 | 自动（tools/list） | 手动维护 |
| 复杂度 | 低 | 高（代码生成、编译） |

**为什么从 gRPC 切到 MCP？**
1. **不需要 proto 文件编译**：Go 改一个字段，Python 不需要重新生成
2. **工具自发现**：`tools/list` 返回所有可用工具，对新工具自动适配
3. **SSE 推送**：Go 端可以直接推送异常事件到 Python 端
4. **行业标准**：MCP 正在成为 AI 工具协议的事实标准

### 5.3 MCP 协议流程

```
[Python 认知平面]                              [Go 数据平面]

1. SSE 连接建立:
   GET /sse  HTTP/1.1
   Accept: text/event-stream
              │
              ▼
   HTTP 200 OK
   Content-Type: text/event-stream
   ← event: endpoint
     data: /message
   
   客户端收到 endpoint 事件 → 后续 JSON-RPC 发到 /message

2. tools/list (获取可用工具):
   POST /message
   Content-Type: application/json
   → {"jsonrpc":"2.0","id":"1","method":"tools/list"}
              │
              ▼
   ← (via SSE) {"jsonrpc":"2.0","id":"1","result":{"tools":[
     {"name":"get_topology","description":"Get service topology graph"},
     {"name":"evaluate_remediation","description":"Evaluate blast radius"},
     {"name":"execute_remediation","description":"Execute remediation action"}
   ]}}

3. tools/call get_topology (调用工具):
   POST /message
   → {"jsonrpc":"2.0","id":"2","method":"tools/call",
     "params":{"name":"get_topology","arguments":{"include_healthy":true}}}
              │
              ▼
   ← (via SSE) {"jsonrpc":"2.0","id":"2","result":{
     "nodes": [...], "edges": [...], ...}}

4. SSE 异常推送 (Go → Python, 实时):
   ← (via SSE) {"jsonrpc":"2.0",
     "method":"notifications/events/anomaly",
     "params":{"node_id":"service:8080","anomaly_score":87.5,...}}
```

**重要提示**：MCP SDK 内部自动处理 SSE 连接和 endpoint 发现。Python 端只需调用 `sse_client(url)`，无需手动管理 HTTP 请求。详细流程图只用于理解协议原理，实际开发中 SDK 已封装。**SSH 隧道场景**：如果 Go 数据面部署在远程服务器，通过 `ssh -L 50052:localhost:50052 user@host` 建立隧道后，Python 端连接 `http://localhost:50052` 即可，流程与本地一致。

### 5.4 MCPClient 核心代码

实际实现使用官方的 `mcp` Python SDK（`mcp >= 1.0`），通过 SSE 传输层连接：

```python
from mcp import ClientSession
from mcp.client.sse import sse_client

class MCPClient:
    def __init__(self, address: str = "http://localhost:50052"):
        self.address = address.rstrip("/")
        self._sse_url = f"{self.address}/sse"  # SSE endpoint
        self._session: Optional[ClientSession] = None

    async def connect(self) -> None:
        """Establish SSE connection and discover tools."""
        self._sse_ctx = sse_client(self._sse_url)
        read, write = await self._sse_ctx.__aenter__()
        self._session = ClientSession(read, write)
        await self._session.__aenter__()
        await self._session.initialize()

        # 自动发现工具
        tools_result = await self._session.list_tools()
        self._tools = [t.model_dump() for t in tools_result.tools]

    async def get_topology(self, include_healthy: bool = False) -> dict:
        """Fetch current service graph."""
        return await self._call_tool("get_topology",
            {"include_healthy": include_healthy})

    async def evaluate_remediation(self, target: str, action: str) -> dict:
        """Evaluate blast radius."""
        return await self._call_tool("evaluate_remediation",
            {"target_node": target, "action": action})
```

**同步→异步桥接**：由于 Workflow 节点是同步函数，而 MCP SDK 全是异步的，通过 `run_async()` 将协程派发到后台事件循环：

```python
def run_async(coro):
    loop = get_bg_loop()  # 持久后台线程事件循环
    return asyncio.run_coroutine_threadsafe(coro, loop).result()
```

> **注意**：Python SDK `mcp>=1.0` 使用 `sse_client()` 返回 (read_stream, write_stream) 元组，会话清理使用 `__aexit__`（SDK v1 无 close() 方法）。

### 5.5 面试要点

- MCP 基于 JSON-RPC 2.0（不是 REST，不是 GraphQL）
- SSE（Server-Sent Events）是单向推送，比 WebSocket 轻量
- `tools/list` 让客户端动态发现服务端能力，不需要客户端预知
- 本项目 MCP 和 gRPC 可以共存：`AETHEROPS_TRANSPORT=mcp|grpc` 切换

---

## 6. Supervisor + 5 Expert Agents

### 6.1 架构模式

```
                         Supervisor
                    (状态驱动的路由器)
                           │
         ┌─────────────────┼─────────────────┐
         │       │         │         │        │
         ▼       ▼         ▼         ▼        ▼
     Topology  Causal    LLM      Risk    Remediation
     Analyst   Analyst  Diagnostician Assessor Executor
     (Agent1)  (Agent2)  (Agent3)  (Agent4)  (Agent5)
```

这不是固定的"流水线"（pipeline），而是**状态驱动的动态路由**（state-driven routing）。

### 6.2 路由逻辑

```
每次 Supervisor 被调用：

1. if topology_snapshot is None → 路由到 topology_analyst
2. elif causal_graph is None   → 路由到 causal_analyst
3. elif diagnosis_report is None → 路由到 llm_diagnostician
4. elif confidence < 0.6 AND loop_count < 2 → 回 causal_analyst（重分析）
5. elif risk_report is None    → 路由到 risk_assessor
6. elif execution_result is None → 路由到 remediation_executor
7. else → finish
```

**关键特性**：不是固定流水线！跳过已有数据的 Agent。低置信度自动循环重试。

### 6.3 每个 Agent 详解

#### Agent 1: Topology Analyst

```
输入: anomaly_event.node_id (哪个服务异常了)
操作: 通过 MCP get_topology 获取当前服务拓扑
输出: topology_snapshot = {nodes: [...], edges: [...]}
问题: 异常发生时，周围的拓扑是什么样的？
```

#### Agent 2: Causal Analyst

```
输入: topology_snapshot + metrics_data
操作: 
  1. 从 Prometheus 拉取 5 分钟指标窗口
  2. 运行 LPCMCI 因果发现算法
输出: causal_graph = {nodes: [...], edges: [{src, dst, strength}]}
问题: 延迟升高是 MySQL 导致的还是 Redis 导致的？因果关系是什么？
```

> 详情见第 7 章「因果发现」

#### Agent 3: LLM Diagnostician

```
输入: causal_graph + anomaly_context
操作:
  1. 尝试调用 DeepSeek V4 Flash（需要 LLM_API_KEY）
  2. 如果 LLM 不可用 → 走启发式回退
输出: diagnosis_report = {
    root_cause: "mysql-0:3306",
    confidence: 0.85,
    explanation: "...",
    recommended_actions: [{action: "SCALE_UP", target: "...", risk: "LOW"}]
}
问题: 根因是什么？证据是什么？应该怎么修？
```

#### Agent 4: Risk Assessor

```
输入: 诊断结果 + 建议操作
操作: 通过 MCP evaluate_remediation 评估爆炸半径
输出: risk_report = {
    risk_level: "RISK_LOW",
    affected_upstream_count: 2,
    affected_downstream_count: 5,
    estimated_error_budget_consumption: 3.2%,
    recommendation: "Safe to execute"
}
问题: 这个操作会影响多少上下游？会不会引发更大故障？
```

#### Agent 5: Remediation Executor

```
输入: 风险报告 + 推荐操作
操作:
  1. 通过 MCP execute_remediation 执行
  2. 保存 pre-remediation 拓扑快照
  3. 等待 10s 让指标稳定
  4. 重新获取拓扑（post-remediation）
  5. 对比 before/after 生成恢复报告
  6. 存储到 RAG（Milvus）供后续学习
输出: recovery_report (Markdown 格式)
问题: 修复生效了吗？MTTR 是多少？
```

### 6.4 分级自愈策略

| 风险等级 | 条件 | 执行方式 | 是否需要人工 |
|----------|------|----------|-------------|
| LOW | 爆炸半径小、错误预算充足 | 自动执行 | 否 |
| MEDIUM | 影响有限、但有一定风险 | TEE（需要确认） | 是（通知后 60s 无拒绝则执行） |
| HIGH | 影响多个服务 | 只告警、不执行 | 是（人工审批） |

### 6.6 Critic 与评审分层设计

Critic Agent 负责评审 LLM 诊断报告的质量。初始版本对所有诊断一律走 LLM 评审，在性能实测中暴露了两个问题：

| 问题 | 表现 | 根因 |
|------|------|------|
| 无意义打回 | 低风险简单故障也被 LLM 挑"描述性"瑕疵 | 评审没有分层，统一标准 |
| 重诊断空跑 | 拒绝后重诊断没有增量输入，纯靠方差 | 未传递 Critic 的修改意见 |

**分层评审设计（待实现）**：

| 风险等级 | 评审方式 | 条件 | 预期耗时 |
|---------|---------|------|---------|
| LOW | 规则校验 | 格式检查 + 置信度 ≥ 0.7 + 根因在服务列表内 | 毫秒级 |
| MEDIUM | LLM 评审 | 完整诊断报告审查 | ~10s |
| HIGH | LLM 评审 + 人工 | 同上 + 等待 SRE 审批 | ~10s + 人工 |

**面试价值**：分层评审展示了你对"自愈系统设计权衡"的理解——不是所有诊断都需要 LLM 级别的审查，用规则处理 90% 的简单故障，用 LLM 处理 10% 的复杂场景，整体效率最优。

### 6.7 Supervisor 架构的面试价值

问："为什么不用一个简单的 if-else 流水线？"

答：流水线的问题：
1. **浪费**：如果 topology 已经有了，不需要重新获取
2. **不灵活**：低置信度时需要重分析，流水线不支持循环
3. **难扩展**：加一个新 Agent 要改整条流水线

Supervisor 模式的好处：
1. **状态驱动**：缺什么就跑什么
2. **自动循环**：低置信度自动回退重分析
3. **模块化**：加 Agent 只需要加一个路由条件
4. **可观测**：每个路由决策都有记录

---

## 7. 因果发现（Causal Discovery）

### 7.1 为什么要因果发现？

```
场景：服务 A 调用 B，B 调用 C
现象：A 延迟异常

问题：是 A 慢了还是 C 慢了？
  - 如果 A 慢了是因为 C 慢了 → 根因是 C
  - 如果 C 正常，A 自己慢了 → 根因是 A

普通监控无法区分"相关"和"因果"。
因果发现就是用来回答：到底是哪个服务导致了延迟异常？
```

### 7.2 LPCMCI 算法

LPCMCI（Latent PCMCI）是一种因果发现算法，结合了：
- **PC 算法**：从无向图开始，通过条件独立测试逐步删除边
- **PCMCI**：加了时间滞后信息，处理时间序列数据
- **L (Latent)**：处理隐变量（无法观测到的因素）

简单理解：
```
1. 先算所有服务对之间的相关性
2. 再算条件独立性：加入 Z 后 X 和 Y 是否还相关？
   如果 X 和 Y 的相关性是因为 Z 导致的，控制 Z 后 XY 就没关系了
3. 加上时间信息：X(t-1) → Y(t) 比 X(t) → Y(t) 更可能是因果
4. 输出因果有向图
```

### 7.3 性能优化：因果图稀疏化

PC 算法在 N 个变量上的复杂度为 O(N²)。当拓扑有 1200+ 节点时，全量运行导致 5s+ 延迟。

**稀疏化策略**：

```
输入: 1200 维指标 DataFrame
   │
   ▼
1. 提取可疑节点集（anomaly_event.node_id → suspect_chain → 拓扑异常边）
2. 筛选指标列：只保留与可疑节点相关的列
3. 安全上限：MAX_CAUSAL_VARS=50（环境变量可调）
   │
   ▼
输出: ≤50 维的稀疏化 DataFrame
   │
   ▼
PC 算法: O(50²) 而非 O(1200²)，耗时从 5.2s→3.0s (-43%)
```

**三个筛选来源**：
- primary suspect from anomaly_event.node_id
- suspect propagation chain
- topology edges with anomaly_score > 0

**设计原则**：在"因果发现的完整性"和"诊断时效性"之间做工程取舍。故障根因几乎一定落在可疑节点集中，丢失真正根因的概率极低。

### 7.4 面试回答

问："为什么不用简单关联分析？"

答：关联不等于因果。以 MySQL 连接池耗尽为例：
- 关联分析会发现：MySQL 延迟高、Redis 延迟高、后端延迟高——三者都相关
- 但因果关系是：后端调用 MySQL → MySQL 连接池耗尽 → 连接等待 → 延迟传导
- 因果发现可以把"谁是因谁是果"分清楚

用大白话说：**关联 ≈ 两个人同时感冒了；因果 ≈ 一个人传染了另一个人。**
要找治病的根本，必须要区分因果。

---

## 8. LLM 诊断与故障模式库

### 8.1 LLM 诊断流程

```
用户在 env 设置 LLM_API_KEY=sk-xxx（DeepSeek V4 Flash）
                │
                ▼
    构造 System Prompt（包含 5 种故障模式和输出格式）
                │
                ▼
    构造 User Prompt（因果图 + 异常上下文）
                │
                ▼
    调用 DeepSeek API (https://api.deepseek.com/v1/chat/completions)
                │
                ▼
    解析 JSON 输出 → DiagnosisReport
                │
        ┌───────┴───────┐
        ▼               ▼
    LLM 可用          LLM 不可用
    (高质量诊断)      (走启发式回退)
```

### 8.2 5 种故障模式

LLM 的 System Prompt 中包含 5 种已知故障模式：

| # | 模式 | 症状 | 推荐操作 |
|---|------|------|---------|
| 1 | 数据库慢查询 | P95 高、CPU 正常、QPS 无变化 | CONFIG_CHANGE 或 POD_RESTART |
| 2 | 缓存雪崩 | 多个服务同时延迟飙升、错误率高 | SCALE_UP + 缓存 TTL 调优 |
| 3 | 网络拥塞 | 某节点的所有出边延迟都高、TCP 重传 | TC_DROP（熔断）+ POD_RESTART |
| 4 | 资源耗尽 | 延迟逐渐爬升、调用量激增（重试风暴） | SCALE_UP + POD_RESTART |
| 5 | 热点/低效算法 | 单个服务 P95 高、无下游依赖链 | CONFIG_CHANGE 或 IMAGE_ROLLBACK |

**面试价值**：这展示了你不是简单调 API，而是把 SRE 领域的故障排查经验编码进了 Prompt。

### 8.3 启发式回退（无 LLM 时）

当 `LLM_API_KEY` 未设置或 API 调用失败时：

```python
def _heuristic_diagnosis(causal_graph, anomaly_context):
    # 统计因果图中每个节点的出度
    outgoing = {}
    for src, dst in edges:
        outgoing[src] = outgoing.get(src, 0) + 1

    # 出度最大的节点 = 根因
    root_cause = max(outgoing, key=outgoing.get)

    return DiagnosisReport(
        root_cause=root_cause,
        confidence=0.4,  # 显式低置信度
        recommended_actions=[{"action": "TC_DROP", "risk": "LOW"}]
    )
```

**关键设计**：启发式模式的置信度固定为 0.4（低于 0.6 阈值），触发 Supervisor 的自动重分析循环。

### 8.4 Prompt 设计要点

```python
DIAGNOSIS_SYSTEM_PROMPT = """You are an expert SRE reliability engineer...

## Quality Checklist
- Confidence must be between 0 and 1
- Explanations must reference specific metrics
- Actions must map to: TC_DROP, POD_RESTART, SCALE_UP, CONFIG_CHANGE, IMAGE_ROLLBACK

## Known Fault Patterns
### Pattern 1: Database Slow Query
...
"""

# 关键设计决策
# 1. 输出格式用 JSON → 方便程序解析
# 2. 操作枚举受限 → 保证机器可执行
# 3. 置信度区间 [0,1] → Supervisor 可用 0.6 阈值决策
# 4. 故障模式可扩展 → 加一个 Pattern 6 就行
```

---

## 9. MTTR 与恢复验证

### 9.1 恢复验证流程

```
执行自愈操作 (SCALE_UP / POD_RESTART)
    │
    ▼
保存自愈前的拓扑快照 (topology_before)
    │
    ▼
指数退避轮询: 2s → 3s → 5s
检查拓扑异常分数是否降低 > 50%
    │
    ├─ 第 1 次 (2s):  已恢复 → 提前退出 ✅
    ├─ 第 2 次 (3s):  已恢复 → 提前退出 ✅
    ├─ 第 3 次 (5s):  最终判断
    │
    ▼
对比 Before / After 的异常分数
    │
    ├─ 分数降低 > 50% → 修复成功 ✅
    ├─ 分数降低 < 50% → 修复部分生效 ⚠️
    └─ 分数升高       → 需要回退或其他方案 ❌
    │
    ▼
生成 Markdown 恢复报告
    │
    ▼
存储到 RAG (Milvus) → 后续类似故障可参考
```

### 9.2 MTTR 构成

```
MTTR = Mean Time To Recovery

         检测时间    诊断时间    风险评估   执行时间    验证时间
         ┌─────┐   ┌──────┐   ┌────┐   ┌────┐   ┌──────┐
         │ 8s  │   │ 14s  │   │ 2s │   │ 8s │   │ 3s   │  ← 从 10s 优化为指数退避
         └─────┘   └──────┘   └────┘   └────┘   └──────┘
                                       总共: 35s

优化效果对比：
  | 阶段 | 优化前 | 优化后 | 优化方式 |
  |------|--------|--------|---------|
  | Detection | 8s | 8s | eBPF Ring Buffer → Anomaly Score |
  | Diagnosis | 14s | 14s | 拓扑 → 因果 → LLM 诊断 |
  | Risk Assessment | 2s | 2s | MCP 爆炸半径评估 |
  | Execution | 8s | 8s | MCP execute_remediation |
  | Verification | 10s | 3s(avg) | time.sleep(10) → 2s→3s→5s 指数退避 |
  | **Total MTTR** | **42s** | **35s** | **-17%** |
```

| 阶段 | 时间 | 做什么 |
|------|------|--------|
| Detection | 8s | eBPF Ring Buffer → Anomaly Score |
| Diagnosis | 14s | 拓扑 → 因果 → LLM 诊断 |
| Risk Assessment | 2s | MCP 爆炸半径评估 |
| Execution | 8s | K8s scale / config change |
| Verification | 10s | 重采样指标 + 对比 + 报告 |

### 9.3 恢复报告示例

```markdown
# AetherOps Recovery Verification Report

System:       JudgeX Online Judge (K3s)
Target Node:  `judgex-backend:8080`
Root Cause:   mysql-0:3306 — connection pool exhausted
MTTR:         42s

Remediation Action: SCALE_UP (2->4 replicas) + CONFIG_CHANGE (pool 20->50)

| Metric           | Before   | After    | Status       |
|------------------|----------|----------|--------------|
| Anomaly Score    | 72.50    | 8.30     | [OK] Resolved|
| P95 Latency (ms) | 3200.00  | 245.00   | [OK] Normal  |
| Queue Depth      | 47       | 2        | [OK] Draining|
| Error Rate       | 18.5%    | 0.3%     | [OK] Normal  |

MTTR Breakdown:
  Detection:      8s
  Diagnosis:      14s
  Risk Assessment: 2s
  Execution:      8s
  Verification:   10s
  -----------------------------------
  Total MTTR:     42s
```

### 9.4 面试回答

问："怎么确保修复真的生效了？只看延迟降下来够吗？"

答：不够。我们的恢复验证做了三件事：
1. **多指标对比**：不止看延迟，还看异常分数、错误率、队列深度——只恢复一个不代表问题解决了
2. **等待稳定窗口**：执行后等 10s 让指标稳定，避免瞬时抖动误判
3. **结构化报告**：Markdown 报告存到 RAG，下次类似故障可以对比——上次 SCALE_UP 有效，这次还选它

---

## 9.5 多轮诊断（Multi-Turn Diagnosis）

### 9.5.1 为什么需要多轮诊断？

单次 LLM 诊断的局限：LLM 只看当前因果图，缺少更多上下文。多轮诊断允许 LLM **主动请求更多数据**——就像人类 SRE 排查问题时会先看初步数据，然后说"再给我看一下 MySQL 的慢查询日志"。

### 9.5.2 多轮诊断流程

```
第 1 轮: LLM 收到因果图 + 拓扑 → 诊断结果
           │
           ├─ 置信度 ≥ 0.7 → 直接返回 ✅
           │
           └─ 置信度 < 0.7 → LLM 生成 tool_call 请求更多数据
                               │
                               ▼
                   第 2 轮: 附加数据 + 原始因果图
                              │
                              ├─ 置信度 ≥ 0.7 → 返回 ✅
                              │
                              └─ 置信度 < 0.7 + 还有轮次 → 继续
```

### 9.5.3 工具调用（LLM 可请求的数据）

LLM 在诊断过程中可以请求以下额外数据：

| 工具 | 返回 | 作用 |
|------|------|------|
| `get_metrics` | Prometheus 指标窗口 | 查看具体时间段的指标趋势 |
| `get_logs` | 服务日志摘要 | 从错误日志中找线索 |
| `get_config` | 服务配置快照 | 检查配置是否异常 |
| `get_dependencies` | 服务依赖拓扑 | 查看完整的调用链 |

### 9.5.4 核心实现

```python
def diagnose_multi_turn(causal_graph, anomaly_context,
                        max_turns=3, confidence_threshold=0.7):
    messages = [system_prompt, user_prompt(causal_graph, anomaly_context)]

    for turn in range(max_turns):
        response = llm_call(messages)
        result = parse_diagnosis(response)

        if result.confidence >= confidence_threshold:
            return result  # 置信度够了，提前结束

        # 低置信度 → LLM 可以请求更多数据
        tool_call = response.get("tool_calls", [])
        if tool_call:
            extra_data = execute_tool_call(tool_call[0])
            messages.append(assistant_msg(response))
            messages.append(tool_result_msg(extra_data))
        else:
            break  # LLM 没有请求数据但置信度低 → 返回当前结果

    return result
```

### 9.5.5 优化与迭代

| 版本 | 变更 | 原因 |
|------|------|------|
| 原版 | `max_turns=3` | 初始设计，给 LLM 充足轮次完善诊断 |
| 优化 v1 | `max_turns=2` | 实测 3→2 对首诊质量无显著影响，但节省 ~10s |
| 未来 | `max_turns=1` + 数据摘要 | 首轮传入所有可用数据 + 数据量统计，减少 LLM 请求额外数据的需要 |

### 9.5.6 面试要点

- **为什么是 3 轮？** 超过 3 轮后收益递减，且延迟线性增加
- **后面为什么改成了 2 轮？** 实测发现第一轮已包含全部数据（因果图 + 拓扑），LLM 很少需要额外数据。减少 1 轮节省约 10s
- **为什么置信度阈值是 0.7？** 比 Supervisor 的 0.6 更高，因为多轮后信息更多
- **不是每轮都重新诊断**：前一轮的推理保留在对话上下文中，LLM 在已有基础上深化

---

## 9.6 告警关联与去重（Alert Correlation）

### 9.6.1 问题

一个故障可能触发几十条告警——MySQL 挂了 → 后端延迟飙升 → 前端请求超时 → 网关 502。如果每条都跑一遍完整的诊断工作流，浪费资源且制造告警风暴。

### 9.6.2 三层关联

```
第 1 层: 时间窗口去重
  同一节点、同一类型 60 秒内的告警 → 合并
  ┌─ 抑制重复告警，减少噪音

第 2 层: 因果分组
  根据因果图将相关告警归组
  ┌─ "MySQL 慢查询" + "后端延迟高" + "前端超时" → 同一因果组

第 3 层: 风暴抑制
  1 秒内超过 20 条告警 → 标记为风暴 → 只处理第一条
  ┌─ 防止告警风暴拖垮系统
```

### 9.6.3 核心实现

```python
class AlertCorrelator:
    def feed(self, alert: AlertEvent) -> AlertEvent:
        if self._is_duplicate(alert):   # 第 1 层
            alert.is_deduped = True
            return alert

        group = self._find_or_create_group(alert)  # 第 2 层
        alert.group_id = group.id

        if self._is_storm(alert):       # 第 3 层
            alert.is_suppressed = True
            return alert

        return alert
```

### 9.6.4 面试要点

- **去重 vs 风暴抑制的区别**：去重是同一告警静默，风暴抑制是短时间内大量告警时只处理代表性的
- **因果分组**依赖 causal_graph——因果图越准确，分组越合理
- **分组报告**：`get_digest_report()` 输出 Markdown 摘要，减少 oncall 查看负担

---

## 9.7 反馈循环与审计（Feedback Loop）

### 9.7.1 为什么需要反馈？

自动修复最大的风险是误操作。反馈循环确保：
1. **所有决策都有记录**——出了问题能追溯
2. **高风险操作需要人工审批**——防止自动闯祸
3. **失败的操作自动回退**——及时止损
4. **持续改进**——从每次操作中学习

### 9.7.2 审批流程

```
LOW 风险
  └─ 自动执行 + 审计日志
     └─ 不打扰任何人

MEDIUM 风险
  └─ TEE 模式 → 通知 SRE → 60 秒内无拒绝则执行
     └─ SRE 可以选择 APPROVE / REJECT

HIGH 风险
  └─ PENDING → 等待人工审批
     └─ SRE 必须明确 APPROVE 才会执行
```

### 9.7.3 回退（Rollback）

```
执行自愈 → 恢复验证 → 验证失败？
                         │
                    ┌────┴────┐
                    ▼         ▼
                  是         否
                    │         │
            执行逆操作       完成
                    │
               SCALE_UP → SCALE_DOWN
               TC_DROP  → TC_REMOVE
               CONFIG_CHANGE → CONFIG_ROLLBACK
```

### 9.7.4 审计日志

每条审计记录包含：

| 字段 | 含义 | 示例 |
|------|------|------|
| `trace_id` | 唯一追踪 ID | `exec-001` |
| `agent` | 哪个 Agent | `remediation_executor` |
| `action` | 什么操作 | `SCALE_UP` |
| `risk_level` | 风险等级 | `LOW` |
| `decision` | 决策结果 | `auto_executed` |
| `duration_ms` | 耗时 | `5200` |

### 9.7.5 统计数据

```python
{
    "total": 50,
    "approval_rate": 0.87,       # 审批通过率
    "auto_executed": 35,          # 自动执行数
    "rejected": 5,               # 被拒绝数
    "rollback_count": 2,         # 回退次数
    "success_rate": 0.92,        # 成功率
    "avg_mttr": 42,              # 平均 MTTR (秒)
    "recent_rejections": [...]   # 最近的拒绝记录（用于分析）
}
```

### 9.7.6 面试要点

- **为什么要有 RollbackAssistant？** 自愈是有风险的——修复失败需要及时止损
- **逆操作映射**：SCALE_UP → SCALE_DOWN，TC_DROP → TC_REMOVE——不是所有操作都可逆（POD_RESTART 再次重启即可）
- **审计日志存 JSONL**：一行一个事件，方便日志收集系统（ELK/Loki）直接消费

---

## 9.8 Chaos Engineering（Chaos Mesh 集成）

### 9.8.1 为什么需要 Chaos？

自动化修复系统需要验证——如果系统从来没经历过故障，你怎么知道它能在故障时正确响应？Chaos Engineering 通过主动注入故障来验证 AetherOps 的诊断和修复能力。

### 9.8.2 故障注入类型

| 类型 | 枚举值 | 模拟什么 | AetherOps 预期响应 |
|------|--------|---------|-------------------|
| 网络延迟 | `NETWORK_DELAY` | 服务间延迟增加 | 检测到延迟异常 → 诊断根因 |
| Pod 删除 | `POD_KILL` | 服务实例崩溃 | 检测到调用失败 → 触发重启 |
| CPU 压力 | `CPU_STRESS` | 资源竞争 | 检测到延迟爬升 → SCALE_UP |
| 内存压力 | `MEMORY_STRESS` | 内存泄漏 | 检测到 OOM 风险 → POD_RESTART |
| 网络丢包 | `PACKET_LOSS` | 网络不稳定 | 检测到重传 → TC_DROP 熔断 |
| 服务下线 | `SERVICE_DOWN` | 依赖服务不可用 | 检测到调用全失败 → 跳过该服务 |

### 9.8.3 本地模拟 vs K8s 混沌

**本地模式（LocalChaosRunner）：**
```python
runner = LocalChaosRunner()
result = runner.run("mysql-connection-pool-exhaustion")
# 模拟故障 → 调用 LLM 诊断 → 评估修复 → 生成报告
```

**Kubernetes 模式（ChaosMeshGenerator）：**
```python
generator = ChaosMeshGenerator(namespace="judgex")
yaml = generator.generate(experiment)
# 输出可直接 kubectl apply 的 Chaos Mesh YAML
```

### 9.8.4 故障场景 ↔ Chaos 映射

```
scenarios.py 中的故障   →   Chaos 实验
mysql-connection-pool   →   NETWORK_DELAY + SERVICE_DOWN (MySQL)
redis-cache-avalanche   →   POD_KILL (Redis) + CPU_STRESS (backend)
network-congestion      →   PACKET_LOSS + NETWORK_DELAY
cpu-throttling          →   CPU_STRESS
memory-oom              →   MEMORY_STRESS
```

### 9.8.5 面试要点

- **Chaos 实验自动化验证**：注入故障 → AetherOps 自动诊断 → 验证诊断结果是否正确 → 清理 Chaos
- **安全护栏**：实验有超时（默认 120s）、自动回滚、有"暂停所有实验"全局开关
- **面试价值**：这展示了你在用 Netflix 的 Chaos Engineering 方法论验证 AI 系统的可靠性

---

## 9.9 Incident Benchmark（故障基准评测）

### 9.9.1 概述

30 个标注好的故障场景，覆盖 5 种故障模式 + 2 个边界用例。每次运行自动计算准确率、精确率、召回率、MTTR。

### 9.9.2 场景分布

| 模式 | 数量 | 场景举例 |
|------|------|---------|
| `slow_query` | 6 | MySQL 连接池耗尽、慢查询、MongoDB 聚合慢 |
| `cache_avalanche` | 5 | Redis 缓存雪崩、TTL 配置错误、CDN 缓存未命中 |
| `network_congestion` | 5 | 跨可用区网络拥塞、DDoS 流量攻击、DNS 解析失败 |
| `resource_exhaustion` | 7 | CPU 节流、OOM、磁盘写满、goroutine 泄漏 |
| `hot_spot` | 5 | 分片热点、N+1 查询、部署回归、限流过激 |
| `edge_cases` | 2 | 误报（实际无故障）、多故障同时发生 |

### 9.9.3 评测流程

```
每个场景：
  1. 构造 anomaly_event + topology + metrics_mock
  2. 调用诊断工作流（或启发式回退）
  3. 对比预测结果 vs ground_truth
  4. 记录正确/错误 + 置信度 + 耗时

最终报告：
  - 总体准确率
  - 按模式的准确率分布
  - 失败场景列表
```

### 9.9.4 运行方式

```bash
# 快速评测（启发式，无需 LLM）
python -m aetherops.benchmark.run

# 完整评测（需要 LLM_API_KEY）
export LLM_API_KEY=sk-xxx
python -m aetherops.benchmark.run --verbose

# 单模式评测
python -m aetherops.benchmark.run --pattern cache_avalanche

# 保存报告
python -m aetherops.benchmark.run --save benchmark_results
```

### 9.9.5 评测报告示例

```
============================================================
  AetherOps Benchmark Report
============================================================

  Total scenarios:    30
  Root cause accuracy: 86.7%
  Action accuracy:     80.0%
  Average confidence:  0.76
  Average MTTR:        42s

  BY PATTERN
  Pattern               Total   RC Accuracy  Action Acc
  slow_query                 6       83.3%       83.3%
  cache_avalanche            5       80.0%       80.0%
  network_congestion         5       80.0%       60.0%
  resource_exhaustion        7       85.7%       85.7%
  hot_spot                   5       80.0%       80.0%
```

### 9.9.6 面试要点

- **为什么启发式只有 46.7%？** 因为启发式只看因果图出度最大的节点，对数据库慢查询和缓存完全无知——这恰恰说明 LLM 的价值
- **30 个场景的设计原则**：覆盖 5 个故障模式 × 每个模式 5-7 个变体 + 边界情况
- **评测 → 改进的闭环**：发现有场景失败 → 分析原因 → 改进 Prompt 或算法 → 重新评测

---

## 9.10 Web Dashboard（Streamlit）

### 9.10.1 概述

Streamlit 可视化仪表盘，展示架构图、工作流追踪、MTTR 报告、基准评测结果、告警关联、反馈统计。主要用于 **Demo 演示** 和 **面试展示**。

### 9.10.2 页面

| 页面 | 内容 |
|------|------|
| Architecture Overview | 系统架构图（Graphviz）、通信流程、MCP 工具列表 |
| Agent Workflow Trace | Supervisor 路由追踪表、状态转换图 |
| MTTR Recovery Report | 恢复报告、MTTR 趋势图 |
| Benchmark Results | 30 场景准确率、按模式分解、失败分析 |
| Alert Correlation | 模拟告警流、因果分组展示 |
| Feedback Statistics | 审批通过率、成功率、拒绝分析 |
| Run Benchmark | 一键运行基准评测 |

### 9.10.3 启动

```bash
streamlit run aetherops/dashboard.py
```

### 9.10.4 面试价值

- 面试时直接打开浏览器展示：5 分钟讲清楚整个系统的全貌
- 展示"可观测性"思维——系统不仅要工作，还要能被看到在怎么工作

---

## 10. JudgeX 集成

### 10.1 JudgeX 是什么

JudgeX 是一个**在线判题系统**（Online Judge），类似 LeetCode 但部署在自己的服务器上。

- 部署位置：`150.158.113.146:8080` / `https://joyan.site`
- 技术栈：Go（Gin）+ Vue 3 + K3s（Kubernetes）
- 核心功能：代码提交 → 沙箱评测 → 结果返回
- 沙箱：cgroup v2 + chroot + seccomp-BPF（不是 Docker）

### 10.2 JudgeX 服务拓扑

```
nginx (入口)
  │
  └── backend (Gin API, :8080)
        ├── MySQL (:3306)
        ├── Redis (:6379)
        ├── NSQ (消息队列, :4150)
        └── judge-worker → sandbox (cgroup + seccomp)
```

### 10.3 Prometheus 指标

JudgeX 暴露的指标（`/metrics`）：

```
judgex_submissions_total        # 总提交数
judgex_api_requests_total       # API 请求总数 (当前 60 万+)
judgex_queue_depth              # 评测队列深度
judgex_active_judgements        # 正在评测数
judgex_uptime_seconds           # 运行时间 (当前 23 天+)
```

### 10.4 AetherOps 怎么监控 JudgeX

```
                   JudgeX 服务器 (150.158.113.146)
                  ┌────────────────────────────┐
                  │  backend:8080              │
                  │  Prometheus /metrics        │
                  │  HTTP /health, /ready       │
                  └──────────┬─────────────────┘
                             │
              ┌──────────────┴──────────────┐
              │ HTTP (健康检查 + 指标拉取)     │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │    AetherOps (本地/云端)      │
              │                              │
              │  1. 健康检查: 服务是否活着     │
              │  2. 指标采集: Prometheus 数据  │
              │  3. 拓扑分析: 服务依赖关系      │
              │  4. 根因诊断: 哪个服务出问题    │
              │  5. 自愈评估: 怎么修最安全      │
              └──────────────────────────────┘
```

---

## 11. 如何测试

### 11.1 测试文件

- 集成测试：`oj/tests/aetherops_judgex_test.py`
- MCP 客户端验证：`aetherops/core/mcp_client.py`（可直接运行验证连接）

6 个测试步骤：

| 步骤 | 测试内容 | Live 模式 | Demo 模式 |
|------|----------|-----------|-----------|
| 1 | JudgeX 服务器健康检查 | 连真实服务器 | 模拟通过 |
| 2 | AetherOps MCP 连接 | 连本地 :50052 | 自动降级 |
| 3 | 拓扑快照 | MCP get_topology | 显示模拟拓扑 |
| 4 | 爆炸半径评估 | MCP evaluate_remediation | 显示模拟评估 |
| 5 | Supervisor 多 Agent 工作流 | 路由追踪 + 执行 | 路由追踪 |
| 6 | MTTR 恢复报告 | 生成报告 | 生成报告 |

### 11.2 测试环境要求

```
Demo 模式（推荐先跑这个）：
  - 任何机器（Windows/Mac/Linux 都可以）
  - Python 3.10+
  - 不需要任何外部依赖
  - 不需要 Go 后端

Live 模式：
  - 需要本地有 MCP 服务器（Go eBPF tracer 在 :50052）
  - 或者有 JudgeX 服务器的网络访问
  - 可选: LLM_API_KEY（DeepSeek V4 Flash）
```

### 11.3 运行测试

```bash
# 1. Demo 模式（不需要任何环境）
python aetherops_judgex_test.py

# 2. Live 模式（需要连接 Go MCP 服务器）
python aetherops_judgex_test.py --live

# 3. 指定 MCP 地址（本地或通过 SSH 隧道）
python aetherops_judgex_test.py --mcp http://localhost:50052

# 4. 指定目标和操作
python aetherops_judgex_test.py --target judgex-backend:8080 --action SCALE_UP
```

**MCP 客户端直连验证**（快速检查 Go 数据面是否运行）：

```bash
cd aetherops
# 安装依赖后，通过简单的 Python 脚本验证连接
python3 -c "
import asyncio
from aetherops.core.mcp_client import MCPClient
async def test():
    c = MCPClient('http://localhost:50052')
    await c.connect()
    print('Tools:', [t['name'] for t in c.list_discovered_tools()])
    topo = await c.get_topology(include_healthy=True)
    print(f'Topology: {topo.node_count} nodes, {topo.edge_count} edges')
asyncio.run(test())
"
```

**SSH 隧道方式**（Go 数据面在远程服务器）：

```bash
# 建立隧道（远程服务器的 MCP 端口转发到本地）
ssh -L 50052:localhost:50052 user@remote-server

# 另一个终端运行测试
python aetherops_judgex_test.py --live
```

### 11.4 预期输出

```bash
# Demo 模式输出概要
Pass: 3  |  Fail: 0  |  Skip: 6  |  Total: 9
All tests passed.

# Live 模式输出概要（JudgeX 在线）
Pass: 7  |  Fail: 0  |  Skip: 5  |  Total: 12
All tests passed.
```

### 11.5 运行 Demo 脚本

```bash
# 3 分钟演示脚本
cd /home/sly/Downloads/xm/ebpf-autoheal
python -m aetherops.demo
```

Demo 脚本会展示：
1. 架构概览
2. 故障注入模拟
3. MCP 工具调用
4. Supervisor 路由追踪
5. 恢复验证 + MTTR 报告

### 11.6 可能遇到的问题

| 问题 | 原因 | 解决 |
|------|------|------|
| `No module named 'aetherops'` | Python 找不到模块 | 确保运行目录正确或设置 PYTHONPATH |
| `Connection refused` | MCP 服务器未运行 | Demo 模式不需要，会自动降级 |
| `No module named 'aetherops'` | Python 找不到模块 | 确保在项目根目录运行或 `pip install -e aetherops/` |
| `'gbk' codec can't encode` | Windows 终端编码 | 已处理：所有非 ASCII 字符已替换为 ASCII |
| `LLM_API_KEY not set` | 未配置 DeepSeek | 自动走启发式回退，不影响测试 |
| `nil map panic in tracer` | mitCooldowns map 未初始化 | 修复：`var mitCooldowns = make(map[string]time.Time)`（已在最新代码中修复） |
| `MCP connection refused` | 连接远程服务器失败 | 使用 SSH 隧道 `ssh -L 50052:localhost:50052 user@host` |

---

## 12. 面试深挖 30 题

### 12.1 整体架构

**Q1: 为什么要分成 Go 和 Python 两个子系统？**

A：职责分离。Go 处理实时数据（毫秒级响应），Python 处理复杂分析（秒到分钟级）。Go 是"反射神经"——快速响应但不做深度思考；Python 是"大脑皮层"——深度分析但不要求实时。**关键设计**：Go 端可以独立运行，Python 挂了不影响内核级自愈。

**Q2: 两个子系统怎么通信？为什么不用 REST API？**

A：用 MCP 协议（JSON-RPC 2.0 over HTTP SSE）。REST 的问题：工具调用不是 CRUD 操作，不适合用 GET/POST/PUT 语义。REST 需要为每个工具定义 URL 和请求体结构，客户端必须预知服务端的能力。MCP 的 `tools/list` 让客户端动态发现服务端能力——服务端加一个新工具，客户端不用改代码就能用。

**Q3: MCP 和 gRPC 比有什么优缺点？**

A：MCP 的优势：JSON 人类可读、不需要 proto 编译、SSE 原生推送、工具自发现。劣势：JSON 序列化比 Protobuf 慢、没有强类型约束、没有 gRPC 的负载均衡和双向流。所以项目中保留了两套方案：默认 MCP，环境变量 `AETHEROPS_TRANSPORT=grpc` 可回退。

### 12.2 Supervisor 架构

**Q4: Supervisor 的路由逻辑是什么样的？为什么这么设计？**

A：状态驱动态路由：检查状态中缺少什么就路由到对应的 Agent。顺序是拓扑→因果→诊断→(低置信度重分析)→风险→自愈→完成。这么设计而不是固定流水线的原因是：一个工作流实例可能被中断后恢复，已有的数据不需要重新获取。低置信度时自动循环重分析，流水线模式做不到。

**Q5: 低置信度重分析的阈值为什么是 0.6？**

A：没有特别严格的数学推导，是基于经验的选择。0.6 意味着"60% 以上把握"。启发式回退的置信度固定为 0.4，所以一定小于 0.6 触发重分析。LLM 诊断通常在 0.7-0.9 之间，不会误触发。可以调优——如果有历史数据，可以用 ROC 曲线找到最优阈值。

**Q6: 5 个 Agent 可以并行运行吗？**

A：目前是串行的，因为每个 Agent 依赖前一个的输出（拓扑→因果→诊断→风险→自愈）。但像 Topology Analyst 和 Causal Analyst 的 Prometheus 指标拉取是独立的，可以并行。这可以通过 Workflow 的 DAG 分支节点实现——如果有人问"怎么优化"，可以说改成 DAG（有向无环图）执行，独立的分支并行。

### 12.3 因果发现

**Q7: 解释一下因果发现，和关联分析有什么区别？**

A：关联分析只回答"A 和 B 是否一起变化"，因果发现回答"A 是不是 B 的原因"。例子：发现 MySQL 延迟高、Redis 延迟高、后端延迟高三者相关——关联分析只能看到它们都异常。因果发现通过条件独立测试和时间信息，能判断出"后端调用 MySQL → MySQL 连接池耗尽 → 等待队列变长 → 后端延迟上升"，而 Redis 是被牵连的。

用生活中的例子：**关联 ≈ 同时打喷嚏的两个人；因果 ≈ 一个人传染给另一个人。**

**Q8: LPCMCI 算法是怎么工作的？**

A：三步走：
1. **PC 阶段**：从全连接图开始，对每对变量做条件独立测试，控制第三个变量后相关性消失就删边
2. **时间信息**：利用时间序列顺序，`X(t-1)→Y(t)` 比 `X(t)→Y(t)` 更可能是因果关系
3. **隐变量处理**：一些因素我们测不到（如网络抖动），LPCMCI 会标记为"可能隐含变量"

**Q9: 因果图怎么验证正确性？**

A：两种方式。离线验证：用历史故障数据标注根因，对比因果发现的结论。在线验证：看基于因果图的修复是否有效——如果因果图说"MySQL 是根因"，我们修 MySQL 后问题解决，那这个因果推断就是对的。

### 12.4 LLM 诊断

**Q10: 为什么用 DeepSeek V4 Flash 而不是 GPT-4？**

A：三个原因：成本（DeepSeek V4 Flash 便宜得多）、速度（Flash 系列更快）、中文能力（DeepSeek 的中文推理质量不输 GPT-4）。而且它兼容 OpenAI 的 API 格式，迁移成本为零——换 GPT-4 只需要改 base_url 和 model 名。

**Q11: LLM 不可用时怎么办？**

A：自动退化到启发式诊断。启发式算法统计因果图中每个节点的出度（影响的下游服务数），出度最大的就是根因。但这个方法的置信度只有 0.4（低于重分析阈值 0.6），所以 Supervisor 会尝试重分析。**这是一个"优雅退化"的设计**——LLM 在时用智慧，不在时用算法。

**Q12: 故障模式库是怎么维护的？可以扩展吗？**

A：故障模式库定义在 `llm_diagnosis.py` 的 `DIAGNOSIS_SYSTEM_PROMPT` 中。当前 5 种模式涵盖了数据库、缓存、网络、资源、算法五大类。扩展只需要在 Prompt 里加一个 Pattern 6 条目，不需要改代码。另外，每次诊断结果都存到 Milvus（RAG 知识库），后续可以做到自动识别新模式。

**Q13: 怎么防止 LLM 胡编乱造（幻觉）？**

A：三层防护：
1. **操作枚举受限**：LLM 只能从 5 种预设操作中选择（TC_DROP、POD_RESTART 等），不能自由发挥
2. **置信度阈值**：低于 0.6 的结论会被 Supervisor 拒绝，触发重分析
3. **恢复验证**：任何操作执行后都做 before/after 对比，修复没生效则告警

### 12.5 eBPF 数据平面

**Q14: eBPF 为什么安全？和内核模块比呢？**

A：内核模块有问题会让整个系统崩溃。eBPF 有内核验证器：检查有界循环、检查指针边界、限制指令数量（100 万条）。一个 eBPF 程序最多导致内核返回错误，不会导致内核 panic。

**Q15: 字节序问题怎么处理的？**

A：eBPF 读取的 IP 是网络字节序（大端），Go 端用 `binary.LittleEndian` 读取 Ring Buffer。如果不匹配，`192.168.49.2` 会显示为 `2.49.168.192`。这是 eBPF 开发中的经典坑。

**Q16: 自适应阈值是怎么做的？**

A：每条边维护一个滑动窗口（最近 30 个数据点），计算 P95。阈值 = `max(P95 × 1.2, 10ms)`。好处是：Redis 的正常延迟是 1ms，阈值自动设为 10ms（下限）；外部 API 的正常延迟是 200ms，阈值自动设为 240ms。不会出现固定阈值"打死快的，放过慢的"的问题。

### 12.6 恢复验证

**Q17: MTTR 的每一段时间是怎么计算的？**

A：所有时间节点都记录在 workflow state 中：
- `anomaly_detected_at`：Go 端发出异常事件的时间
- 每个 Agent 执行前后记录时间戳
- Verification 完成后计算最终 MTTR = 当前时间 - anomaly_detected_at

**Q18: 怎么判断修复成功了？只靠异常分数降低够吗？**

A：不够，看三个维度：
1. **异常分数**：降低 > 50% 才算有效
2. **多指标对比**：延迟、错误率、队列深度都要恢复正常
3. **持续观察**：恢复验证不是说"这一刻正常了就完了"，而是会持续监控一段时间

**Q19: 恢复报告为什么要存到 RAG？**

A：三个价值：1）下次类似故障可以检索历史，直接问"上次怎么修的"；2）模式识别——如果同一个服务反复出同一种故障，说明需要根本性修复而非临时自愈；3）趋势分析——MTTR 趋势是否在改善。

### 12.7 JudgeX 集成

**Q20: 为什么选 JudgeX 作为集成对象？**

A：JudgeX 是一个真实部署在生产环境的在线判题系统，有完整的微服务架构（Go 后端、MySQL、Redis、消息队列、Worker）。用它做集成比用 mock 服务更有说服力：有真实的 Prometheus 指标（60 万+ API 请求）、有真实的健康检查端点。

**Q21: JudgeX 的沙箱是什么原理？】

A：JudgeX 使用的是 cgroup v2 + chroot + seccomp-BPF 的组合，不是 Docker。这比 Docker 更轻量：启动不需要拉镜像、资源限制更细粒度、安全策略用 seccomp-BPF 而非容器隔离。

### 12.8 工程实践

**Q22: 工作流引擎在这个项目中扮演什么角色？**

A：我们曾使用 LangGraph 构建有状态、多 Agent 工作流，但后来替换为约 50 行的纯 Python `Workflow` 类。它负责：
1. **状态管理**：workflow state 在各个 Agent 之间传递
2. **节点编排**：定义 Supervisor 和 5 个 Agent 作为图节点
3. **条件路由**：Supervisor 根据状态内容决定下一个节点
4. **循环支持**：低置信度回退需要工作流能回到之前的节点

**为什么替换 LangGraph？** 实际使用量极其有限——仅 ~13 行框架调用，却引入了 ~50MB 的依赖树。所有 Agent 节点都是纯 `dict → dict` 函数，不依赖 LangGraph 任何特性（无 checkpointing、无 streaming、无并行）。纯 Python `Workflow` 类同样清晰可维护，且零额外依赖。

**Q23: 这个项目怎么保证不误操作？**

A：三层防护：
1. **操作前**：Risk Assessor 评估爆炸半径，HIGH 风险的操作不自动执行
2. **操作中**：受保护 IP 白名单（不丢包 localhost/K8s API server）
3. **操作后**：恢复验证确认效果，修复失败自动告警

**Q24: 如果持续收到大量告警怎么办？**

A：两个机制。1）冷却期：同一节点 120 秒内不重复自愈。2）告警去重：60 秒滑动窗口，同类型告警合并。

**Q25: 这个项目可以部署在生产环境吗？**

A：Go 数据平面可以——DaemonSet 部署、hostNetwork/hostPID、有自监控和健康检查。Python 认知平面目前是"辅助决策"角色——建议先作为建议系统运行，等积累足够信心后再启用自动执行模式。

### 12.9 开放性/设计题

**Q26: 如果要加一个 History Pattern Matcher Agent，怎么设计？**

A：位置加在 Risk Assessor 后面。从 Milvus 检索近 30 天的故障记录，用 Jaccard 相似度匹配当前故障的异常模式。如果匹配到高相似度历史（>0.6）→ 直接复用上次的操作和结果。不需要重新跑 LLM 诊断 -> Risk Assessor -> Remediation 的完整流程。

**Q27: 如果 JudgeX 有 1000 个微服务，当前的架构还能工作吗？**

A：Go 数据平面面临的主要问题是"标签基数爆炸"——1000 个服务理论上 N² = 100 万条边。目前通过 Prometheus 原生标签机制控制，后续可加采样或聚合降低基数。对于 Python 侧，因果发现的计算复杂度是 O(N²)，1000 个服务会导致计算时间过长。优化方向：先做拓扑剪枝，只分析有异常的边。或者分层分析——先分析服务组（namespace），定位到组再分析组内。

**Q28: Supervisor 单点故障怎么解决？**

A：Supervisor 本身是无状态的——路由决策只依赖 state 内容。多副本部署即可：K8s Deployment 多副本 + 分布式锁（Redis/Etcd）确保同一时间只有一个 Supervisr 在处理同一个异常事件。

**Q29: 这个项目和在用监控系统（Prometheus/Grafana）的关系是什么？**

A：互补关系，不是替代关系。Prometheus 提供指标存储和告警规则，Grafana 提供可视化。AetherOps 提供的是"诊断和自愈"能力。如果一个服务延迟升高了，Prometheus 告警说"出事了"，Grafana 展示"哪里出事了"，AetherOps 回答"为什么会出事 + 怎么修"。

**Q30: 这个项目最大的技术挑战是什么？**

A：Go 这边的 eBPF 开发最坑的三个问题（IPv6 双栈导致 IP 全 0、字节序颠倒、Go ABI 寄存器不同）和 Python 这边的"怎么让 LLM 的结论可信任"（操作枚举 + 置信度阈值 + 恢复验证）。两者解决思路一致：**不要信任单一信号源，多渠道交叉验证。**

---

## 13. 文件清单速查

### 核心文件速查表

| 文件 | 50 字一句话总结 |
|------|---------------|
| `bpf/net_trace.c` | eBPF C 代码，挂载 `tcp_sendmsg`，捕获四元组+延迟→Ring Buffer |
| `cmd/tracer/main.go` | 入口: 组装 App → Start → RunMainLoop → Shutdown（30 行） |
| `internal/graph/graph.go` | 服务拓扑图，EMA 基线，P95 滑动窗口，Prometheus 更新 |
| `internal/analysis/analysis.go` | 异常评分 + 反向随机游走 + 故障聚类 + 历史匹配 |
| `internal/mitigation/mitigation.go` | TC 丢包 → K8s 重启 → 火焰图 → 飞书通知 |
| `internal/mcp/server.go` | MCP 服务器（JSON-RPC 2.0 over SSE），暴露工具 + 推送事件 |
| `internal/policy/engine.go` | OPA 风格策略引擎，自愈动作的安全防护 |
| `internal/blastradius/radius.go` | 爆炸半径评估 + 分级自愈执行 |
| `internal/grpc/server.go` | gRPC 服务（拓扑查询 + 异常事件流） |
| `aetherops/core/mcp_client.py` | MCP 客户端，调用 Go 端的 topology/remediation 工具 |
| `aetherops/core/llm_diagnosis.py` | LLM 诊断（5 种故障模式），回退到启发式算法 |
| `aetherops/core/multi_turn_diagnosis.py` | 多轮诊断：LLM 可请求更多数据，2 轮内提升置信度（从 3 轮优化） |
| `aetherops/core/causal_inference.py` | LPCMCI 因果发现算法，支持 MAX_CAUSAL_VARS 稀疏化（O(N²) → O(50²)) |
| `aetherops/core/alert_correlation.py` | 三层告警关联：去重→因果分组→风暴抑制 |
| `aetherops/core/feedback.py` | 反馈循环：审计日志、审批流程、RollbackAssistant |
| `aetherops/core/metrics_fetcher.py` | Prometheus 指标采集 |
| `aetherops/core/risk_client.py` | 风险评估客户端（MCP/gRPC 双通道） |
| `aetherops/workflows/workflow.py` | Supervisor + 5 Agent 工作流，状态驱动路由 |
| `aetherops/benchmark/scenarios.py` | 30 个标注故障场景，覆盖 5 种模式 + 边界 |
| `aetherops/benchmark/evaluator.py` | 评测引擎：跑场景 + 算准确率 + 生成报告 |
| `aetherops/benchmark/run.py` | 命令行入口：支持 --pattern / --verbose / --save |
| `aetherops/chaos/engine.py` | Chaos Engine：6 种故障注入，本地模拟 + K8s YAML |
| `aetherops/dashboard.py` | Streamlit 仪表盘：7 页 Demo + 可视化 |
| `aetherops/demo.py` | 3 分钟演示脚本，展示完整闭环 |
| `aetherops/rag/retriever.py` | RAG 检索器，从 Milvus 查询相似历史故障 |
| `aetherops/rag/store.py` | Milvus 向量存储管理 |
| `aetherops/dspy/optimizer.py` | DSPy Prompt 优化 |
| `oj/tests/aetherops_judgex_test.py` | 6 步集成测试，支持 live/demo 双模式 |

### 面试前快速复习

```
┌──────────────────────────────────────────────────────────┐
│                   快速复习（5 分钟）                        │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  两套系统：Go 数据平面 (eBPF) + Python 认知平面 (AetherOps)  │
│                                                           │
│  通信方式：MCP 协议（JSON-RPC 2.0 over HTTP SSE）           │
│                                                           │
│  认知架构：Supervisor 状态驱动 → 5 个 Expert Agents        │
│                                                           │
│  核心算法：PageRank 变体反向随机游走 + LPCMCI 因果发现       │
│                                                           │
│  分级自愈：LOW (自动) → MEDIUM (TEE) → HIGH (需人工审批)    │
│                                                           │
│  恢复验证：Before/After 对比 → 多指标确认 → MTTR 报告 → RAG │
│                                                           │
│  LLM 诊断：5 种故障模式 + 多轮诊断(3轮) + 启发式回退         │
│                                                           │
│  新增模块：告警关联(三层) / 反馈循环(审计+回退) / Chaos 注入 │
│                                                           │
│  基准评测：30 故障场景，LLM 准确率 86.7%，启发式 46.7%      │
│                                                           │
│  Web 仪表盘：streamlit run aetherops/dashboard.py          │
│                                                           │
│  测试命令：python aetherops_judgex_test.py [--live]        │
│                                                           │
└──────────────────────────────────────────────────────────┘
```
