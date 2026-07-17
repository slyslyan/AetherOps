# CLAUDE.md - ebpfagent 项目约定

## 交流语言

- 始终使用中文回复用户

## Git 提交

- 不要在任何 git commit 消息中添加 `Co-Authored-By` 行

## 项目架构（已简化）

核心叙事：**eBPF 采集 → AI Multi-Agent 分析 → K8s 自愈**

```
Go 数据面: eBPF kprobe → Ring Buffer → ServiceGraph → 异常检测 → MCP Server
Python 认知面: MCP Client → Supervisor → 5 Expert Agents → LLM Diagnosis → 分级自愈 + 恢复验证
```

## 已删除模块（面试不展开，不要重建）

以下模块已在简化中删除：chaos/、benchmark/、causal_inference.py、multi_turn_diagnosis.py、metrics_fetcher.py、hooks.py、agent_observability.py、incident_memory.py

## 核心接口（必须保持兼容）

- `workflows.workflow.build_workflow()` → Workflow
- `workflows.workflow.run_workflow(workflow, state)` → dict
- `core.llm_provider.ProviderFactory.from_env()` → LLMProvider
- `core.mcp_client.MCPClient` — MCP 客户端
- `mitigation.PolicyChecker.CheckBeforeMitigation(suspect graph.Suspicion) bool` — 单嫌疑节点接口（非切片）

## eBPF 探针架构

| 探针 | C 文件 | Hook 点 | 测量内容 | 适用场景 |
|---|---|---|---|---|
| tracer | `bpf/net_trace.c` | kprobe/kretprobe tcp_sendmsg | 内核缓冲拷贝时间（~µs） | 通用流量拓扑发现 |
| tcp_conntrack | `bpf/tcp_conntrack.c` | kprobe tcp_connect + tcp_close | 连接生命周期 RTT | 短连接（HTTP/1.0, DNS） |
| tcp_rtt | `bpf/tcp_rtt.c` | kprobe tcp_sendmsg + kretprobe tcp_recvmsg | 请求级往返延迟 | **长连接池**（MySQL, Redis, PgSQL） |
| tc_drop | `bpf/tc_drop.c` | TC clsact | 丢包 | 自愈熔断 |
| http_probe | `bpf/http_probe.c` | uprobe HTTP handler | HTTP 请求耗时 | HTTP 服务细分 |

关键设计：
- `tcp_rtt.c` 用 `sk_ptr`（socket 指针）做 key，正确配对同一 socket 的 send/recv
- `tcp_rtt.c` 和 `tcp_conntrack.c` 各有独立 ringbuf，互不干扰
- RTT > 30s 的事件被丢弃（空闲 keep-alive 非真实请求）

## 异常检测阈值

- `ServiceEdge.BaselineP95`：EMA 平滑的稳定基线，仅在非异常窗口更新
- gating 逻辑：`windowP95 < BaselineP95 * 2.0` 时才纳入基线（防止双峰分布抬高阈值）
- 分析时用 `BaselineP95 * P95Multiplier` 而非原始 `P95` 计算阈值

## 自愈策略链

- `PerformMitigation` 按嫌疑分数降序遍历 `[]Suspicion`
- 遇到被策略拒绝的节点 → `continue` 尝试下一个
- 成功执行一个 → `return`
- 全部被拒 → 仅发告警，不执行
