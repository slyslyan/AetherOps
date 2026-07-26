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

### Go 目录结构

```
cmd/tracer/          应用入口（app.go, loop.go, collector.go）
internal/
  config/            配置加载（env → Config struct）
  detection/         根因分析（latRatio = max(sendmsgLatRatio, rttLatRatio) + 反向随机游走 + 故障聚类）
  errors/            错误哨兵（ErrEBPFLoad, ErrKprobeAttach 等）
  graph/             服务拓扑图（ServiceGraph + ServiceEdge，含独立 RTT 统计 RttP95/RttBaselineP95）
  mcp/               MCP JSON-RPC over HTTP SSE 服务
  metrics/           Prometheus 指标（agent_events, agent_errors）
  remediation/       自愈执行（mitigation）+ 策略引擎（policy）+ 爆炸半径评估（blastradius）
  resolver/          服务名解析（PID → 进程名）
bpf/                 eBPF C 程序（net_trace.c, tcp_conntrack.c, tcp_rtt.c, tc_drop.c, http_probe.c）
proto/               Protobuf 定义（aetherops.proto → gen/）
```

### Python 目录结构

```
python/
  src/aetherops/
    core/            MCP 客户端 + LLM Provider + LLM 诊断 + 风险评估 + 告警关联 + 反馈
    workflows/       Multi-Agent 工作流（Planner → Supervisor → 5 Expert Agents）
  tests/             测试（pytest + asyncio）
  scripts/demo.py    面试演示脚本
  pyproject.toml     Poetry 项目配置（src-layout）
  Dockerfile         Python 认知平面容器镜像
```

### 部署配置

```
docker/              Go tracer Dockerfiles（Dockerfile.agent, Dockerfile.local）
deploy/              K8s manifests + Helm chart + 安装脚本
config/              Prometheus + Grafana 监控配置
docker-compose.aetherops.yml  一键启动认知平面 + Prometheus + Grafana
```

## 已删除模块（面试不展开，不要重建）

以下模块已在简化中删除：benchmark/、causal_inference.py、multi_turn_diagnosis.py、metrics_fetcher.py、hooks.py、agent_observability.py、incident_memory.py

## 核心接口（必须保持兼容）

- `workflows.workflow.build_workflow()` → Workflow
- `workflows.workflow.run_workflow(workflow, state)` → dict
- `core.llm_provider.ProviderFactory.from_env()` → LLMProvider
- `core.mcp_client.MCPClient` — MCP 客户端
- `remediation.PolicyChecker.CheckBeforeMitigation(suspect graph.Suspicion) bool` — 单嫌疑节点接口（非切片）

## eBPF 探针架构

| 探针 | C 文件 | Hook 点 | 测量内容 | 适用场景 |
|---|---|---|---|---|
| tracer | `bpf/net_trace.c` | kprobe/kretprobe tcp_sendmsg | 内核缓冲拷贝时间（~µs） | 通用流量拓扑发现 |
| tcp_conntrack | `bpf/tcp_conntrack.c` | kprobe tcp_connect + tcp_close | 连接生命周期 RTT（~ms） | 短连接 RTT 检测，tc netem 等网络级故障 |
| tcp_rtt | `bpf/tcp_rtt.c` | kprobe tcp_sendmsg + kretprobe tcp_recvmsg | 请求级往返延迟（~ms） | **长连接池**（MySQL, Redis, PgSQL）请求级 RTT |
| tc_drop | `bpf/tc_drop.c` | TC clsact | 丢包 | 自愈熔断 |
| http_probe | `bpf/http_probe.c` | uprobe HTTP handler | HTTP 请求耗时 | HTTP 服务细分 |

关键设计：
- `tcp_rtt.c` 用 `sk_ptr`（socket 指针）做 key，正确配对同一 socket 的 send/recv
- `tcp_rtt.c` 和 `tcp_conntrack.c` 各有独立 ringbuf，互不干扰
- RTT > 30s 的事件被丢弃（空闲 keep-alive 非真实请求）
- `tcp_sendmsg` 测量的是内核缓冲拷贝时间（~µs），**不受网络延迟影响**；网络级故障检测依赖 `tcp_conntrack`（连接级）和 `tcp_rtt`（请求级）作为 RTT 数据源

## 异常检测阈值

- `ServiceEdge.BaselineP95`：EMA 平滑的稳定基线，仅在非异常窗口更新
- `RttBaselineP95`：独立 RTT 基线，与 sendmsg BaselineP95 分离统计，不受 µs 级样本稀释
- gating 逻辑：`windowP95 < BaselineP95 * 2.0` 时才纳入基线（防止双峰分布抬高阈值）
- `latRatio = max(sendmsgLatRatio, rttLatRatio)` — RTT 信号强于 sendmsg 时自动切换数据源

## 自愈策略链

- `PerformMitigation` 按嫌疑分数降序遍历 `[]Suspicion`
- 遇到被策略拒绝的节点 → `continue` 尝试下一个
- 成功执行一个 → `return`
- 全部被拒 → 仅发告警，不执行
