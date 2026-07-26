# AetherOps 面试深度讲解

本文档围绕 AetherOps（ebpfagent）项目的五大核心能力展开，每节包含基础问题、追问及答案，用于面试深度复盘。

---

## 1. 数据感知（eBPF 内核探针）

### 核心叙事

> 开发 8 个内核探针（kprobe/uprobe/TC），以零代码侵入、极低开销采集 TCP 流量与请求延迟，精确定位 Redis 及长连接池的内核级网络延迟，大幅压缩链路诊断盲区。

### 探针全景

| # | 探针 | Hook 点 | 测量内容 | 数据用途 |
|---|------|---------|----------|---------|
| 1 | `net_trace.c` | kprobe/kretprobe `tcp_sendmsg` | 内核缓冲拷贝时间（~µs） | 流量拓扑发现、基础延迟统计 |
| 2 | `tcp_conntrack.c` | kprobe `tcp_connect` + `tcp_close` | 连接生命周期 RTT（~ms） | 短连接延迟、网络级故障检测 |
| 3 | `tcp_rtt.c` | kprobe `tcp_sendmsg` + kretprobe `tcp_recvmsg` | 请求级往返延迟（~ms） | 长连接池（MySQL/Redis/PgSQL）RTT |
| 4 | `tc_drop.c` | TC clsact egress | 内核级丢包 | 自愈熔断执行 |
| 5 | `http_probe.c` | uprobe Go HTTP/gRPC handler | HTTP 状态码 + 耗时 | L7 异常诊断（按需挂载） |
| 6 | `redis_trace.c` | kprobe `tcp_sendmsg` (6379) | Redis 命令名 | Redis 协议发现 |
| 7 | `proto_classifier.c` | kprobe `tcp_sendmsg` | 协议类型自动识别 | 服务端口 → 协议映射 |
| 8 | `trace_context.c` | kprobe `tcp_sendmsg` | W3C/Jaeger/Datadog TraceID | 指标→拓扑→Trace 三位一体 |

### 基础问题

**Q1: 8 个探针如何做到"零代码侵入"？**

答：所有探针挂载在内核函数或用户态二进制符号上，不需要修改任何业务代码、不需要引入 SDK 或 sidecar。eBPF 程序在内核态运行，通过 Ring Buffer 将事件推送到用户态 Go 程序。业务进程完全无感知——没有端口劫持、没有 iptables 重定向、没有 HTTP proxy。

**Q2: 为什么需要 3 个不同的延迟测量探针？它们各自测量什么？**

答：三个探针测量 TCP 通信链路上的不同层级，解决不同的盲区问题——

- `tcp_sendmsg`（net_trace）：hook 在内核 `tcp_sendmsg` 函数的出入口，测量的是**内核缓冲拷贝时间**，量级 ~µs。应用层调用 `write()`/`send()` → 进入内核 → 拷贝数据到 socket buffer → 返回。这个路径不包含网络传输延迟，**不受 tc netem、交换机延迟等网络级故障影响**。

- `tcp_conntrack`：hook 在 `tcp_connect` 和 `tcp_close`，测量的是**连接生命周期**，从 TCP 三次握手建立到四次挥手关闭的完整时长，量级 ~ms 到 ~s。这个时长包含所有网络传输延迟。适用于短连接场景（HTTP/1.0、DNS）。

- `tcp_rtt`：hook 在 `tcp_sendmsg` 入口和 `tcp_recvmsg` 出口，测量的是**请求级往返延迟**——从客户端发出一个请求到收到服务端响应的完整时间，量级 ~ms。用 `sk_ptr`（struct sock 指针）而非 pid_tgid 做 key 配对 send/recv，解决了连接池中多 goroutine 共享连接时无法正确配对的难题。

**关键洞察**：混沌实验验证，tc netem 注入 200ms 延迟后，`tcp_sendmsg` 的 anomaly_score 始终为 0。因为内核缓冲拷贝只需几十微秒，200ms 的网络延迟完全不经过这条代码路径。只有切换到 `tcp_conntrack` 或 `tcp_rtt` 作为数据源，异常检测才从 0 触发到 15.68。这说明"调低阈值没用，要换对数据源"。

**Q3: Redis 和长连接池为什么是"盲区"？tcp_rtt 怎么解决的？**

答：MySQL/Redis/PgSQL 使用连接池——一个 TCP 连接存活数小时甚至数天，期间承载数万次请求-响应。`tcp_conntrack` 在连接关闭时才计算 duration，对于长连接完全无意义。`tcp_sendmsg` 只能测内核缓冲拷贝。

`tcp_rtt` 在每次 `tcp_sendmsg` 时记录时间戳（以 socket 指针 `sk_ptr` 为 key 存入 BPF map），在 `kretprobe/tcp_recvmsg` 时查找配对并计算 RTT。因为同一连接的 send 和 recv 操作在同一个 `struct sock` 上，无论多少个 goroutine 参与、无论连接存活多久，每次请求的 RTT 都能正确配对。RTT > 30s 的事件被丢弃（那是 TCP keep-alive 而非真实请求）。

**Q4: uprobe http_probe 为什么是"按需动态挂载"而不是常驻？**

答：uprobe 的性能开销远大于 kprobe——每次 HTTP 请求都会触发 CPU 从用户态切换到内核态执行 BPF 程序、读取 HTTP header、写入 Ring Buffer。持续挂载在高 QPS 服务上会造成 1-5% 的 CPU 额外开销。

设计策略是"最小采集原则"：平时只加载 eBPF 对象但不挂载 uprobe（`httpProbeActive=false`），Go 数据面检测到 TCP 级异常后调用 `StartHTTPProbe()` 动态挂载三个 uprobe（readRequest + WriteHeader + gRPC Invoke），60 秒后自动卸载。正常时只用轻量 TCP 探针做拓扑和延迟，异常时才按需启用 L7 深度诊断。

### 追问

**Q5: Ring Buffer vs perf_event 的区别？为什么选 Ring Buffer？**

答：Ring Buffer 是 Linux 5.8+ 引入的新 API。相比 perf_event：支持可变长度记录（不需要预分配固定大小）、API 更简单（reserve/commit 两阶段）、多生产者单消费者场景下锁竞争更小。每个探针独立 Ring Buffer 16MB，Go 侧通过 cilium/ebpf 的 `ringbuf.Reader` 循环读取。缺点是高吞吐下可能丢事件，需要监控 `ringbuf_dropped` 指标。

**Q6: 多个探针都挂在 `tcp_sendmsg` 上，不冲突吗？**

答：不冲突。Linux kprobe 允许在同一函数上注册多个探针，内核维护一个 kprobe 链表。每个探针有独立的 BPF program、独立的 Ring Buffer、独立的 Go 消费 goroutine。`tcp_sendmsg` 是最关键的观测点——TCP 出站流量的必经之路，所以多个探针复用这个 hook 点。代价是入口处的指令数累加（每个 BPF program 都要执行），但每个 program 都很短（小几十条指令），总体开销可控。

**Q7: 探针如何在不同内核版本上运行？**

答：使用 BPF CO-RE（Compile Once, Run Everywhere）。C 代码通过 `vmlinux.h`（BTF 生成的全量内核类型）访问内核结构体，用 `BPF_CORE_READ_INTO` 宏读取字段，字段偏移由 libbpf 在加载时根据目标内核 BTF 信息自动重定位。代码中显式处理 IPv4/IPv6 双栈的地址读取路径。

**Q8: 如果要在生产环境增加一个 TLS 握手延迟探针，怎么设计？**

答：新增 `bpf/tls_handshake.c`，选择 uprobe OpenSSL `SSL_do_handshake` 或 BoringSSL 对应函数。定义独立事件结构体和 Ring Buffer。Go 侧在 `app.go` 的 `Start()` 中加载，消费事件进入 ServiceGraph 时用独立边缘类型标记。策略上同 http_probe 做按需挂载——TLS 握手不如 TCP 通信频繁，常驻采集性价比较低。

---

## 2. 系统架构（Go/Python 解耦）

### 核心叙事

> 采用 "Go 数据面 + Python AI 认知面" 双引擎架构，通过 MCP 协议解耦，确保 Python 认知面故障时 Go 数据面独立运行，内核级自愈不受影响。

### 架构图

```
┌─────────────────────────────────────────────────────┐
│ Linux Kernel                                        │
│  kprobe/kretprobe · uprobe · TC clsact · Ring Buffer│
└──────────────┬──────────────────────────────────────┘
               │ Ring Buffer events
┌──────────────▼──────────────────────────────────────┐
│ Go 数据面 (Data Plane)                               │
│                                                      │
│  事件消费 → ServiceGraph → 异常检测 → 根因分析        │
│       │                    │            │            │
│       │            latRatio = max(      │            │
│       │        sendmsgLatRatio,         │            │
│       │           rttLatRatio)          │            │
│       │                                 │            │
│   Prometheus :2112         自愈执行 + 策略引擎        │
│                             (TC丢包/Pod重启)          │
│                                │                     │
│                        MCP Server :50052              │
│                        (JSON-RPC 2.0 over SSE)        │
└──────────────────────────────┬───────────────────────┘
                               │ MCP 协议
┌──────────────────────────────▼───────────────────────┐
│ Python 认知面 (Cognitive Plane)                       │
│                                                      │
│  MCP Client SSE 订阅 → AlertCorrelator 去重          │
│                                                      │
│  Supervisor → 4 Expert Agents:                       │
│    Topology Analyst → Causal Analyst                 │
│    → LLM Diagnostician → Risk Assessor               │
│    → Remediation Executor + 恢复验证                  │
│                                                      │
│  降级: LLM → 5 Expert Rules → Heuristic              │
└─────────────────────────────────────────────────────┘
```

### 基础问题

**Q1: 为什么是 Go + Python 双层，而不是全 Go 或全 Python？**

答：Go 适合实时数据面——低延迟（微秒级事件消费）、高并发（goroutine）、cilium/ebpf 是 Go 生态最好的 eBPF 库。Python 适合 AI 认知面——LLM SDK 丰富（OpenAI/Anthropic 协议兼容）、LangGraph 工作流编排成熟、数据处理生态完备。

两层通过 MCP 协议松耦合。Python 认知面完全挂掉时，Go 数据面仍能独立执行 eBPF 采集 → 异常检测 → 本地专家规则 → 自愈执行的全链路。内核级自愈不受 AI 可用性影响。

**Q2: MCP 协议在两层之间扮演什么角色？为什么不用 gRPC 或 REST？**

答：MCP（Model Context Protocol）是 AI Agent 与工具交互的新兴标准协议，原生支持 Tool 和 Resource 语义、SSE 流式推送、JSON-RPC 2.0 格式。

Go 侧暴露 5 个工具：`get_topology`（获取异常拓扑）、`evaluate_remediation`（评估爆炸半径）、`execute_remediation`（执行自愈）、`check_policy`（策略检查）、`list_policies`（策略列表）。3 个资源：`topology://current`、`topology://anomalies`、`policy://rules`。

Python 侧通过 SSE 流订阅 `notifications/events/anomaly`，收到异常通知后触发 Multi-Agent 工作流。

相比 gRPC：更轻量、调试更简单（纯 JSON + HTTP）、AI 社区生态更好。相比 REST：Tool/Resource 语义更清晰，SSE 支持服务端主动推送。

**Q3: Python 挂了之后怎么恢复？**

答：Go 数据面不依赖 Python——所有采集、检测、自愈都在 Go 侧独立完成。Python 重启后通过 MCP SSE 重新连接，`get_topology` 拉取当前快照，状态自动同步。Go 侧不缓存通知——Python 断连期间错过的异常通知不补推（发后即忘模式），但下一个 15s 分析周期如果异常仍存在会再次推送。

### 追问

**Q4: MCP SSE 连接断开后怎么处理？**

答：Python MCP Client 在 SSE 断开时自动重连（SDK 内置指数退避）。Go 侧不缓存通知。生产环境需加强：Go 侧增加通知环形缓冲区（重连后补推）、Python 侧主动轮询 `get_topology` 做状态同步。

**Q5: Go 数据面的性能瓶颈在哪？**

答：① Ring Buffer 背压——高吞吐下 16MB buffer 可能不够，Go 消费速率跟不上时丢事件；② ServiceGraph 写锁竞争——`AddCall`/`AddRttCall` 每次都要写锁，高连接数下成为瓶颈（演进方向：分片锁或无锁数据结构）；③ 内存——全量存储 Node/Edge，无自动淘汰，数万边缘场景需考虑。

**Q6: 如果要把两层拆成独立微服务怎么拆？**

答：MCP Server 可独立部署（Go 数据面只做采集和自愈，MCP Server 做查询和推送）。Python 认知面可拆为诊断服务 + 风险评估服务 + 反馈分析服务。但 MVP 阶段两层架构更利于快速迭代和本地演示，过早拆分增加运维复杂度。

---

## 3. 智能诊断（Multi-Agent / 拓扑根因）

### 核心叙事

> 基于 eBPF TCP 连接关系动态生成服务拓扑图，通过 Supervisor 编排 4 专家 Agent 沿链路推导因果链，实现复杂级联故障秒级定位根因。

### 基础问题

**Q1: ServiceGraph 是怎么从 TCP 数据包构建出来的？**

答：eBPF 探针采集的每条 TCP 事件包含五元组（源IP、目标IP、源端口、目标端口、协议）+ PID + 进程名。Go 侧 `consumeMainEvents` goroutine 消费 Ring Buffer 事件：

1. PID → 进程名解析（读取 `/proc/{pid}/cmdline`）
2. IP:Port → 服务名聚合（同服务多实例合并为同一个 Node）
3. `AddCall(src, dst, latencyMs, isError)` 更新边统计
4. `AddRttCall(src, dst, rttMs, isError)` 独立更新 RTT 统计

边统计包含：Count、TotalLat、AvgLat、EmaLat（EMA 平滑，α=0.2）、LatencyWindow（滑动窗口 [30]float64）、P95、BaselineP95（EMA 平滑基线，α=0.1）、CallEma（调用量 EMA）、独立 RTT 统计（RttCount、RttAvgLat、RttP95、RttBaselineP95）。

**Q2: 异常检测的 latRatio 是怎么算的？为什么是双源？**

答：每条边在每个分析周期（15s）计算两个 latRatio：

```
sendmsgLatRatio = max(0, AvgLat / max(BaselineP95 * P95Multiplier, MinLatThresholdMs) - 1)
rttLatRatio    = max(0, RttAvgLat / max(RttBaselineP95 * P95Multiplier, MinLatThresholdMs) - 1)
latRatio       = max(sendmsgLatRatio, rttLatRatio)
```

双源的原因：`tcp_sendmsg` 测量内核缓冲拷贝（~µs），不受网络延迟影响。tc netem 注入 200ms 延迟后 sendmsgLatRatio 仍为 0，但 rttLatRatio 由 tcp_conntrack 驱动，立即触发。`max()` 保证任一数据源检测到异常即可触发。

最终异常分数：`AnomalyScore = latRatio * errorFactor + callAnomaly * CallAnomalyWeight`

**Q3: 反向随机游走是怎么定位根因的？**

答：三步流程——

1. **边缘异常分数计算**：遍历所有边，按延迟 + 调用量维度计算 AnomalyScore
2. **反向随机游走（FaultPropagationRank）**：在反向图（边方向 = 被调用者 → 调用者）上执行带重启的随机游走。以异常边的目标节点为种子，异常分数为边权重。重启概率 0.15 防止陷入循环依赖。迭代最多 50 次或收敛（分数变化 < 0.0001）。收敛后每个节点得到一个嫌疑分数——根因节点会累积所有下游的嫌疑分数，排名最高
3. **嫌疑节点聚类（ClusterSuspects）**：取 Top 5，相邻分数差 < 15% 归为同一故障集群

**为什么反向传播？** 微服务故障有传播效应——一个节点出问题，所有依赖它的下游都表现出延迟上涨。在反向图上从被调用者往调用者走，故障源头累积上游所有下游的分数，而中间节点和下游客的分数会向更上游扩散。

**Q4: Multi-Agent 工作流的 4 个 Agent 分别做什么？**

答：Supervisor 按计划步骤路由到 4 个专长 Agent：

1. **Topology Analyst**：通过 MCP `get_topology` 从 Go 数据面获取当前拓扑（默认仅异常边），过滤和格式化拓扑数据
2. **Causal Analyst**：从异常边构建因果图（`topology_propagation` 方法），沿依赖链推导故障传播路径
3. **LLM Diagnostician**：在因果图 + 异常上下文上运行 LLM 单轮诊断，输出 DiagnosisReport（根因描述 + 置信度 + 受影响服务 + 推荐动作）。含启发式回退
4. **Risk Assessor**：对排名第一的推荐动作评估爆炸半径，输出风险等级 + 执行建议
5. **Remediation Executor**：执行分级自愈 + 轮询恢复验证（2 次，2s/3s 退避）+ 关键字匹配自动回滚

### 追问

**Q5: 异常门控（BaselineGateMultiplier=2.0）解决什么问题？**

答：防止双峰分布抬高基线。定时任务期间 P95 可能暴涨 5-10 倍，如果不设门控，这些异常值会被 EMA 纳入基线，后续正常请求反而低于基线，异常检测永久失效（"温水煮青蛙"）。门控条件：`windowP95 < BaselineP95 * 2.0` 才更新基线，否则冻结。

**Q6: 调用量异常为什么权重是 2.0？**

答：调用量骤降通常是上游链路断裂的信号（下游挂了→上游不再发请求→调用量接近 0），是比延迟上涨更确定的故障信号。权重 2.0 让调用量维度不会被延迟维度淹没。

**Q7: 如果有两个独立根因同时发生（MySQL 慢查询 + Redis 超时），算法能区分吗？**

答：ClusterSuspects 的分组机制部分解决——两个独立根因在调用图中形成两个不连通异常区域，嫌疑分数在高分区呈现双峰（组间分数差 > 15%），聚类后分成两个独立集群。但如果两个根因影响的边数相差悬殊，低分根因可能被高分淹没。改进方向：多次随机游走，每次用不同种子子集。

**Q8: LLM 诊断结果不可靠怎么办？**

答：三层防护：① 启发式回退——LLM API 失败或输出无法解析时降级到规则（选择出边最多的异常节点作为根因，置信度 0.4）；② 置信度字段——Risk Assessor 参考置信度调整风险判断；③ 最终执行仍要通过策略引擎 + 爆炸半径评估 + 金丝雀验证。

---

## 4. 容灾降级与安全熔断

### 核心叙事

> 构建 "LLM → 5 类本地规则 → 启发式" 三层降级与多道安全闸门（含爆炸半径评估与 30s 金丝雀），确保 AI 故障时秒级切本地规则兜底，杜绝高危自愈引发二次事故。

### 安全架构

```
异常检测信号
      │
      ▼
┌──────────────────────────────┐
│ 1. LLM 诊断 (DeepSeek/GPT-4)  │  ← 最高精度，依赖外部 API
│    失败时 ↓                    │
├──────────────────────────────┤
│ 2. 5 类本地专家规则            │  ← Go 本地，不依赖外部
│    cpu-throttle               │
│    conn-pool-exhaustion       │
│    network-partition          │
│    cascading-failure          │
│    retry-storm                │
│    全部不匹配时 ↓              │
├──────────────────────────────┤
│ 3. 启发式兜底                  │  ← 选异常边最多的节点
│    置信度 0.4                  │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ 安全闸门 (执行前检查)          │
├──────────────────────────────┤
│ ✓ 策略引擎 (7 条默认规则)      │
│ ✓ 爆炸半径评估                 │
│ ✓ 冷却防抖 (120s)             │
│ ✓ 金丝雀执行 (单Pod 30s 观察)  │
│ ✓ 恢复验证 + 自动回滚          │
└──────────────┬───────────────┘
               │
               ▼
          执行 / 告警 / 拒绝
```

### 基础问题

**Q1: 三层降级是怎么设计的？**

答：诊断链路的三级降级，保证即使 LLM 完全不可用，系统仍能给出可用的诊断结果：

- **第一层 LLM 诊断**（最高精度）：因果图 + 异常上下文 → LLM → DiagnosisReport（根因 + 置信度 0.6-0.9）。延迟 1-3s。
- **第二层 5 类本地规则**（LLM 失败时）：Go 侧纯规则匹配，不需要网络调用。cpu-throttle（同节点所有边 P95 升高且错误率 < 1%）、conn-pool-exhaustion（单 DB 边高延迟+高错误、邻居正常）、network-partition（单节点所有边错误率 > 90%）、cascading-failure（延迟沿拓扑链递增）、retry-storm（调用量 > 3x 正常、延迟仅微增）。延迟 < 1ms。
- **第三层启发式**（规则全部不匹配时）：选择出边最多的异常节点作为根因，置信度固定 0.4。

**Q2: 7 条策略规则分别保护什么？**

答：策略引擎参照 OPA 设计，轻量级嵌入式实现：

| # | 规则 | 保护对象 | 效果 |
|---|------|---------|------|
| 1 | protect-control-plane | K8s API/etcd/scheduler（kube-system） | deny 所有操作 |
| 2 | protect-critical-data-services | MySQL/Redis/etcd/MinIO/PgSQL | deny 破坏性操作 |
| 3 | protect-localhost | 127.0.0.1/::1 | deny TC 丢包 |
| 4 | max-replica-restart | 单次变更 ≤ 20% 副本 | deny 超量变更 |
| 5 | max-concurrent-tc-drop | 全局 ≤ 5 条 TC 规则 | deny 超额丢包 |
| 6 | daytime-ddl-block | 工作日 9:00-18:00 | deny 配置变更 |
| 7 | high-risk-require-approval | CONFIG_CHANGE/IMAGE_ROLLBACK | warn（不 deny） |

策略检查在 `PerformMitigation` 中对每个嫌疑节点执行，被拒则跳过尝试下一个，全部被拒则只告警不执行。

**Q3: 爆炸半径评估是怎么做的？**

答：通过 MCP 工具 `evaluate_remediation` 评估自愈动作的影响范围：

- **上游影响**：多少服务调用了目标节点（InEdges 索引统计）
- **下游影响**：目标节点调用了多少服务
- **错误预算消耗**：目标节点相关调用量 / 全局总调用量

风险分级：TC_DROP / SCALE_UP → LOW（可逆）；POD_RESTART → 影响 < 3 服务为 MEDIUM、≥ 3 为 HIGH；CONFIG_CHANGE / IMAGE_ROLLBACK → 固定 HIGH。

执行策略：LOW 自动执行、MEDIUM 建议沙箱验证、HIGH 生成 GitOps PR 需人工审批。

**Q4: 金丝雀执行是怎么做的？**

答：LOW 风险动作自动执行时仍走金丝雀流程：先对 1 个 Pod 执行 → 观察 30s → 异常分数下降才全量执行。异常分数未下降则暂停并发送告警。此机制存在于自愈执行管线中，即使策略引擎放行也有金丝雀做最后一道防线。

**Q5: 恢复验证 + 自动回滚怎么做？**

答：自愈执行后，轮询 2 次（2s + 3s 退避）获取拓扑快照。恢复条件：目标节点异常分数降至执行前的 30% 以下 + 平均延迟 < 1000ms。满足 → 生成含 MTTR 的恢复报告。不满足 → 关键字匹配（"Not Resolved"、"Still Elevated"、"failed"）触发自动回滚——TC 丢包调用 `RemoveDropIP`、Pod restart 记录需要人工介入。

### 追问

**Q6: "全部被拒则只告警不执行"是无奈的妥协还是有意的设计？**

答：是有意设计。自愈系统最大的风险不是"不做"而是"做错"——误杀正常节点造成的二次故障比原始故障更严重。如果所有嫌疑节点都被策略拒绝（比如根因是 MySQL 但 `protect-critical-data-services` 阻止了自动操作），系统选择告警通知 SRE 而非冒险操作。宁可漏过一个可自动修复的故障，也不能误操作关键基础设施。

**Q7: 如果 LLM 对同一个异常反复返回不同的诊断结果怎么办？**

答：当前单轮诊断，同一异常只调用一次 LLM，不存在跨轮次不一致。如果异常持续存在（15s 后再次触发），`ServiceHistory` 用 Jaccard 相似度匹配历史异常模式，匹配则复用历史诊断。这是预留能力（方法存在但未深度集成），防止 LLM 在同一故障上反复给出矛盾结论。

**Q8: Dry Run 影子模式有什么价值？**

答：`DRY_RUN=1` 时完整检测-分析-策略评估流程照常运行，告警也正常发送，但所有执行动作被跳过。价值：① 让 SRE 在真实流量中验证 AI 诊断和策略决策的质量，建立信任；② AI 建议作为人工响应的参考；③ 新策略上线前在影子模式中观察假阳性率。

---

## 5. 验证与效能（混沌工程）

### 核心叙事

> 基于自动化混沌工程框架注入典型故障（网络延迟/连接拒绝/CPU 饱和/DNS 失败），将核心检测链路从"不可用"验证到"可用"，发现并修复了 anomaly_score 始终为 0 的结构性缺陷。

### 混沌工程框架

```
runner.sh (主编排器)
  ├── config.sh          全局配置
  ├── lib/
  │   ├── metrics.sh     断言库 (基线对比)
  │   ├── inject.sh      故障注入原语 (幂等)
  │   ├── cleanup.sh     故障清理原语 (幂等)
  │   └── report.sh      JSON + Markdown 报告
  └── experiments/
      ├── 01-network-latency.sh   ✅ 已验证
      ├── 02-tcp-rejection.sh     ✅ 已验证 (已知盲点)
      ├── 04-cpu-saturation.sh    ✅ 已验证
      └── 05-dns-failure.sh       ✅ 已验证 (UDP 盲点确认)
```

实验生命周期：`pre_check → snapshot(pre) → inject → wait → collect_metrics → verify → cleanup → recover_wait → post_check`

### 基础问题

**Q1: 为什么要做混沌工程？发现了什么问题？**

答：最初系统部署后 anomaly_score 始终为 0——无论注入多强的故障（tc netem 200ms、iptables REJECT、stress-ng CPU 打满），仪表盘上所有边都是绿色的。团队花了两周排查阈值、配置、算法公式，都无法解决。

混沌实验系统性地排查了这个问题：依次注入网络延迟、TCP 拒绝、CPU 饱和、DNS 失败 4 类故障，每次采集 Prometheus 指标的 pre/during/post 快照，做基线对比断言。

**关键发现**：问题不在检测阈值（将 MinLatThresholdMs 从 10ms 降到 0.5ms 毫无效果），而在数据源——`tcp_sendmsg` 测量的是内核缓冲拷贝时间（~µs），tc netem 增加的 200ms 网络延迟根本不经过这个代码路径。只有切换到 `tcp_conntrack`（连接生命周期 RTT）或 `tcp_rtt`（请求级 RTT）作为数据源，网络延迟才能被观测到。

**Q2: 修复后效果如何？**

答：代码改动后，实验 01（tc netem 200ms）：

- `anomaly_score_max`: 1.48 → **15.68**（11 条边触发异常）
- `latency_increased`: **10/75 条边** ≥ 50ms
- `ebpf_agent_up`: 保持健康，错误数无新增

核心验证成功：eBPF agent 能从"完全检测不到"到"200ms 延迟立即触发 11 条边异常"。

**Q3: 发现了哪些结构性盲点？**

答：三个盲点，逐一解决：

| 盲点 | 根因 | 解决方案 | 状态 |
|------|------|---------|------|
| tcp_sendmsg 无法检测网络延迟 | kprobe 测量内核缓冲拷贝（~µs），不经过网络栈 | 引入 tcp_conntrack/tcp_rtt RTT 数据源，独立统计 | **已解决** |
| iptables REJECT 无法被 kprobe 观测 | netfilter REJECT 早于 TCP 协议栈，kprobe 在更下层 | 文档标注为已知局限，agent 容忍 | 已知局限 |
| DNS UDP 失败不可观测 | eBPF 不观测 UDP DNS 应答，仅能通过上层 TCP QPS 下降间接推断 | 文档标注为预期盲点 | 已知局限 |

**Q4: 混沌框架的断言为什么基于基线对比而非硬编码阈值？**

答：不同环境的 P95 基线差异很大——开发环境可能是 5ms，生产环境可能是 50ms。硬编码阈值（如"P95 > 20ms 即为异常"）不可移植。基线对比的方案：实验前采集 pre 快照 → 故障期采集 during 快照 → 断言 `during_value > pre_value + delta`。同样适用于恢复验证：`post_value <= max(pre_value, threshold)`。

**Q5: MTTR 从 5 分钟到 15-60 秒是怎么算的？**

答：手动排查链路：收到告警 → 登录服务器 → 查看日志 → 查 Grafana → 定位服务 → 判断根因 → 执行恢复 → 验证。平均 ~5 分钟。

自动链路：eBPF 持续采集 → 15s 分析周期检测异常 → 反向随机游走定位根因（< 1s）→ 策略检查（< 1ms）→ TC 丢包/告警（即时生效）。端到端延迟由分析周期（15s）主导，保守估计 15-60 秒。

改善倍数：5min / 15s = 20x。保守取 15-60s 范围覆盖分析周期抖动和异常传播延迟。

### 追问

**Q6: anomaly_score 从 15.68 恢复到 0 需要多久？为什么？**

答：需要 ~450 秒（约 7.5 分钟）。原因是 P95 窗口有 30 个样本，每个分析周期 15s 产生一个样本。故障清理后，新的正常样本需要逐步替换窗口中所有异常样本，P95 才会归零。120s 恢复后分数降到 ~13.9（降低 12%），180s 降到 ~13.9，未完全清零。这是滚动窗口的数学限制，不是 bug。生产环境通过降低窗口大小或缩短分析周期来优化恢复检测时延。

**Q7: 如果在混沌实验中发现了一个新的盲点，你会怎么处理？**

答：① 记录 pre/during/post 快照做证据；② 分析是检测层问题（数据源/阈值/算法）还是采集层问题（探针 hook 点/协议解析）；③ 如果是采集层问题，判断需要新增探针还是修改现有探针；④ 更新文档的已知局限清单；⑤ 如果是结构性缺陷（如本次的 tcp_sendmsg 盲区），排入技术 Roadmap 解决。每个盲点都是系统变得更鲁棒的机会。

**Q8: 后续还可以注入哪些故障来验证系统？**

答：优先级排序：① 连接池耗尽（模拟 Redis/MySQL 连接池打满，验证 conn-pool-exhaustion 规则）；② 内存泄漏（逐步增加内存压力，验证 OOM 检测和 POD_RESTART 决策）；③ 不稳定的网络（随机丢包率 5-20%，验证异常门控是否误触发）；④ 级联故障（A 慢 → B 慢 → C 慢，验证反向随机游走的根因定位精度）。每次注入按同一生命周期执行，积累检测准确率和 MTTR 改善数据。

---

## 面试建议回答框架

每个问题按三段回答：

1. **是什么**：一句话说清设计/机制/问题
2. **为什么这样设计**：取舍、权衡、实际踩过的坑
3. **极限情况怎么做**：如果压力大 10 倍/如果组件挂掉/如果数据源变了，怎么演进

加分技巧：
- 提到混沌实验的具体数据（anomaly_score 0→15.68）比只说"我们做了测试"有说服力
- 提到盲点（tcp_sendmsg 测 µs 不测网络延迟）比只讲优点更真实
- 用"我们踩过的坑"叙事比"我们实现了 X"更有记忆点
