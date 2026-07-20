# AetherOps / ebpfagent 面试问题与答案清单

这份清单用于围绕 ebpfagent（AetherOps）做项目面试复盘。项目核心叙事：**eBPF 内核采集 → 服务拓扑构建 → 异常检测 → 反向随机游走根因定位 → Go 数据面自动自愈 → Python AI Multi-Agent 深度诊断**。

---

## 1. 项目总览

### 基础问题

1. ebpfagent 解决的核心问题是什么？

   答：ebpfagent 是一个基于 eBPF 的智能可观测性与自愈系统。它在内核态通过 kprobe/tracepoint 采集 TCP 通信延迟和连接事件，构建实时服务拓扑图；在用户态通过 EMA 滑动窗口 + P95 基线 + 反向随机游走算法定位根因节点；在自愈侧通过策略引擎 + 爆炸半径评估 + 分级执行实现自动化故障响应；在认知侧通过 MCP 协议连接 Python AI Multi-Agent（Supervisor + 5 专家 Agent）进行 LLM 深度诊断。核心目标是让微服务系统的故障从发现到恢复的 MTTR 从分钟级降到秒级。

2. 项目的技术栈是什么？

   答：内核采集使用 eBPF C（CO-RE + kprobe/kretprobe/uprobe/TC clsact），Go 数据面使用 cilium/ebpf 库加载探针并通过 Ring Buffer 消费事件、构建 ServiceGraph，策略引擎参照 OPA 设计，Go 与 Python 之间通过 MCP 协议（JSON-RPC 2.0 over HTTP SSE）通信，Python 认知面使用自定义工作流引擎编排 Supervisor + 5 专家 Agent，LLM 通过 OpenAI 兼容协议对接 DeepSeek/Anthropic/GPT-4o/Ollama。部署支持 Helm、Docker Compose、systemd。

3. Go 数据面和 Python 认知面分别承担什么职责？

   答：Go 数据面负责实时 eBPF 探针管理、Ring Buffer 事件消费、ServiceGraph 拓扑构建、异常检测与根因分析、策略检查、分级自愈执行以及 MCP Server 暴露工具和推送异常通知。Python 认知面通过 MCP Client SSE 流订阅异常事件，触发 Multi-Agent 工作流（拓扑分析 → 因果分析 → LLM 诊断 → 风险评估 → 自愈执行 + 恢复验证），并记录反馈和计算 MTTR。

4. 从一次 TCP 延迟异常到自动自愈，完整链路是什么？

   答：eBPF kprobe/kretprobe 采集每次 tcp_sendmsg 的耗时 → Ring Buffer 推送事件到 Go 用户态 → ServiceGraph.AddCall 更新边缘 EMA 延迟和滑动窗口 P95 → 每 15 秒分析周期触发 AnalyzeRootCause（边缘异常分数计算 → 反向随机游走 → 嫌疑节点聚类）→ PerformMitigation 按分数降序遍历嫌疑节点：过策略检查 → 过冷却检查 → 对 IP:Port 执行 TC 丢包 + pprof 故障现场保全 → 发送飞书告警 → PublishAnomaly 推送 MCP 通知 → Python 认知面 AlertCorrelator 去重 → Multi-Agent 工作流启动 → LLM 深度诊断 → 风险评估 → 自愈执行 + 恢复验证 + 自动回滚。

5. 这个项目最能体现后端/基础设施能力的 2-3 个设计点是什么？

   答：第一是 eBPF 探针的分层设计——内核级 tcp_sendmsg 拓扑发现 + tcp_rtt 长连接 RTT + tcp_conntrack 连接生命周期 + uprobe HTTP L7 按需挂载，四个探针各司其职、输出共享 net_event 结构。第二是根因分析算法——EMA 平滑 P95 基线 + 异常门控防双峰分布 + 反向随机游走故障传播定位 + 嫌疑节点聚类，概率方法在无分布式追踪的系统中定位根因。第三是自愈策略链——策略引擎 OPA 风格规则检查 + 爆炸半径评估 + 分级执行 + 冷却防抖 + 故障现场保全 + AI 恢复验证 + 自动回滚，形成完整闭环。

### 追问

1. 如果让你用 2 分钟介绍这个项目，你会怎么组织答案？

   答：先用一句话说明 ebpfagent 是通过 eBPF 无侵入采集内核 TCP 通信、结合 AI Multi-Agent 实现微服务故障自动诊断与自愈的系统。然后讲三层架构：内核 eBPF 探针采集 TCP 延迟/连接/HTTP 事件 → Go 数据面构建 ServiceGraph、异常检测和根因定位、执行自愈 → Python 认知面通过 MCP 协议订阅异常、运行 Supervisor + 5 专家 Agent 做 LLM 深度诊断。最后讲技术亮点：反向随机游走根因定位、EMA 异常门控防基线漂移、按需动态 uprobe、策略链步行、分级自愈 + 恢复验证 + 自动回滚的完整闭环。

2. 当前系统的性能瓶颈可能出现在哪些环节？

   答：eBPF 探针在高吞吐场景下 Ring Buffer 可能丢事件（当前 16MB buffer），Go 用户态消费速率跟不上内核生产速率时会丢失采样。ServiceGraph 的锁竞争——AddCall 每次都要写锁更新边缘统计，高 QPS 下边缘数增多后锁成为瓶颈。LLM 诊断的延迟——API 调用耗时在 1-3 秒，是整条链路中最慢的环节。MCP SSE 通知的可靠性和重连机制在生产环境还需加强。

3. 如果要在生产环境落地，你会先补齐哪些能力？

   答：① Ring Buffer 背压监控和丢事件告警；② ServiceGraph 分片锁或无锁数据结构减少竞争；③ MCP 通知持久化和断线重连；④ 自愈执行的结果审计和回滚记录持久化到数据库；⑤ LLM 诊断的多轮对话支持（当前是单轮）；⑥ eBPF 探针的版本兼容性测试矩阵（不同内核版本的 CO-RE 验证）。

4. 这个项目适合拆成微服务吗？

   答：当前 Go 单体 + Python 认知面的两层架构已经是合理的拆分——Go 负责实时数据面（低延迟要求），Python 负责 AI 认知面（高延迟 LLM 调用可接受）。进一步拆分可以将 MCP Server 独立部署（Go 数据面只做采集和自愈，MCP Server 做查询和推送），Python 认知面也可拆为独立的诊断服务、风险评估服务和反馈分析服务。但 MVP 阶段保持两层架构更利于快速迭代和本地演示。

---

## 2. eBPF 探针架构

### 基础问题

1. 项目里有哪些 eBPF 探针？各自 Hook 什么内核函数？

   答：五个探针。`net_trace.c`（kprobe/kretprobe tcp_sendmsg）测量内核发送缓冲拷贝耗时，用于拓扑发现和延迟采集；`tcp_rtt.c`（kprobe tcp_sendmsg + kretprobe tcp_recvmsg）测量请求级 send→recv 往返延迟，覆盖长连接池场景；`tcp_conntrack.c`（kprobe tcp_connect + kprobe tcp_close）测量连接生命周期，覆盖短连接；`tc_drop.c`（TC clsact ingress）用于自愈时内核级丢包；`http_probe.c`（uprobe Go HTTP/gRPC 函数）按需动态挂载，提供 L7 请求路径和状态码。

2. 为什么 tcp_rtt 和 net_trace 都挂了 tcp_sendmsg？不重复吗？

   答：两个探针挂在同一个 hook 点上，但测量目标不同。net_trace 的 kretprobe/tcp_sendmsg 测量的是内核 sendmsg 函数自身的执行耗时（~µs 级），用于延迟基线建立。tcp_rtt 的 kprobe/tcp_sendmsg 只记录发送时间戳（以 sk_ptr 为 key 存入 rtt_track map），在 kretprobe/tcp_recvmsg 中计算 send→recv 的完整 RTT（~ms 级），用于长连接池的请求级延迟。两者输出都使用相同的 net_event 结构体写入各自独立的 Ring Buffer。模块独立是为了按需编译加载——不需要 RTT 时只加载 net_trace，节省 map 内存。

3. tcp_rtt 和 tcp_conntrack 分别适用什么场景？

   答：tcp_conntrack 在 tcp_connect 记录起始、tcp_close 计算连接生命周期，适合短连接场景（HTTP/1.0、DNS）。但对于 MySQL/Redis/PgSQL 连接池，一个 TCP 连接存活数小时甚至数天，connect 到 close 之间可能有数万次请求，tcp_conntrack 的时间跨度毫无意义。tcp_rtt 在每次 sendmsg 记录时间戳、recvmsg 计算 RTT，以 socket 指针为 key（而非 pid_tgid），能正确配合同一连接上多次请求-响应，覆盖连接池盲区。

4. http_probe 为什么是"按需动态挂载"？

   答：uprobe 的性能开销远大于 kprobe——每次 HTTP 请求都会触发 BPF 程序执行、字符串读取和 Ring Buffer 写入。持续挂载在高 QPS 服务上会造成可观的 CPU 开销。当前设计是平时只加载 eBPF 对象但不挂载 uprobe，Go 数据面检测到 TCP 级异常后才调用 `StartHTTPProbe()` 动态挂载，60 秒后自动 `closeHTTPProbe()` 卸载。这是"最小采集原则"——正常情况下只用轻量 TCP 探针做拓扑和延迟监控，异常时才启用 L7 深度诊断。

5. tc_drop 是怎么在内核层丢包的？

   答：tc_drop 是一个 TC clsact 程序挂载在指定网卡的 ingress 方向。Go 侧通过 `AddDropIP(targetIP)` 将目标 IP（uint32 网络字节序）写入 eBPF map `tc_drop_ips`。每次入站数据包到达时，TC 程序解析以太网头 → IP 头 → 提取 dst_ip → 在 map 中查找，命中则返回 `TC_ACT_SHOT`，内核直接丢弃，不进入协议栈。TC 丢包比 iptables 效率更高（在协议栈更早阶段拦截）。Go 侧还有双重机制——BPF map 操作失败时回退到 `tc filter u32 + netem loss 100%`。

### 追问

1. tcp_rtt 如何解决连接池场景下 send/recv 的配对问题？

   答：net_trace 用 `pid_tgid` 做 key 配对 kprobe 和 kretprobe，这在短连接场景有效。但连接池中多个 goroutine 共享同一连接，不同请求的 send/recv 来自不同 goroutine，pid_tgid 完全错配。tcp_rtt 改用 `sk_ptr`（socket 内核对象的指针地址）做 key——同一连接的 send 和 recv 共享同一个 struct sock，无论多少个 goroutine 参与，时间戳都能正确配对。同时 RTT > 30s 的事件被丢弃，因为那是 TCP keep-alive 而非真实请求。

2. eBPF 探针如何保证在不同内核版本上运行？

   答：使用 BPF CO-RE（Compile Once, Run Everywhere）。C 代码里通过 `vmlinux.h`（BTF 生成的全量内核类型定义）和 `BPF_CORE_READ_INTO` 宏读取内核结构体字段，字段偏移由 libbpf 在加载时根据目标内核的 BTF 信息自动重定位。代码中显式处理了 AF_INET（IPv4）和 AF_INET6（IPv6）两种协议族的地址读取路径，分别从 `skc_rcv_saddr/skc_daddr` 和 `skc_v6_rcv_saddr/skc_v6_daddr` 读取，取 IPv6 地址的低 32 位作为简化映射。

3. 为什么选择 kprobe 而不是 tracepoint？

   答：kprobe 可以 hook 几乎所有内核函数，灵活性高；tracepoint 是内核维护的稳定 ABI，但覆盖的函数有限。tcp_sendmsg、tcp_recvmsg、tcp_connect、tcp_close 这些函数签名相对稳定，使用 kprobe 风险可控。代价是内核升级时函数可能改名或参数变化，需要 CO-RE 兼容性测试矩阵。

4. Ring Buffer 和 perf_event 的区别？为什么选择 Ring Buffer？

   答：Ring Buffer 是 Linux 5.8+ 引入的新 API，相比 perf_event 的优势：支持可变长度记录、API 更简单（reserve/commit 两阶段）、多生产者单消费者场景下锁竞争更小。ebpfagent 中每个探针有独立 Ring Buffer，大小 16MB（1<<24），Go 侧通过 cilium/ebpf 的 Reader 循环读取。16MB 足够缓冲短时间的突发流量，但持续高吞吐下需要监控丢事件率。

5. 如果要在生产环境再增加一个探针（比如监控 TLS 握手延迟），你会怎么设计？

   答：在 `bpf/` 下新增 `tls_handshake.c`，选择 kprobe `tls_dev_add` 或 uprobe OpenSSL/BoringSSL 的握手函数。定义独立的事件结构体和 Ring Buffer，复用现有的采样/去重逻辑。Go 侧在 `cmd/tracer/app.go` 中增加 `tlsHandshakeObjects` 的加载和消费 goroutine，事件进入 ServiceGraph 时用独立边缘类型标记。策略上可以和 http_probe 一样做按需挂载，因为 TLS 握手不如 TCP 通信频繁，持续采集性价比较低。

---

## 3. 服务拓扑与异常检测

### 基础问题

1. ServiceGraph 是什么数据结构？

   答：ServiceGraph 是 Go 数据面维护的内存拓扑图，包含 `Nodes map[string]*ServiceNode`（节点 ID→服务节点）和 `Edges map[string]*ServiceEdge`（边 ID→调用关系）。每个 ServiceNode 维护自身的 AvgLat、ErrorRate、CallCount。每个 ServiceEdge 维护 Count、TotalLat、Errors、AvgLat、EmaLat（EMA 平滑延迟）、AnomalyScore、LatencyWindow（滑动窗口 [30]float64）、P95、BaselineP95（EMA 平滑基线）、LastCount、CallEma（调用量 EMA）、CallAnomaly。同时维护 OutEdges 和 InEdges 索引，支持反向随机游走。

2. 异常检测的延迟阈值是怎么计算的？

   答：每个分析周期（默认 15 秒）对每条边计算异常分数。延迟异常部分：`latRatio = max(0, edge.AvgLat / max(BaselineP95 * P95Multiplier, MinLatThresholdMs) - 1)`。即当前平均延迟超过基线的 P95Multiplier 倍（默认 1.2）且大于 MinLatThresholdMs（默认 10ms）时判定为异常，超出的比例即为延迟异常分。调用量异常部分：当前 QPS 低于 CallEma * CallQPSDropRatio（默认 0.3）时触发，量化调用量骤降的程度。最终 `AnomalyScore = latRatio * errorFactor + callAnomaly * CallAnomalyWeight`。

3. 为什么 BaselineP95 要用 EMA 平滑？alpha 为什么是 0.1？

   答：直接用单窗口 P95 做基线会剧烈波动——一次批量任务或网络抖动就让阈值跳变。EMA（指数移动平均）让基线缓慢平滑，alpha=0.1 意味着当前窗口的 P95 只占基线更新的 10%，历史基线的 90% 保留，对短期波动不敏感。选择 0.1 而非更大的 alpha 是因为微服务延迟的自然波动频率较低，较小的 alpha 能更好地捕捉长期趋势。

4. "异常门控"解决什么问题？

   答：在更新 BaselineP95 之前有一个 gating 条件：`if windowP95 < BaselineP95 * 2.0`，只有满足时才更新基线。如果当前窗口 P95 已经是基线的 2 倍以上，说明系统正在经历真正的异常，此时不应该把异常值纳入基线。不这么做的话，一个 30 秒的双峰延迟（比如某节点 CPU 打满）就会把基线抬高，后续即使恢复，也会因为基线过高而检测不到未来的真实异常。这是经典的"温水煮青蛙"问题。

5. ServiceGraph 的内存管理怎么做？

   答：当前 ServiceGraph 是全量内存存储，没有自动淘汰。Node 和 Edge 创建后不会被删除，只会在每个分析周期后被遍历计算异常分数。异常检测阶段的锁策略是读锁遍历边缘、单条边缘内部无锁更新（AddCall 用写锁）。在高连接数场景下（数万个服务间调用关系），内存占用和锁竞争会成为瓶颈，后续演进方向是分片锁（每 N 个边缘一个锁）或使用无锁数据结构。

### 追问

1. EMA 延迟和 EMA 基线为什么要用不同的 alpha（0.2 vs 0.1）？

   答：延迟 EMA（alpha=0.2）用于平滑当前延迟的短期波动，给出最近一段时间的平均延迟水平，需要较快响应真实变化。基线 EMA（alpha=0.1）用于建立长期稳定阈值，变化应该非常慢，防止短暂波动抬高检测门槛。两个 EMA 的快慢搭配是监控系统的常见模式——快 EMA 用于当前值，慢 EMA 用于历史基线。

2. 双峰流量分布（如定时任务和在线请求混合）会导致什么问题？

   答：同一服务可能同时处理低延迟在线请求和高延迟定时批量任务，形成双峰延迟分布。如果基线被定时任务期间的高 P95 纳入，在线请求的延迟即使正常也会远低于基线，异常检测失效。异常门控（2.0x gating）部分解决了这个问题——定时任务通常让 P95 暴涨远超 2 倍，触发门控冻结基线。更彻底的解法是按请求类型分离开边缘统计（例如按 RPC method 或 HTTP path 拆开）。

3. 调用量异常为什么权重是 2.0？

   答：调用量骤降通常是上游链路断裂的信号（下游挂了 → 上游不再发请求 → 调用量接近 0），而不是正常波动。给调用量异常 2.0 的额外权重（CallAnomalyWeight）是因为：① QPS 骤降是强故障信号，比延迟小幅上涨更确定；② 延迟异常和调用量异常常常伴随出现，较高的权重让调用量维度不至于被延迟维度淹没。

4. 为什么 MinLatThresholdMs 设为 10ms？

   答：低于 10ms 的延迟波动通常不是故障，而是正常的系统抖动（上下文切换、缓存 miss、NUMA 效应）。如果不对低延迟做下限保护，一个从 1ms 涨到 2ms 的边缘会算出 latRatio=1.0（100% 增长），但实际上 2ms 完全正常。10ms 是一个经验阈值——低于此的波动不触发异常检测，高于此的波动才有排查价值。

5. 如果在分析周期内（15s）只有少数几条边出现延迟上涨，会被检测到吗？

   答：会。每条边的 AvgLat 是基于本周期内所有采样计算的平均值。如果一条边本周期内只有 2 次采样且都从 10ms 涨到 50ms，AvgLat=50ms，超过基线 10ms * 1.2 = 12ms，会被检测到。但采样稀疏会导致 AvgLat 不稳定——2 次抖动和 2000 次抖动算出同样的 AvgLat，但置信度不同。当前代码没有区分采样量权重，是一个改进方向。

---

## 4. 根因分析算法

### 基础问题

1. 根因分析的三步流程是什么？

   答：① 边缘异常分数计算：遍历 ServiceGraph 所有边，按延迟和调用量两个维度计算 AnomalyScore。② 反向随机游走（FaultPropagationRank）：在反向图上执行带重启的随机游走，以异常边的目标节点为种子，异常分数作为边权重，迭代最多 50 次或收敛（分数变化 < 0.0001），重启概率 0.15。收敛后每个节点得到一个嫌疑分数。③ 嫌疑节点聚类（ClusterSuspects）：取 Top 5 嫌疑节点，相邻分数差 < 15% 的归为同一故障集群。

2. 为什么用反向随机游走而不是简单的"找异常最多的节点"？

   答：微服务故障有传播效应——一个节点出问题，所有依赖它的下游都会表现出延迟上涨。如果只看异常边数量，下游节点因为依赖多个上游，出问题时会被多条异常边指向，容易被误判为根因。反向随机游走在反向图上从异常边往上游传播嫌疑分数——方向是从被调用者往调用者走——每次迭代都把被调用者的嫌疑分数按边权重比例反推给它的调用者。这样故障源头（真正的根因节点）会累积上游所有下游的嫌疑分数，而中间节点和下游客的分数会向更上游扩散。

3. 重启概率 0.15 的作用是什么？

   答：重启概率保证随机游走不会陷入局部循环。在微服务调用图中，A 调 B、B 调 A 的循环依赖很常见，如果没有重启，随机游走会在这个环里来回振荡。每次迭代有 15% 的概率回到原始种子分布（异常边的目标节点），保证分数不会完全被局部循环捕获，同时保留足够的迭代次数让分数沿着调用链向上传播。

4. 为什么嫌疑节点要聚类（15% 分数差阈值）？

   答：同一个根因可能让多个紧密相关的节点同时出现高嫌疑分数——例如一个故障数据库及其连接池代理，两者的嫌疑分数会相近。聚类将这些相关节点归为一组，让自愈执行器和 AI 诊断师看到的是"一组相关的故障节点"而非"一个最高分节点"。"分数差 < 15%"这个阈值经验性较强，可以在生产环境通过历史事件的回溯分析调优。

5. 如果异常检测阶段没有发现任何异常边，根因分析还会运行吗？

   答：不会。`AnalyzeRootCause()` 只在至少有一条边的 AnomalyScore > 0 时才会启动后续的自愈和 MCP 通知。如果所有边缘正常，分析周期只是空转一轮 ServiceGraph 遍历，不触发任何动作。

### 追问

1. 随机游走的收敛条件是什么？

   答：两个条件任一满足即停止：① 迭代次数达到 MaxIter（默认 50 次）；② 所有节点的两次连续迭代分数变化绝对值之和 < 1e-4。在实际运行中，小型拓扑（< 50 个节点）通常在 10-20 次迭代内收敛，MaxIter=50 主要防止大型拓扑或环形依赖导致的收敛缓慢。

2. 如果有两个独立的根因同时发生（比如 MySQL 慢查询 + Redis 连接超时），算法能区分吗？

   答：ClusterSuspects 的分组机制部分解决了这个问题。两个独立根因会在调用图中形成两个不连通的异常区域，嫌疑分数的分布也会在高分区呈现双峰（两组各自的高分节点，组间分数差 > 15%）。聚类后的两个集群分别对应两个根因。但反向随机游走的一次运行只有一个种子分布，如果两个根因影响的边数相差悬殊，低分根因可能被高分根因淹没。改进方向是多次随机游走，每次用不同的种子子集。

3. 为什么不用 PageRank 而是带重启的随机游走？

   答：PageRank 的随机游走是正向的（沿出边传播，模拟用户点击），而故障传播是反向的（沿入边，从被调用者往调用者找根因）。带重启的随机游走更灵活——可以自定义种子分布（异常边的目标节点）、自定义迁移概率（边异常分数）、自定义重启概率。本质上是一个带 personalization 向量的个性化 PageRank 在反向图上的变体。

4. 如果调用图中存在没有边连接但逻辑相关的节点（如共享同一个 Redis），算法怎么处理？

   答：当前算法无法发现"无直接调用关系的共享依赖"。如果服务 A 和服务 B 都调用同一个 Redis，但 A 和 B 之间没有直接调用边，A 的延迟异常不会传播到 B。这是仅依赖网络拓扑做根因分析的固有局限。解法包括：① 引入基础设施依赖拓扑（MySQL/Redis/Kafka 作为独立节点）；② 在 ServiceGraph 中按资源维度（IP:Port 聚合）而不是仅按服务名聚合；当前代码中 IP:Port 粒度的嫌疑节点正是这个方向的尝试。

5. ServiceHistory 历史模式匹配的作用是什么？

   答：`ServiceHistory` 记录每次根因分析的结果（嫌疑节点分布），当新一次分析结果和历史模式相似时（Jaccard 相似度），可以加速诊断——直接复用历史 LLM 诊断结果或采取已验证的自愈策略。当前代码中这是个预留的轻量实现（方法存在但未深度集成），是典型的"先留接口，后补能力"。

---

## 5. 自愈策略链

### 基础问题

1. 自愈执行的整体流程是什么？

   答：`PerformMitigation(suspects)` 接收到按分数降序排列的嫌疑节点列表后，链式遍历每个节点：① 构造 PolicyAction（含 action 类型、target_node、namespace 推断）；② 调用 `CheckBeforeMitigation` 过策略检查和冷却检查；③ 被拒则 continue 尝试下一个节点；④ 通过则执行——对 IP:Port 节点调用 `AddDropIP` TC 丢包，同时采集 pprof CPU/Heap flamegraph、goroutine/thread dump、tcpdump 抓包；⑤ 设置冷却期（默认 120 秒）；⑥ 发送飞书/钉钉告警。全部被拒则只告警不执行。

2. 策略检查都包括哪些规则？

   答：7 条默认规则：① max-replica-restart——禁止单次变更超过 20% 副本；② protect-control-plane——禁止对 K8s 控制平面组件操作；③ protect-critical-data-services——禁止对 mysql/redis/etcd/minio/postgresql 执行破坏性操作；④ protect-localhost——禁止对 127.0.0.1 TC 丢包；⑤ high-risk-require-approval——高风险操作警告；⑥ max-concurrent-tc-drop——全局最多同时 5 个 TC 丢包规则；⑦ daytime-ddl-block——工作日 9:00-18:00 禁止配置变更。

3. 冷却机制（Cooldown）解决什么问题？

   答：冷却期（默认 120 秒）阻止同一个节点被反复自愈。如果根因是配置错误或资源不足，一次自愈后问题仍然存在，没有冷却的话系统会陷入"检测异常→自愈→异常仍在→再次自愈→..."的死循环。冷却给自愈动作留出生效时间，也防止因误判导致的重复冲击。冷却基于内存 map（nodeID → 最近自愈时间），进程重启后冷却状态丢失——这是故意的，因为重启后 eBPF 探针也要重新加载，拓扑从头构建。

4. "全部被拒则只告警不执行"这个设计是无奈之举还是有意为之？

   答：是有意设计。自愈系统最大的风险不是"不做"而是"做错"——误杀正常节点造成的二次故障比原始故障更严重。如果所有嫌疑节点都被策略拒绝（例如根因是 MySQL 但 protect-critical-data-services 规则阻止了自动操作），系统选择发送告警通知 oncall 人员而非冒险操作。这个设计体现了"安全优先"原则——宁可漏过一个可自动修复的故障，也不能误操作关键基础设施。

5. 故障现场保全做了什么？为什么需要？

   答：对 IP:Port 执行 TC 丢包前，先采集：pprof CPU profile（10s 采样）、pprof Heap profile、goroutine dump、thread dump、tcpdump 抓包（`dst host {ip} and port {port}`）。所有文件保存到 `~/.aetherops/output/`，超过 1 小时自动清理。作用：① 事后分析——CPU flamegraph 和 goroutine dump 是定位根因（死锁、CPU 热点、goroutine 泄漏）的核心证据；② 误判兜底——如果自愈动作是错的，有现场数据可以复盘调整策略；③ 审计合规——谁在什么时候对什么节点执行了什么操作，有据可查。

### 追问

1. 为什么使用链式步行而不是一次执行所有嫌疑节点的自愈？

   答：微服务根因通常只有一个或少数几个源头。对 Top-5 全部执行自愈是过度响应——把无辜的下游节点也一起干掉，放大故障半径。链式步行从最高分开始尝试，成功执行一个就 return，符合"最小干预"原则。如果最高分节点被策略拒绝（比如是受保护的数据服务），自动降级到次高分节点尝试。这是一种权衡——可能在根因是受保护服务时"治标不治本"，但避免了误杀。

2. namespace 是如何自动推断的？

   答：`CheckBeforeMitigation` 中，如果 suspicion 节点的 namespace 为空，按节点特征推断：① 控制平面相关节点（端口 6443/2379/10250/10257/10259 或包含 kube/api/etcd 关键字）→ `kube-system`；② 数据库中间件（端口 3306/6379/5432/27017/9092）→ `data-plane`；③ 其他 → `default`。这是基于端口和关键字的启发式推断，K8s 环境中有 cgroup 解析时可以直接拿到真实的 namespace。

3. 飞书告警里展示哪些信息？为什么选 Top 3？

   答：展示 Top 3 嫌疑节点（ID、分数、平均延迟、调用量）、异常摘要、火焰图文件列表。选 3 个是因为移动端推送空间有限，且 3 个节点足够覆盖根因（1 个）和相关影响节点（2 个）。全部 5 个节点信息和详细火焰图需要进入 Grafana 或日志系统查看。

4. 冷却期选 120 秒的依据是什么？

   答：120 秒足够覆盖：① eBPF TC 丢包规则生效（即时）+ pprof 采样（10s CPU + 即时 heap/goroutine）+ tcpdump 抓包片段（~10s）+ 系统稳定观察（~60s）；② Pod restart 类操作在 K8s 中的典型恢复时间（优雅终止 30s + 新 Pod 启动 30s + 健康检查通过 10s）；③ 避免同节点的连续告警风暴。120 秒是一个经验值，可以通过环境变量覆盖。

5. Dry Run 影子模式的价值是什么？

   答：`DRY_RUN=1` 时，完整的检测-分析-策略评估流程照常运行，飞书告警也正常发送，但 `PerformMitigation` 中所有执行动作被跳过。价值：① 让 SRE 团队在真实流量中验证 AI 诊断和策略决策的质量，建立信任；② 影子模式的告警可以作为人工响应的参考——"AI 建议对这个 IP 做 TC 丢包，你要不要手动操作？"；③ 新策略上线前可以在影子模式中观察假阳性率。

---

## 6. AI Multi-Agent 诊断

### 基础问题

1. Python 认知面的 Multi-Agent 架构是什么样的？

   答：一个 Supervisor（调度者）+ 5 个专长 Expert Agent + 可选的 Planner。Supervisor 按计划步骤路由到对应的 Agent。5 个 Agent：Topology Analyst 通过 MCP 从 Go 数据面获取当前拓扑（仅含异常边）；Causal Analyst 从异常边直接构建因果图（当前未接入外部指标，使用 topology_propagation 方法）；LLM Diagnostician 在因果图 + 异常上下文上运行 LLM 单轮诊断（含启发式回退）；Risk Assessor 对排名第一的推荐动作评估爆炸半径；Remediation Executor 执行分级自愈 + 轮询恢复验证 + 关键字匹配自动回滚。

2. 标准工作流的 5 个步骤是什么？

   答：Topology Analyst → Causal Analyst → LLM Diagnostician → Risk Assessor → Remediation Executor。每个步骤的输出是下一步骤的输入。Supervisor 在每步完成后判断下一步路由，全部完成后路由到 `finish`。

3. LLM Diagnostician 的输入和输出是什么？

   答：输入：因果图（服务间依赖关系 + 异常边）、异常上下文（哪些边延迟/调用量异常、异常分数）、可选的 Grafana 截图。用户消息限制在 4000 字符（约 1000 token），仅保留前 20 条异常边防止超长。输出：DiagnosisReport 包含 root_cause（自然语言根因描述）、confidence（0-1 置信度）、explanation（推理过程）、affected_services（受影响服务列表）、recommended_actions（推荐自愈动作）、raw_llm_response（LLM 原始响应）。

4. 启发式回退是什么？什么时候触发？

   答：当 LLM API 调用失败（超时、rate limit、网络错误）或返回无法解析的响应时，自动降级到 `_heuristic_diagnosis`——选择出边最多的异常节点作为根因，置信度固定 0.4。回退计数器跟踪触发次数，频繁回退时说明 LLM 服务质量有问题需要排查。这个设计保证即使 LLM 完全不可用，系统仍然能给出一个基本可用的诊断结果（尽管准确率较低）。

5. 恢复验证怎么做？

   答：自愈执行后，`_verify_recovery` 轮询 2 次（2s + 3s 退避间隔）获取拓扑快照。恢复条件：① 目标节点的异常分数降至执行前的 30% 以下（`post_anomaly < anomaly_score_before * 0.3`）；② 目标节点的平均延迟 < 1000ms。满足条件判定为恢复成功，生成含 MTTR 计算的 Markdown 报告。不满足则检查回滚关键字（"Not Resolved"、"Still Elevated"、"failed"），触发自动回滚。

### 追问

1. Supervisor 怎么知道当前该路由到哪个 Agent？

   答：工作流引擎维护一个步骤索引 `current_step`。Supervisor 读取当前计划中的第 current_step 个步骤名称，按名称映射到对应的 Agent 节点。如果 Planner 生成了动态计划（如 ["causal_analyst", "llm_diagnostician"]），步骤顺序可能不同于默认 5 步。所有步骤完成后，Supervisor 路由到 `finish`。

2. Planner 在什么时候启用？动态计划和固定计划哪种更好？

   答：Planner 通过 `ENABLE_PLANNER=1` 环境变量启用，默认关闭。关闭时使用硬编码的 5 步计划。动态计划的优势是 LLM 可以根据异常类型调整流程——比如明显的网络故障可能跳过因果分析直接进入风险评估，节省 token 和延迟。劣势是增加一次 LLM 调用（约 1-2 秒延迟）+ Planner 可能生成不合理的计划。当前 MVP 阶段默认关闭 Planner，优先跑通固定流程。

3. Causal Analyst 当前使用 topology_propagation 方法是什么？

   答：直接从拓扑的异常边构建因果图——如果服务 A 到服务 B 的边异常，且服务 B 到服务 C 的边也异常，则构建因果链 A→B→C。节点之间是否有因果关系取决于拓扑中是否存在依赖链。这是纯拓扑传播方法，不接入外部 metrics（CPU/内存/磁盘 IO）——这些是预留的扩展点。

4. 为什么 Risk Assessor 只评估排名第一的推荐动作？

   答：LLM Diagnostician 可能返回多个 `recommended_actions`。Risk Assessor 只对排名第一（LLM 认为最优先）的动作进行爆炸半径评估。因为：① 爆炸半径评估需要调用 MCP `evaluate_remediation` 工具，一次调用只评估一个动作；② 如果第一推荐被风险评估拒绝（如爆炸半径太大），Remediation Executor 可以手动降级到第二推荐。全部推荐都不可行时向上报告"无安全可行方案"。

5. 自动回滚的关键字匹配是怎么做的？

   答：在恢复验证阶段，获取自愈后的拓扑数据，用 LLM 分析恢复状态（或直接用固定关键字匹配）：如果响应中出现 "Not Resolved"、"Still Elevated"、"failed"、"degraded" 等关键字，`RollbackAssistant` 触发回滚——对 TC 丢包调用 `RemoveDropIP`，对 Pod restart 记录需要人工介入。关键字匹配的精度有限，更适合做快速反应的兜底，生产环境应升级为 LLM 判断或基于指标的自动回滚。

6. 如果 LLM 对同一个异常重复返回不同的根因，怎么保证诊断一致性？

   答：当前实现单轮诊断，同一异常只调用一次 LLM，不存在跨轮次不一致的问题。但如果异常持续存在（15s 后再次触发分析），LLM 可能给出不同的诊断结果。`ServiceHistory` 和 `JaccardSimilarity` 正是为这个问题预留的——如果当前异常与历史模式高度相似，直接复用历史诊断结果，避免 LLM 在同一个故障上反复给出矛盾结论。

---

## 7. MCP 协议与 Go-Python 通信

### 基础问题

1. MCP 协议在项目里扮演什么角色？

   答：MCP（Model Context Protocol）是 Go 数据面和 Python 认知面之间的通信协议。Go 侧作为 MCP Server，暴露 5 个工具（get_topology、evaluate_remediation、execute_remediation、check_policy、list_policies）和 3 个资源（topology://current、topology://anomalies、policy://rules），通过 HTTP SSE 传输。Python 侧作为 MCP Client，连接 Go 的 MCP 地址，调用工具获取拓扑、评估风险、执行自愈，并通过 SSE 流订阅异常通知。

2. Go MCP Server 暴露了哪些工具？

   答：5 个工具。`get_topology(include_healthy)` 返回当前服务拓扑（节点、边、统计），不传参数时默认只返回异常边以减少传输量；`evaluate_remediation(target_node, action)` 评估自愈动作的爆炸半径——返回风险等级（LOW/MEDIUM/HIGH）；`execute_remediation(target_node, action, force)` 执行自愈，force 为 true 时跳过策略检查；`check_policy(action, target_node, target_ip, namespace)` 检查动作是否通过策略引擎；`list_policies` 列出所有活跃策略规则和冷却状态。

3. 异常通知是怎么从 Go 推送到 Python 的？

   答：Go 侧 `PublishAnomaly()` 通过 MCP Server 推送 `notifications/events/anomaly` 通知——包含 node_id、异常分数、平均延迟、调用量、嫌疑链、时间戳。Python 侧 MCP Client 通过 SSE 流订阅，`AlertCorrelator` 对通知做去重和风暴抑制（相同 node+type+severity 在 60 秒窗口内合并）。有一个技术细节——MCP Python SDK 的 `ServerNotification` 联合类型使用严格 Pydantic 验证，会静默丢弃自定义通知。解决方案是在 SSE 流层面注入 `_AnomalyFilter` 拦截器，在 SDK 看到之前提取异常通知。

4. Python 的同步代码如何调用异步 MCP SDK？

   答：LangGraph 风格的工作流节点是同步函数，但 MCP Python SDK 是异步的（asyncio + httpx）。解决方案是 `run_async` 桥接函数——内部用 `asyncio.run_coroutine_threadsafe` 将协程提交到独立事件循环线程执行，同步代码阻塞等待 Future 结果。这是一种实用但不优雅的桥接方式，代价是每个 MCP 调用都有线程切换开销。更好的方案是让整个工作流引擎异步化，但会增加代码复杂度。

5. 为什么选择 MCP 而不是 gRPC 或 REST？

   答：MCP 是 AI Agent 与工具交互的新兴标准协议，原生支持 Tool 和 Resource 语义、SSE 流式通知、JSON-RPC 2.0 格式。与 gRPC 相比更轻量、调试更简单（纯 JSON + HTTP）；与 REST 相比有更好的语义（Tool 调用 vs CRUD 资源）。项目中的 proto 文件定义了 gRPC 服务但实际使用 MCP——proto 更多是作为接口契约文档留存。

### 追问

1. MCP SSE 连接断开后怎么重连？

   答：当前 Python 侧的 MCP Client 在 SSE 连接断开时会自动重连（SDK 内置的指数退避重连），但重连期间可能丢失异常通知。Go 侧 MCP Server 的 `PublishAnomaly` 是"发后即忘"模式——不缓存通知也不保证送达。生产环境需要：① Go 侧增加通知环形缓冲区，重连后补推；② Python 侧主动调用 `get_topology` 做状态同步。

2. 为什么 `include_healthy` 默认是 false？

   答：正常运行时拓扑可能有数千条边，但异常边通常只有几条到几十条。默认只返回异常边能减少 95%+ 的传输量，让 MCP 调用更快、LLM 上下文更精简。仅当需要全景分析（如排查全局性能问题）时才传 `include_healthy=true`。

3. MCP 工具调用失败时 Python 侧怎么处理？

   答：每个工具调用都有 try/except 封装，失败时返回一个包含错误信息的降级结果。例如 `get_topology` 失败时，Causal Analyst 使用上一轮缓存的拓扑数据；`execute_remediation` 失败时，Remediation Executor 记录错误并向上报告。不会让单一 MCP 调用失败导致整个工作流中断。

4. Go 和 Python 之间为什么要分层而不是全 Go 或全 Python？

   答：Go 适合实时数据面——低延迟、高并发、eBPF 原生支持（cilium/ebpf 是 Go 生态最好的 eBPF 库）。Python 适合 AI 认知面——LLM SDK 丰富、LangGraph/LangChain 生态成熟、数据科学库完备。分层让两个语言各司其职，通过 MCP 松耦合——即使 Python 认知面完全挂掉，Go 数据面仍能独立执行检测和自愈。

5. MCP 协议在生产环境有哪些潜在问题？

   答：① HTTP SSE 的单向推送在代理/负载均衡器后面可能被缓冲或截断，需要确保代理支持长连接透传；② JSON-RPC 2.0 没有内置的服务发现和负载均衡，多副本部署时需要上层解决；③ MCP 协议还在快速演进（当前 SDK 版本间有不兼容变更），需要锁定 SDK 版本；④ Python MCP SDK 对自定义通知的处理不够灵活（Pydantic 严格校验），需要通过 Monkey Patch 或修改 SDK 解决。

---

## 8. 策略引擎

### 基础问题

1. 策略引擎的设计思路是什么？

   答：参照 OPA（Open Policy Agent）的设计，但做了一个轻量级的嵌入式实现。每条策略是一个 `PolicyRule`，包含条件（`PolicyCondition`）和效果（allow/deny/warn）。条件支持：Actions 列表匹配、ProtectedNamespaces/Services/IPs 保护名单、MaxReplicasPercent 批次上限、MaxConcurrentActions 并发上限、BlockTimeRanges 时间窗口、BlockDays 日期限制、MatchPattern 正则匹配。策略可以从外部 JSON 文件加载，也可以直接用内置默认策略。

2. 7 条默认策略分别保护什么？

   答：按保护对象分类——① K8s 控制平面（kube-system namespace + 特定端口和服务名）禁止操作；② 关键数据服务（mysql/redis/etcd/minio/postgresql/pg）禁止破坏性操作；③ 本地回环地址 127.0.0.1 禁止 TC 丢包（防止自伤）；④ 单次变更副本数不超过 20%；⑤ 全局 TC 丢包规则上限 5 条；⑥ 工作日 9:00-18:00 禁止配置变更；⑦ 高风险操作（config_change/image_rollback）标记警告。

3. `CheckBeforeMitigation` 的 namespace 推断逻辑是怎样的？

   答：如果 suspicion 节点本身没有 namespace 信息，按端口和关键字推断：端口 6443/2379/10250/10257/10259 或包含 kube/api-system/etcd 关键字 → `kube-system`；端口 3306/6379/5432/27017/9092 或包含 mysql/redis/postgres/mongo/kafka → `data-plane`；其他 → `default`。这个推断基于 eBPF 从 TCP 连接中采集到的 IP:Port 信息——它不知道 K8s 的 namespace 概念，所以需要用户态启发式映射。

4. 为什么把 `protect-localhost` 作为独立的规则？

   答：在本地开发和压测环境中，所有服务都跑在 127.0.0.1 上。如果没有这条规则，TC 丢包会直接切断本地所有网络通信，导致系统完全不可用。这是一条"自保规则"——防止在不经意间自残。生产环境中这条规则的实际触发很少，因为生产服务通常不会监听 127.0.0.1。

5. `max-concurrent-tc-drop` 限制 5 条是硬编码吗？为什么是 5？

   答：不是硬编码，`MaxConcurrentActions=5` 是默认值，可通过策略配置覆盖。选择 5 是因为：① TC ingress 的丢包规则在数据包处理的最早阶段执行，每个包都要查一次 eBPF map，5 条规则的查找开销可控；② 同时有 5 个以上故障节点需要 TC 丢包是极小概率事件；③ 如果真的发生了，说明不是单点故障，应该升级为人工介入。

### 追问

1. 策略引擎和 OPA 的差异是什么？

   答：OPA 使用 Rego 声明式语言，策略表达能力更强（集合运算、变量绑定、部分求值），但有学习成本。本项目使用 Go 原生实现的条件匹配引擎，表达能力限制在字段相等/正则匹配/数值范围/时间窗口的组合判断，但学习成本为零、无外部依赖、性能更高。取舍是表达能力——复杂的"如果 A 且非 B 且 C 的 80% 条件"在 OPA 里一句话，在条件引擎里需要多个规则组合。

2. 如果需要在工作日夜间允许变更，怎么配置？

   答：`daytime-ddl-block` 规则的 `BlockTimeRanges` 默认是 `[{"start":"09:00","end":"18:00"}]`，`BlockDays` 是 `["Monday","Tuesday","Wednesday","Thursday","Friday"]`。只需修改 `BlockTimeRanges` 的起止时间或 `BlockDays` 排除周末，或者添加一条覆盖规则（优先级更高的 allow 规则在夜间生效）。

3. 策略文件热加载怎么做？

   答：当前策略通过 `WithExternalPolicies(jsonFilePath)` 在启动时加载，运行时不支持热加载。如果需要热加载，实现思路是：① 文件 watcher（fsnotify）监控策略文件变化；② 变化时重新解析 JSON 并原子替换 `engine.rules`；③ 用读写锁保护规则列表的并发访问。当前没做是因为 MVP 阶段策略变更频率极低。

4. 一条自愈动作被 den 和 warn 的区别是什么？

   答：deny 直接拒绝执行，PerformMitigation 的链式步行跳过该节点尝试下一个。warn 表示动作可以执行但需要记录告警——例如 high-risk-require-approval 规则对 CONFIG_CHANGE 类型标记 warn（不是 deny），执行照常但告警中标注"高风险操作，建议人工确认"。warn 的设计给 SRE 留了一个中间地带——不是完全自动也不是完全拒绝。

5. 策略审计日志记录了什么？

   答：`auditLog()` 记录每个自愈动作的决策过程：时间、目标节点、动作类型、检查的规则列表、每条规则的评估结果（allow/deny/warn 及 reason）、最终决策、执行结果。审计日志写入标准输出（能被日志采集系统收集），是事后复盘和安全审计的核心数据源。

---

## 9. 爆炸半径评估

### 基础问题

1. 爆炸半径评估在什么时候触发？评估什么？

   答：两种触发方式。Go 侧：MCP 工具 `evaluate_remediation` 被 Python Risk Assessor 调用时触发，或者在 Web UI/CLI 手动评估时触发。Python 侧：Risk Assessor Agent 在工作流中调用。评估内容：① 上游影响——哪些服务调用了目标节点（通过 InEdges 索引统计）；② 下游影响——目标节点调用了哪些服务；③ 错误预算消耗——目标节点相关调用量 / 总调用量的比例。最终输出风险等级（LOW/MEDIUM/HIGH）和建议。

2. 风险等级是怎么划分的？

   答：按自愈动作类型和影响范围综合判断。TC_DROP 和 SCALE_UP 默认 LOW（可逆、影响范围可控）；POD_RESTART 根据影响节点数——影响服务少于 3 个为 MEDIUM，3 个及以上为 HIGH；CONFIG_CHANGE 和 IMAGE_ROLLBACK 固定 HIGH（不可逆风险高）。风险等级同时影响执行策略——LOW 自动执行，MEDIUM 建议 TEE 沙箱测试，HIGH 要求人工审批生成 GitOps PR。

3. 错误预算消耗是怎么计算的？

   答：`错误预算消耗 = 目标节点相关的总调用次数 / 全局总调用次数`。如果目标节点承载了 30% 的全局调用量，TC 丢包这个节点就相当于消耗 30% 的错误预算。这是一个简单的流量占比估算，目的是量化自愈动作的爆炸半径——"我动这个节点会影响多少流量？"

4. `buildRecommendation` 的三级建议是什么？

   答：LOW → "推荐自动执行，无需人工介入"——系统直接执行自愈。MEDIUM → "建议在 TEE 沙箱环境中先测试后再执行"——先在隔离环境验证自愈动作的安全性。HIGH → "建议生成 GitOps PR，需人工审批后执行"——不直接操作，而是生成变更提案等待 SRE review。

5. 为什么 CONFIG_CHANGE 和 IMAGE_ROLLBACK 固定为 HIGH？

   答：配置变更和镜像回滚是不可逆或难以快速回滚的操作。改一个数据库连接池大小的配置可能让整个服务雪崩，回滚一个镜像可能引入更旧的 bug。TC 丢包是瞬时可逆的（RemoveDropIP 即可恢复），Pod 重启是 K8s 原生能力（ReplicaSet 自动恢复），但配置和镜像变更的影响范围更大、恢复时间更长。固定 HIGH 是保守但安全的选择。

### 追问

1. 如果目标节点承载了 80% 的调用量，评估结果会是什么？

   答：错误预算消耗 = 80%，即使操作类型是 TC_DROP（默认 LOW），`assignRiskLevel` 也会因为影响范围过大将风险等级至少提升到 MEDIUM 或 HIGH。最终 `buildRecommendation` 会建议至少走 TEE 沙箱或人工审批。极端情况下（80%+ 的流量承载在单一节点上）系统会建议"不做任何操作，仅发送告警"——因为对这个节点做任何操作的风险都大于收益。

2. TEE 沙箱在当前实现中是真实存在的吗？

   答：不是。TEE 沙箱在当前代码中是一个 placeholder 建议——系统生成"建议在沙箱环境测试"的文本，但实际没有对应的沙箱环境。这是一个预留的扩展点——如果有 TEE 或 staging 环境，可以自动将自愈动作先在沙箱执行、验证无副作用后再在生产执行。

3. 爆炸半径评估依赖的拓扑数据是实时的吗？

   答：是。评估时通过 MCP 工具 `evaluate_remediation` 调用 Go 侧，Go 侧直接读取内存中的 ServiceGraph 当前快照。ServiceGraph 通过 Ring Buffer 事件实时更新，所以评估基于最新的拓扑状态。但如果 eBPF 采集有延迟（Ring Buffer 背压），拓扑可能滞后于实际网络状态。

4. 如果两个嫌疑节点有依赖关系，先操作哪一个？

   答：PerformMitigation 的链式步行按分数降序，不关心依赖关系。如果 Top-1 和 Top-2 存在调用关系（如 Top-1 调用了 Top-2），先对 Top-1 执行自愈——如果 Top-1 确实是根因，下游 Top-2 的异常会在下一个分析周期自动消失。如果 Top-1 不是根因（被误判），Top-2 的异常仍然存在，下一个周期会再次触发分析。这是一个"乐观单次干预"策略。

5. 爆炸半径评估能用到 K8s 的实际拓扑数据吗？

   答：当前不依赖 K8s API。eBPF 从 TCP 连接层面采集的服务间调用关系更真实（代码里写的调用链 vs 实际网络流量）。但 K8s 的 Deployment/Service/Pod 拓扑可以增强爆炸半径评估——比如知道一个 Pod 属于哪个 Deployment、有几个副本、是否有 PDB 保护。这是一个明确的扩展方向——K8s 感知的爆炸半径评估。

---

## 10. 按需动态挂载（On-Demand Tracing）

### 基础问题

1. http_probe 的按需挂载是怎么触发的？

   答：每次根因分析后，如果检测到异常，Go 侧调用 `StartHTTPProbe()`。这个函数动态挂载三个 uprobe——`net/http.(*conn).readRequest`（记录请求开始时间）、`net/http.(*response).WriteHeader`（捕获 HTTP 状态码和耗时）、`google.golang.org/grpc.(*ClientConn).Invoke`（捕获 gRPC 调用方法名）。挂载持续 60 秒，超时后自动卸载。挂载期间 HTTP 事件写入独立的 Ring Buffer，由 `consumeHTTPEvents` goroutine 消费。

2. 为什么是 60 秒？

   答：60 秒足够覆盖：① Go pprof CPU profile 采样（通常 10-30 秒）；② 几轮 tcpdump 抓包片段；③ 异常自愈动作的生效和验证。同时 60 秒足够短，不会对生产服务造成持续性能影响。60 秒是通过环境变量可调的，建议根据异常排查的典型时间窗口调整。

3. uprobe 的性能开销有多大？

   答：每次目标函数被调用时，uprobe 触发 CPU 从用户态切换到内核态执行 BPF 程序。对于高频 HTTP handler（QPS > 1000），uprobe 的额外开销会累积——BPF 程序的指令数（读寄存器、Ring Buffer reserve/submit）、内核态-用户态切换、Ring Buffer 内存拷贝。在高 QPS 服务上持续挂载 uprobe 可能导致 1-5% 的 CPU 额外开销。按需挂载的设计就是为了让这个开销只在需要排查时产生。

4. 挂载 uprobe 需要知道目标二进制路径吗？

   答：需要。`httpProbeTarget` 配置项（环境变量 `HTTP_PROBE_TARGET`）指定目标二进制路径。对于 Go 服务，通常是 `/proc/self/exe` 或具体的二进制路径。不同部署方式（裸机 vs Docker vs K8s）的路径不同，需要在配置中指定。uprobe 通过符号表解析函数地址，所以目标二进制必须包含符号信息（Go 默认不 strip 符号表）。

5. 卸载 uprobe 后已经采集的数据会丢失吗？

   答：不会。Ring Buffer 中的事件在挂载期间持续被 `consumeHTTPEvents` goroutine 消费并更新到 ServiceGraph 中。卸载只是断开 uprobe hook，已经写入 Ring Buffer 且已消费的数据已经体现在拓扑和指标中。如果卸载时 Ring Buffer 中还有未消费的事件，它们会随 Ring Buffer 的关闭而丢失——这是 Ring Buffer 的"消费后即遗忘"语义。

### 追问

1. 如果 60 秒内没排查完，能手动延长吗？

   答：当前代码不支持手动延长——60 秒到期自动调用 `closeHTTPProbe()`。如果排查需要更长时间，有两个选择：① 调大 `HTTP_PROBE_DURATION` 环境变量（如果暴露了此配置）；② 在下一个分析周期（15 秒后）再次触发异常检测和 StartHTTPProbe。后者会导致 15 秒的 L7 数据空白期。

2. gRPC uprobe 为什么只挂了 `Invoke` 而没有挂 `Stream`？

   答：当前只覆盖了 Unary RPC（单次请求-响应），未覆盖 Streaming RPC。Unary 是最常见的 gRPC 模式，覆盖了绝大多数微服务间调用。Streaming RPC 的 hook 点更复杂（需要 uprobe `ClientStream.SendMsg` 和 `ClientStream.RecvMsg`），且流式调用在延迟诊断中的排查需求不如 Unary 常见。这是一个范围取舍。

3. 如果目标服务不是 Go 写的，http_probe 还能工作吗？

   答：不能。uprobe 挂载的符号是 Go 标准库的特定函数（`net/http.(*conn).readRequest`），目标必须是 Go 编译的二进制。对于 Java Spring Boot、Python FastAPI、Node.js Express 等服务，需要各自语言的 uprobe 符号。当前设计是针对 Go 微服务栈的——如果环境中混合多语言，需要为每种语言写对应的 uprobe 程序。

4. uprobe 挂载失败时怎么处理？

   答：`StartHTTPProbe()` 内部有错误处理——如果 uprobe 挂载失败（符号不存在、权限不足、目标路径错误），记录错误日志但不中断异常处理流程。Go 数据面继续基于 TCP 级探针做拓扑分析和自愈，只是缺少 L7 HTTP 细节（请求路径、状态码）。这是一种优雅降级。

5. 能不能根据端口或进程名自动发现目标二进制？

   答：当前不支持。理论上可以通过 `/proc/{pid}/exe` 自动发现——根据 eBPF TCP 探针采集到的端口号，反查 `/proc/net/tcp` 找到监听该端口的进程 PID，再读取 `/proc/{pid}/exe` 获取二进制路径，然后挂载 uprobe。但这个过程涉及多个系统调用和错误处理，在生产环境的可靠性需要验证。这是一个合理的后续演进方向。

---

## 11. LLM 集成与缓存

### 基础问题

1. 支持哪些 LLM 提供商？

   答：通过 `LLM_PROVIDER` 环境变量切换：deepseek（DeepSeek v4 Flash，默认）、openai（GPT-4o）、anthropic（Claude Sonnet 4.6）、ollama（本地 Llama 3）。所有提供商通过 `LLMProvider` 接口抽象——`Diagnose(ctx, systemPrompt, userMessage)` → `DiagnosisReport`。Provider 的创建通过 `ProviderFactory.from_env()` 工厂方法。

2. 客户端 LLM 缓存是怎么做的？

   答：DeepSeek 不支持服务端 prompt 缓存（Anthropic 支持 `cache_control: ephemeral`），所以在 OpenAICompatibleProvider 中实现了一个客户端 TTL 缓存：key = md5(system_prompt + user_message)，value = DiagnosisReport。缓存大小 128 条目、TTL 60 秒、LRU 淘汰。同一异常周期内（15s 分析间隔 + 相同拓扑输入），后续的 LLM 调用会命中缓存，节省 90%+ 的 API 调用和 token 消耗。

3. LLM 响应的解析为什么会做三级降级？

   答：LLM 输出格式不稳定。`parse_llm_response()` 首先尝试从 ```json 代码块中提取 JSON→如果失败则尝试裸 JSON 解析→如果仍然失败则使用正则从自然语言文本中提取 root_cause 和 recommended_actions。三级降级保证即使 LLM"不听话"输出了非 JSON 格式（例如"根因是：..."这种自由文本），系统仍能提取出可用的结构化信息。

4. Anthropic 的 ephemeral cache 是怎么用的？

   答：`AnthropicProvider` 在 system prompt 中标记 `cache_control: {type: "ephemeral"}`，告诉 Anthropic 服务端缓存 system prompt（98 行结构化的诊断指令）。后续相同 system prompt 的请求在 5 分钟缓存窗口内免去 prompt 处理开销，减少延迟和费用。user message（因果图 + 异常上下文）每次不同，不做缓存。

5. 诊断结果中为什么要加 `confidence` 字段？

   答：LLM 诊断不是 100% 可靠的。`confidence` 让下游（Risk Assessor、Remediation Executor）能量化诊断结果的可信度。低置信度（< 0.5）的诊断结果在风险评估阶段更保守——倾向于只告警不执行。启发式回退固定 0.4 置信度，低于 LLM 诊断的典型值（0.6-0.9），暗示下游"这个诊断结果可能不太准"。

### 追问

1. 为什么默认选择 DeepSeek？

   答：成本低（API 调用费用远低于 GPT-4o/Claude）、延迟可接受（1-2 秒）、中文和英文质量都不错。更重要的是，DeepSeek 是可用性要求不高的诊断场景的合适选择——诊断不是面向用户的，2 秒延迟完全可以接受。生产环境可以根据预算和延迟要求切换到 GPT-4o 或 Claude。

2. 客户端缓存的 LRU 淘汰策略在什么情况下会导致问题？

   答：缓存 key 是 md5(system_prompt + user_message)，如果两个不同的异常恰好产生相同的 user_message（前 20 条异常边的拓扑一致），缓存会返回前一次异常的错误诊断结果。这种情况概率很低——20 条边的具体延迟值、异常分数、调用量完全相同的可能性极小。更安全的做法是在 hash 中加入时间戳或事件 ID，但会降低缓存命中率。

3. 如果 LLM 返回了一个看起来合理但实际错误的根因，系统有什么防止执行的机制？

   答：多层防护：① 策略引擎可能拒绝对这个节点的操作；② 爆炸半径评估如果判定为 HIGH 风险，只生成 GitOps PR 不自动执行；③ Dry Run 模式完全不执行；④ 恢复验证阶段如果发现未恢复，触发回滚。但这些都不能防止"诊断结论本身错误"——这是当前 AI 诊断系统的固有限制。

4. LLM 上下文长度限制（4000 字符 / ~1000 token）对诊断质量影响大吗？

   答：有一定影响。4000 字符可以容纳约 20 条异常边的详细信息 + 因果关系图 + 系统提示中的诊断指南，对大多数故障足够了。但复杂故障（数十个服务间级联故障）的上下文会被截断，可能导致 LLM 遗漏关键的间接依赖关系。调大限制会增加 token 消耗和延迟。更好的方案是多轮诊断——先让 LLM 看全景，再追问具体的嫌疑路径。

5. Ollama 本地模型的诊断效果如何？

   答：Llama 3 8B/70B 在结构化输出方面不如 GPT-4o/Claude 稳定——更容易输出非 JSON 格式或不符合预期结构的内容。三级降级解析在这种情况下会被频繁触发（降级到正则提取）。本地模型的优势是零 API 费用、零网络延迟、数据不出本地，适合:① 开发调试阶段；② 对数据合规性有严格要求的场景。生产环境的诊断质量建议至少使用 DeepSeek V3 或 GPT-4o 级别的模型。

---

## 12. 监控与运维

### 基础问题

1. 项目暴露了哪些 Prometheus 指标？

   答：14 个指标，命名空间为 `aetherops`。核心指标包括：边延迟（Gauge）、调用量（Counter）、错误数（Counter）、异常分数（Gauge）、节点平均延迟（Gauge）、根因分数（Gauge）、自愈触发数（Counter）、HTTP 请求数和延迟（Histogram + Counter）、Agent 事件/错误数（Counter）、Agent 存活（Gauge）。Go 数据面通过 `:9091` 端口暴露，Python 认知面通过 `:9093` 端口暴露。

2. 自愈触发数和根因分数这两个指标有什么用？

   答：自愈触发数是 SRE 最关注的告警指标——短时间内的飙升说明系统反复检测到异常并尝试自愈，可能意味着根因未被真正解决或自愈动作无效（重复触发）。根因分数是诊断质量的代理指标——高分（> 90 百分位）且集中的分布说明根因信号清晰，低分且分散说明系统在"猜测"而不是"确定"。两个指标结合可以评估自愈系统的健康度。

3. Go 数据面和 Python 认知面各自独立暴露 metrics，如何统一查看？

   答：Prometheus 配置中同时抓取 `:9091` 和 `:9093` 两个 target，Grafana 面板将两者的指标放在同一个 dashboard 中。Go 侧的指标偏基础设施（拓扑、延迟、自愈次数），Python 侧的指标偏 AI 应用（Agent 事件数、LLM 调用延迟、诊断置信度分布）。统一的 Grafana dashboard 让 oncall 人员在一个页面看到从内核到 AI 的完整链路。

4. 如何在本地运行和验证项目？

   答：Docker Compose 启动全栈：`cd apps && docker compose up -d --build`。启动后可以手动触发异常（如用 stress 工具对某个服务加压），观察 ebpfagent 是否检测到延迟上涨、是否触发根因分析和自愈。验证路径：查看 Grafana 拓扑面板 → 查看 Prometheus 异常分数 → 查看飞书/webhook 告警 → 查看 `~/.aetherops/output/` 火焰图和抓包文件。

5. Worker 成功率和 Agent 存活指标分别说明什么？

   答：Worker 成功率（Go mq_*_consume 指标）表示 RabbitMQ 消息消费的健康度——低成功率意味着互动落库或 fanout 有问题。Agent 存活（Python agent_alive Gauge）是心跳指标——如果持续为 0，说明 Python 认知面挂了，Go 数据面仍在独立运行但失去了 AI 诊断能力。

### 追问

1. eBPF 探针本身的运行状态怎么监控？

   答：当前没有专门的 eBPF 探针存活指标。可以通过间接方式判断：① Ring Buffer 消费的事件数为 0 但系统有流量 → 探针可能挂载失败或 hook 点未触发；② ServiceGraph 的节点/边数量无变化 → 探针未工作。生产环境应增加：eBPF 程序运行状态、Ring Buffer 丢事件计数、kprobe 挂载状态。cilium/ebpf 库本身提供了这些 API。

2. 如果异常检测触发了自愈但飞书告警没收到，怎么排查？

   答：依次排查：① Prometheus 自愈触发数是否 +1（确认 Go 侧确实执行了）；② Go 日志中 `sendAlert` 是否有错误输出；③ webhook URL 是否正确配置；④ 网络是否能从部署环境访问飞书/钉钉 API；⑤ webhook 响应状态码和 body。条件允许时可以加上告警投递成功的 Counter 指标。

3. Grafana 面板中最重要的 3 个面板是什么？

   答：① 拓扑图（节点和边实时更新、异常边红色高亮）——一眼看到哪个服务出问题；② 根因分数时间序列——看检测结果是否稳定收敛（同一个节点持续高分 = 真正的根因，分数在不同节点间跳变 = 诊断不稳定）；③ 自愈执行日志（时间、目标、动作、结果）——事后复盘的核心数据源。

4. 如何验证新策略上线后不会导致假阳性？

   答：先在 Dry Run 模式下运行一段时间（建议至少一周），收集所有"本应执行但被影子模式跳过的"自愈动作。人工审核这些动作是否合理——如果大部分都应该执行，说明策略没挡住正常操作；如果出现明显不合理的建议（如建议重启 kube-apiserver），说明策略需要收紧。Dry Run 数据和真实告警对比后调整策略阈值和规则。

5. 当前项目没有分布式追踪，eBPF 能在多大程度上替代？

   答：eBPF TCP 探针能替代分布式追踪的核心能力——端到端延迟、服务间调用关系、错误率。但缺失：请求级别的上下文传播（trace ID、span ID）、业务标签（用户 ID、订单 ID）、应用级别的错误语义。eBPF 的延迟测量是无侵入的、100% 覆盖的，分布式追踪需要代码埋点但能提供更丰富的请求上下文。两者互补而非替代——eBPF 做粗粒度的拓扑和延迟异常检测，分布式追踪做细粒度的请求级排查。

---

## 13. 大厂高频综合追问

1. 你在这个项目里做过最复杂的技术决策是什么？

   答：最复杂的决策是根因分析算法的选择——在反向随机游走、PageRank 变体和简单阈值排序之间做取舍。最终选择反向随机游走是因为微服务故障传播的方向性（从上游往下游扩散），反向传播能更准确地定位源头。同时加入重启概率（防循环依赖）和异常门控（防基线漂移）两个关键细节。这个决策需要在算法准确性、计算开销和代码复杂度之间平衡——随机游走比简单阈值准但比 ML 模型轻，50 行 Go 代码就能实现。

2. 这个系统如何保证不自伤——即不因为错误的诊断而加剧故障？

   答：多层防护：① 策略引擎的多条保护规则（禁止操作控制平面、数据服务、127.0.0.1）；② 爆炸半径评估（影响范围过大时升级为人工审批）；③ 冷却防抖（同一节点 120 秒内不重复操作）；④ 链式步行 + 单次干预（一次只操作一个节点）；⑤ Dry Run 影子模式（先看决策质量再开自动执行）；⑥ 恢复验证 + 自动回滚（自愈后检查是否真的恢复了）。每一层都可能拦截错误决策，且默认行为是"不做"（全部被拒只告警）。

3. 如果 eBPF 探针本身在目标机器上出了问题（比如内核版本不支持），怎么发现和处理？

   答：发现：① Go 启动时 eBPF 对象加载会失败（cilium/ebpf 返回错误），进程无法启动 → 通过进程存活监控发现；② 运行时 kprobe 失效（如内核热补丁修改了函数签名），Ring Buffer 事件量骤降 → 通过事件消费速率指标发现。处理：① CO-RE 兼容性测试矩阵（在 CI 中对多个内核版本做自动化测试）；② Go 侧的 eBPF 加载失败时记录详细错误（包括内核版本、缺失的 BTF 类型）方便排查；③ 提供回退方案——如果 eBPF 不可用，降级到 /proc/net/tcp 轮询采集。

4. 如果把这个项目写进简历，你会突出哪些指标和取舍？

   答：突出 eBPF 探针的内核级零侵入采集能力（无需改应用代码、无需 sidecar）、反向随机游走 + EMA 门控的根因定位算法（15s 分析周期）、策略引擎 + 爆炸半径评估 + 分级自愈的安全执行链路。指标上写清探针覆盖的内核函数、异常检测的 P95 阈值精度、自愈成功率和误报率（需在压测环境中统计）。关键取舍：准确性 vs 计算开销（概率方法而非 ML）、自主性 vs 安全性（链式步行 + 多层防护 + 默认不操作）、覆盖度 vs 性能（按需动态 uprobe）。

5. 如果老板要求 MTTR 从 5 分钟降到 30 秒，你会怎么改架构？

   答：① 分析周期从 15s 降到 5s（更快检测）；② 冷却期从 120s 降到 30s（更快重试）；③ 跳过 Python 认知面的 AI 诊断环节（LLM 调用 2-3s 太长），Go 数据面直接根据根因分数执行自愈；④ 预计算常见故障模式的自愈策略表（模式匹配代替 LLM 推理）。代价是误判率上升——30 秒的观察窗口可能没有足够的采样数据支撑准确判断。30s MTTR 和低误判率是矛盾目标，需要根据业务的容错能力选择平衡点。

6. 如果线上出现一起故障，系统检测到了但没有触发自愈，你从哪些链路排查？

   答：先看 detection 环节：① 边缘的 AnomalyScore 是否 > 0？如果没有，检查基线是否被异常值抬高（门控失效）、MinLatThresholdMs 是否设置过高、P95Multiplier 是否过于宽松。再看 analysis 环节：② AnalyzeRootCause 是否找到了嫌疑节点？如果随机游走后所有节点分数都接近 0，检查异常边是否形成了合理的反向传播路径。然后看 mitigation 环节：③ 嫌疑节点是否全部被策略拒绝？检查每个嫌疑节点的 PolicyCheck 结果和拒因。④ 是否被冷却期拦截？检查 Cooldown 状态。⑤ 是否 Dry Run 模式？检查 DRY_RUN 环境变量。最后看执行环节：⑥ 自愈动作是否执行失败？检查 AddDropIP 的错误日志和回退 tc 命令的返回值。

---

## 14. 建议练习顺序

1. 先练项目总览、eBPF 探针架构、探针取舍（tcp_rtt vs tcp_conntrack vs net_trace）。
2. 再练 ServiceGraph、异常检测算法、EMA 门控。
3. 然后练根因分析（反向随机游走）、策略引擎、自愈链式步行。
4. 接着练 Python 认知面（Supervisor + 5 Agents）、MCP 协议、按需 uprobe。
5. 最后练 LLM 缓存、爆炸半径、监控运维和综合追问。

每个问题都尽量按"现有实现、为什么这样设计、极端情况下怎么演进"三段回答。
