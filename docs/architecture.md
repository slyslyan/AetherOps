# 系统架构

## 总览

AetherOps 采用三层架构：**内核采集层** → **Go 数据面** → **Python 认知面**。各层通过明确定义的接口通信，可独立部署和扩展。

```
┌─────────────────────────────────────────────────────────────────┐
│                     Python 认知面 (Cognitive Plane)               │
│  Supervisor → Topology/Causal Analyst → LLM Diagnostician        │
│            → Risk Assessor → Remediation Executor               │
│  通信: MCP JSON-RPC 2.0 over HTTP SSE                           │
└───────────────────────────┬─────────────────────────────────────┘
                            │ MCP 协议
┌───────────────────────────┴─────────────────────────────────────┐
│                      Go 数据面 (Data Plane)                       │
│  Ring Buffer → ServiceGraph → 异常检测 → 根因分析                   │
│             → 专家规则引擎 → 分级自愈 + 安全门控                      │
│  通信: Ring Buffer (内核→用户态), MCP Server (对外)                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │ Ring Buffer
┌───────────────────────────┴─────────────────────────────────────┐
│                    Linux 内核 (Kernel Space)                      │
│  kprobe/kretprobe: tcp_sendmsg, tcp_connect, tcp_close,         │
│                    tcp_recvmsg                                    │
│  TC clsact: 丢包熔断                                              │
│  uprobe: net/http.(*conn).readRequest, WriteHeader               │
│  BPF CO-RE: 跨内核版本兼容                                         │
└─────────────────────────────────────────────────────────────────┘
```

## 数据流

### 1. eBPF 事件采集 → Ring Buffer

每个 eBPF 探针有独立的 Ring Buffer，避免跨探针竞争：

```
tcp_sendmsg (kprobe) ──→ main_events (ringbuf)
tcp_connect/close     ──→ conn_events (ringbuf)
tcp_sendmsg/recvmsg   ──→ rtt_events (ringbuf)
tcp_sendmsg (redis)   ──→ redis_events (ringbuf)
tcp_sendmsg (proto)   ──→ proto_events (ringbuf)
tcp_sendmsg (trace)   ──→ trace_context_events (ringbuf)
net/http (uprobe)     ──→ http_events (ringbuf)
```

### 2. Ring Buffer → ServiceGraph

Go 消费 goroutine 并行读取各 Ring Buffer，解析事件后调用 `graph.AddCall()` / `graph.AddProtocolCall()` / `graph.AddTraceContext()` 注入拓扑图。

```
consumeMainEvents()     ──→ graph.AddCall()
consumeConnEvents()     ──→ graph.AddCall()
consumeRTTEvents()      ──→ graph.AddCall()
consumeRedisEvents()    ──→ graph.AddProtocolCall()
consumeProtoEvents()    ──→ graph.AddProtocolCall()
consumeTraceEvents()    ──→ graph.AddTraceContext()
consumeHTTPEvents()     ──→ Prometheus metrics (直写，不经 graph)
```

### 3. 异常检测 → 根因分析

每 `AnalysisInterval` 秒执行一次分析循环：

```
ServiceGraph (当前窗口)
  │
  ├── 1. 更新边延迟窗口 → 计算 P95
  ├── 2. 计算异常分数：latScore + callScore + errorScore
  ├── 3. 更新历史指纹
  └── 4. 反向随机游走 → 根因嫌疑排序
       │
       ├── 嫌疑分数 > 阈值
       │     ├── 专家规则匹配（优先）
       │     └── 或 → MCP 通知 Python 认知面 → LLM 诊断
       └── 无异常 → 更新基线
```

### 4. 自愈执行管线

```
suspects []Suspicion (按分数降序)
  │
  ├── 策略检查 (PolicyChecker.CheckBeforeMitigation)
  ├── 防抖冷却 (Cooldown.IsOnCooldown)
  ├── 频繁锁定 (LockoutTracker.Record)
  ├── 爆炸半径门控 (GateByBlastRadius)
  ├── Dry Run 检查
  │
  ├── [可通过 TC_DROP] → 内核 eBPF TC clsact 丢包
  ├── [需金丝雀] → 1 pod 先执行 → 观察 30s → 全量/回滚
  └── [全被拒] → 仅告警 (飞书 Webhook)
```

## 关键设计决策

### 为什么 tcp_rtt 用 sk_ptr 而非四元组做 key

`tcp_sendmsg` 的 `struct sock *` 指针在连接生命周期内不变，用它做 key 可以正确配同一 socket 的 send/recv 事件。用四元组 (saddr, daddr, sport, dport) 在端口复用场景下会错误配对。

### 为什么 BaselineP95 需要门控

双峰流量（正常 5ms + 异常 500ms）下，如果基线无差别地纳入所有窗口，EMA 平滑后的基线会被抬高，导致 500ms 异常变得"不异常"。门控逻辑：`windowP95 < BaselineP95 * 2.0` 时才纳入基线更新。

### 为什么 Go 本地有专家规则

MCP 连接可能中断（Python 进程 crash、网络抖动、LLM API 限流）。Go 本地预编码 5 条专家规则作为降级方案，确保内核级自愈（TC_DROP）在任何情况下都能执行。降级链：LLM → 专家规则 → 启发式 → "unknown"。

### 为什么自适应采样

正常运行时 100ms 采样足够捕获流量特征。异常发生时需要更精细的时间粒度来定位故障时刻。Go 侧检测到异常分数超过 `AdaptiveSamplingThreshold` 时，通过 BPF map 动态调整 eBPF 采样间隔到 10ms。

### 为什么 TC_DROP 跳过金丝雀

TC_DROP 是纯网络层操作，可秒级恢复（删除 tc clsact 规则）。POD_RESTART 和 CONFIG_CHANGE 不可逆或恢复慢，因此必须走金丝雀。

## 并发模型

```
                    ┌─────────────┐
                    │ ServiceGraph │
                    │ sync.RWMutex  │
                    └──┬───┬───┬──┘
          ┌───────────┤   │   ├───────────┐
    写锁争用         写锁  读锁  读锁        写锁
    (频繁)          争夺  持有  持有        争夺
    ┌──────┐    ┌──────┐ ┌──┐ ┌──────┐ ┌──────┐
    │7 个消费│    │分析循环│ │MCP│ │指标导出│ │自愈执行│
    │goroutine│   │15s/次 │ │读取│ │Prom   │ │按需   │
    └──────┘    └──────┘ └──┘ └──────┘ └──────┘
```

- 7 个消费 goroutine 高频写 `ServiceGraph`（每个 eBPF 事件一次写锁）
- 分析循环读写混合，使用 `Lock()` 因为会回写 `LastCount`
- MCP 读请求和 Prometheus 导出用 `RLock()`
- 自愈执行按需触发，频率最低

## 组件通信

| 方向 | 协议 | 序列化 | 说明 |
|------|------|--------|------|
| eBPF → Go | Ring Buffer | C struct (binary) | 内核到用户态，零拷贝 |
| Go → Go (内部) | 共享内存 | Go struct | ServiceGraph + sync.RWMutex |
| Go → Python | MCP over HTTP SSE | JSON | 认知面通过 MCP 客户端获取数据 |
| Go → K8s | HTTP API | JSON | kubectl / client-go |
| Go → 飞书 | HTTP POST | JSON | 告警通知 Webhook |
