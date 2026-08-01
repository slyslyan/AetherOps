# eBPF 探针设计文档

## 探针总览

```
                         ┌── tcp_sendmsg (kprobe)     ──→ main_events      ──→ 通用 TCP 流量
                         ├── tcp_sendmsg (kretprobe)
                         │
                         ├── inet_sock_set_state (tp) ──→ conn_events       ──→ 连接生命周期
                         │
                         ├── tcp_close (fentry)        ──→ rtt_events        ──→ 内核 SRTT
Linux Kernel            │
TCP/IP Stack            │
                         ├── tcp_sendmsg (Redis)      ──→ redis_events      ──→ Redis 命令
                         │
                         ├── tcp_sendmsg (Proto)      ──→ proto_events      ──→ 协议分类
                         │
                         ├── tcp_sendmsg (Trace)      ──→ trace_ctx_events  ──→ TraceID 提取
                         │
                         ├── TC clsact (egress)        ──→ 直接丢包          ──→ 自愈熔断
                         │
                         └── net/http (uprobe)         ──→ http_events      ──→ HTTP 细分
```

## 1. tracer — 通用 TCP 流量拓扑

**文件**: `bpf/net_trace.c`
**Hook**: kprobe + kretprobe `tcp_sendmsg`
**事件类型**: `netEventRaw`

```
struct netEventRaw {
    saddr, daddr uint32    // 源/目标 IP (小端序)
    sport, dport uint16    // 源/目标端口
    family       uint16    // AF_INET = 2
    delta        uint64    // 发送耗时 (ns)
    pid          uint32    // 进程 PID
    comm         [16]byte  // 进程名
}
```

**测量原理**：`tcp_sendmsg` 入口记录时间戳 → 出口计算 delta = 内核缓冲拷贝时间。约 µs 级。

**重要限制**：`tcp_sendmsg` 测量的是内核缓冲拷贝（~µs），**不受 tc netem 等网络级延迟影响**。网络故障检测必须依赖 `tcp_conntrack`（连接级 RTT）或 `tcp_rtt`（内核 SRTT）作为延迟数据源。Go 侧异常检测已实现双源切换：`latRatio = max(sendmsgLatRatio, rttLatRatio)`。

**数据通路**：
```
tcp_sendmsg 入口 → bpf_map (PID→时间戳)
                 → tcp_sendmsg 出口 → 计算 delta
                 → ringbuf reserve + submit
                 → Go consumeMainEvents()
                 → graph.AddCall(srcSvc, dstSvc, delta/1e6, isErr)
```

**采样**：通过 `sampling_config` BPF map 控制，默认 100ms 间隔，异常时自适应降至 10ms。

**适用范围**：所有 TCP 出站连接。不区分长/短连接。

---

## 2. tcp_conntrack — 连接生命周期 RTT

**文件**: `bpf/tcp_conntrack.c`
**Hook**: tracepoint `sock/inet_sock_set_state`
**事件类型**: `connEventRaw`
**参考来源**: iovisor/bcc libbpf-tools/tcpstates (BSD-2 License)

```
struct connEventRaw {
    saddr, daddr uint32
    sport, dport uint16
    role         uint8     // 1=client, 2=server
    duration_ns  uint64    // 连接持续时间
    pid          uint32
    comm         [16]byte
}
```

**测量原理**：tracepoint `inet_sock_set_state` 捕获所有 TCP 状态转换。`TCP_ESTABLISHED` 时记录连接建立时间（根据 oldstate 区分 client/server 角色），进入 `TCP_FIN_WAIT1`/`TCP_CLOSE_WAIT`/`TCP_LAST_ACK` 时计算连接持续时长并输出事件。tracepoint 直接提供 sport/dport/saddr/daddr，无需 `BPF_CORE_READ`，比 kprobe 方案更可靠。

**适用范围**：短连接（HTTP/1.0, DNS）的网络级 RTT 检测。长连接（MySQL 连接池）的 duration 会被过滤（> 30s 丢弃）。

**在混沌工程中的关键作用**：`tcp_conntrack` 连接时长包含网络传输延迟（~ms），而 `tcp_sendmsg` 仅测内核缓冲拷贝（~µs）。tc netem 200ms 注入后，`tcp_conntrack` 驱动的 `rttLatRatio` 能正确触发异常检测（anomaly_score 0→15.68）。

---

## 3. tcp_rtt — 内核平滑 RTT

**文件**: `bpf/tcp_rtt.c`
**Hook**: fentry `tcp_close`
**事件类型**: `netEventRaw`（复用）
**参考来源**: cilium/ebpf examples/tcprtt (MIT License)

**测量原理**：`fentry/tcp_close` 在连接关闭时触发，通过 `BPF_CORE_READ(tcp_sock, srtt_us)` 直接读取内核 TCP 栈维护的平滑 RTT（SRTT）。内核从 ACK 往返计时中持续更新 `srtt_us`，比手动 send/recv 配对更可靠。值以微秒 << 3 存储，需 `>> 3 * 1000` 转换为纳秒。

**关键设计**：fentry（trampoline-based hook）比 kprobe 更高效，无需保存中间状态（sk_ptr→timestamp 的 BPF map 不再需要）。每个连接关闭时仅产生一个 RTT 事件，包含连接生命周期内的平均 RTT。

**RTT 范围过滤**（Go 侧）：
- RTT ≤ 0 → 丢弃（内核尚未收集足够样本）
- RTT > 30s → 丢弃（异常值）
- 有效范围：(0, 30s]
- 连接 < 1ms 在 BPF 侧过滤（失败/中止连接）

**适用范围**：所有 TCP 连接的关闭事件。`srtt_us` 是连接生命周期内的平均平滑 RTT，比单次 send/recv 配对更稳定。

---

## 4. tc_drop — 内核级丢包熔断

**文件**: `bpf/tc_drop.c`
**Hook**: TC clsact (egress)
**事件类型**: 无（直接丢包，不产生事件）

**原理**：
1. Go 侧通过 `tc` 命令或 eBPF TC 程序将目标 IP 加入丢包规则
2. 内核在 egress 路径匹配 IP 后直接 DROP
3. 规则有 TTL（默认 5 分钟），到期自动清理

**两级实现**：
1. **eBPF TC 程序**（优先）— BPF_MAP_TYPE_HASH 存储 `drop_ips`，TC clsact 匹配后丢包
2. **tc 命令回退**（eBPF 加载失败时）— `tc qdisc add ... handle 1: root htb` → `tc filter add ... action drop`

**安全特性**：
- 127.0.0.1 / ::1 永不丢包
- TTL 到期自动恢复
- `RemoveAll()` 立即恢复所有流量

---

## 5. http_probe — HTTP 请求细分

**文件**: `bpf/http_probe.c`
**Hook**: uprobe `net/http.(*conn).readRequest` + `net/http.(*response).WriteHeader` + `google.golang.org/grpc.(*ClientConn).Invoke`
**事件类型**: `httpEventRaw`

```
struct httpEventRaw {
    method      uint16   // 1=GET, 2=POST, 3=PUT, 4=DELETE, 5=HEAD, 6=PATCH
    status_code uint16
    duration_ns uint64
    path        [128]byte
}
```

**挂载策略**：按需动态挂载。
1. 初始仅加载 eBPF 对象，**不挂载 uprobe**
2. Go 检测到 HTTP 异常时调用 `StartHTTPProbe()` 挂载
3. 60 秒后自动卸载，避免持续 CPU 开销
4. 重复调用无副作用（httpProbeActive 标志 + mutex 保护）

**数据通路**：不经过 ServiceGraph，直接写入 Prometheus 指标 (`ebpf_http_requests_total`, `ebpf_http_request_duration_ms`)。

---

## 6. redis_trace — Redis 协议解析

**文件**: `bpf/redis_trace.c`
**Hook**: kprobe `tcp_sendmsg`
**事件类型**: `redisEventRaw`

```
struct redisEventRaw {
    pid      uint32
    data_len uint32
    ts_ns    uint64
    command  [16]byte   // "GET", "SET", "MGET" 等
    pad      [4]byte
}
```

**解析策略**：
1. 端口过滤：通过 `redis_ports` BPF map 配置（默认 6379）
2. 读取 payload 前 64 字节
3. 匹配 RESP 协议：`*` + 数字（参数个数）→ 解析 `$` + 数字（参数长度）→ 提取命令名

**识别命令**：GET, SET, DEL, MGET, MSET, INCR, DECR, LPOP, RPOP, EVAL, HGET, HSET, PING, AUTH, LPUSH, RPUSH, SELECT, EXPIRE, HGETALL

**Verifier 约束**：所有字符串比较展开为无循环字节匹配，每个命令独立比较（如 `if (buf[0]=='G' && buf[1]=='E' && buf[2]=='T')`），不做任何不确定次数的循环。

**数据通路**：
```
tcp_sendmsg → redis_events ringbuf
           → Go consumeRedisEvents()
           → graph.AddProtocolCall(src, dst, 0, false, "redis", cmdName)
           → Prometheus redis_commands_total
```

---

## 7. proto_classifier — 应用协议自动发现

**文件**: `bpf/proto_classifier.c`
**Hook**: kprobe `tcp_sendmsg`
**事件类型**: `protoEventRaw`

```
struct protoEventRaw {
    saddr, daddr   uint32
    sport, dport   uint16
    detected_proto uint8    // 0=unknown, 1=HTTP1, 2=HTTP2, 3=MySQL, 4=Redis
    confidence     uint8    // 默认 80%
    pad            [2]byte
    pid            uint32
    comm           [16]byte
}
```

**分类逻辑**：
1. HTTP/2 connection preface: `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`（前 12 字节匹配）
2. HTTP/1.x: 以 GET/POST/PUT/DELETE/HEAD/PATCH/HTTP/1. 开头
3. Redis RESP: 以 `*` + 数字开头
4. MySQL: 端口 3306 且 3 字节小端长度 < 16MB（二进制包头启发式）

**数据通路**：
```
tcp_sendmsg → proto_events ringbuf
           → Go consumeProtoEvents()
           → graph.AddProtocolCall(src, dst, 0, false, "http1"/"redis"/"mysql", "")
           → ServiceEdge.Protocol 字段标注
```

---

## 8. trace_context — 分布式追踪上下文提取

**文件**: `bpf/trace_context.c`
**Hook**: kprobe `tcp_sendmsg`
**事件类型**: `traceEventRaw`

```
struct traceEventRaw {
    saddr, daddr  uint32
    sport, dport  uint16
    pid           uint32
    timestamp_ns  uint64
    trace_id      [16]byte    // 二进制 TraceID
    span_id       [8]byte     // 二进制 SpanID
    trace_source  uint8       // 1=W3C, 2=Jaeger, 3=Datadog, 4=generic
    pad           [3]byte
}
```

**支持的 Trace Header**：

| 标准 | Header 格式 | 提取内容 |
|------|-----------|---------|
| W3C | `traceparent: 00-<32hex>-<16hex>-<2hex>` | TraceID (16B) + SpanID (8B) |
| Jaeger | `uber-trace-id: <hex>:<hex>:...` | TraceID + SpanID |
| Datadog | `x-datadog-trace-id: <decimal>` | TraceID (uint64 → 8B BE) |

**解析策略**：
1. 读取 payload 前 256 字节（覆盖典型 HTTP header block）
2. 按优先级尝试：W3C → Jaeger → Datadog
3. 匹配到第一个即返回

**Verifier 约束**：
- `bpf_probe_read_user` 限制 256 字节
- 所有 hex 转换和字符串比较展开为无循环操作
- 前缀匹配使用逐字节比较（如 `if (buf[0]!='t') return -1`）

**数据通路**：
```
tcp_sendmsg → trace_context_events ringbuf
           → Go consumeTraceEvents()
           → 格式化 hex trace_id/span_id
           → graph.AddTraceContext(src, dst, TraceContext{TraceID, SpanID, Source})
           → ServiceEdge.RecentTraces (环形缓冲，最多 100 条)
```

**集成效果**：MCP `get_topology` 输出的边数据包含 `recent_traces` 字段，实现"指标 → 拓扑 → trace"三位一体关联。

---

## BPF Verifier 约束与应对

所有 eBPF C 程序必须通过 Linux 内核 BPF verifier 检查：

| 约束 | 应对策略 |
|------|---------|
| **无界循环禁止** | 所有循环次数在编译时确定（如 `for (int i=0; i<16; i++)`） |
| **内存边界检查** | `bpf_probe_read_user` 长度明确，不超过声明的 buffer 大小 |
| **栈大小限制** (512B) | 大 buffer 用 `__builtin_memset` 初始化，减少栈变量 |
| **指令数限制** (1M) | 避免深层嵌套，每个函数独立简短 |
| **禁止浮点运算** | 所有计算使用整数，Go 侧做浮点转换 |
| **禁止动态内存分配** | 仅使用 BPF maps 和 ringbuf |

---

## 添加新探针 Checklist

1. 创建 `bpf/new_probe.c`
2. 在 `cmd/tracer/main.go` 添加 `//go:generate bpf2go new_probe bpf/new_probe.c`
3. 在 `cmd/tracer/types.go` 添加事件 struct
4. 在 `cmd/tracer/app.go` 的 `Start()` 加载探针
5. 添加消费 goroutine `consumeNewProbeEvents(ctx)`
6. 在 `Shutdown()` 添加清理代码
7. 运行 `cd cmd/tracer && go generate ./...`
8. 运行 `go build ./...` 验证编译
9. 用 `sudo bpftool prog list` 确认挂载
