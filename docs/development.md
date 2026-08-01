# 开发指南

## 本地环境搭建

### 基础依赖

```bash
# Go 1.24+
go version

# clang + llvm (编译 eBPF)
sudo apt install clang llvm libbpf-dev

# bpftool (调试)
sudo apt install linux-tools-$(uname -r)

# bpf2go (生成 Go bindings)
go install github.com/cilium/ebpf/cmd/bpf2go@latest
```

### 克隆和构建

```bash
git clone <repo-url>
cd ebpfagent

# 生成 eBPF Go bindings
make generate

# 构建
make build

# 运行测试
make test

# 格式化和检查
make fmt
make lint
```

---

## 项目结构约定

### Go 侧

```
cmd/tracer/          应用程序入口，不含业务逻辑
internal/            所有业务逻辑，外部不可导入
  config/            单一 Config struct + LoadFromEnv()
  detection/         异常检测 + 根因分析 + 专家规则
  graph/             ServiceGraph (线程安全)
  mcp/               MCP Server (mark3labs/mcp-go)
  metrics/           Prometheus 指标注册 (init())
  remediation/       自愈执行 + 策略引擎 + 安全门控
  resolver/          服务名解析 (PID → 进程名)
```

**编码规范**：
- 不写 Java-style getter/setter，直接暴露字段
- 无注释优于冗余注释。只注释 WHY 不注释 WHAT
- 错误用 `fmt.Errorf("context (%v): %w", val, sentinel)` 包装，保留链
- 并发安全通过 `sync.RWMutex` 保证，不加额外 channel 同步

### eBPF C

```
bpf/
  net_trace.c         主探针
  tcp_conntrack.c     连接跟踪
  tcp_rtt.c           内核 SRTT (fentry)
  tc_drop.c           TC 丢包
  http_probe.c        HTTP uprobe
  redis_trace.c       Redis 协议
  proto_classifier.c  协议自动发现
  trace_context.c     Trace 上下文提取
```

**C 编码规范**：
- 所有循环在编译时确定次数（`for (int i = 0; i < 16; i++)`）
- 字符串比较展开为逐字节检查，不使用 `__builtin_memcmp`
- 函数标记 `static __always_inline` 以强制内联
- 栈 buffer 使用 `__builtin_memset` 初始化
- BPF maps 声明用 SEC 宏标记段

### Python 侧

```
python/src/aetherops/
  core/               MCP 客户端 + LLM Provider + 诊断
  workflows/          Multi-Agent 工作流
```

---

## 添加新 eBPF 探针

### Step 1: 编写 eBPF C 程序

```c
// bpf/my_probe.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct my_event {
    __u32 pid;
    __u64 timestamp_ns;
    // ... 自定义字段
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB
} my_events SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int kprobe_my_probe(struct pt_regs *ctx) {
    // 1. 读取 socket 信息
    // 2. 读取 payload
    // 3. 填充事件结构
    // 4. ringbuf reserve + submit
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### Step 2: 生成 Go bindings

在 `cmd/tracer/main.go` 添加：

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" my_probe ../../bpf/my_probe.c -- -I/usr/include/bpf -I../../
```

运行生成：

```bash
cd cmd/tracer && go generate ./...
# 生成: cmd/tracer/my_probe_bpfel.go, cmd/tracer/my_probe_bpfeb.go
```

### Step 3: 添加事件结构

在 `cmd/tracer/types.go`：

```go
type myEventRaw struct {
    Pid         uint32
    TimestampNs uint64
    // 字段顺序和 C struct 严格一致，LittleEndian
}
```

### Step 4: 集成到 App

在 `cmd/tracer/app.go`：

```go
// App struct 添加字段
type App struct {
    // ...
    myObjs my_probeObjects
    myRd   *ringbuf.Reader
}

// Start() 中添加加载逻辑
func (a *App) Start(ctx context.Context) error {
    // ...
    myObjs := my_probeObjects{}
    if err := loadMy_probeObjects(&myObjs, nil); err != nil {
        slog.Info(fmt.Sprintf("my_probe load failed: %v", err))
    } else {
        a.myObjs = myObjs
        kp, err := link.Kprobe("tcp_sendmsg", myObjs.KprobeMyProbe, nil)
        if err != nil {
            // cleanup
        } else {
            rd, _ := ringbuf.NewReader(myObjs.MyEvents)
            a.myRd = rd
            go a.consumeMyEvents(ctx)
        }
    }
    // ...
}

// Shutdown() 中添加清理
func (a *App) Shutdown(ctx context.Context) {
    if a.myRd != nil { a.myRd.Close() }
    if a.myObjs.KprobeMyProbe != nil { a.myObjs.Close() }
}
```

### Step 5: 消费 goroutine

```go
func (a *App) consumeMyEvents(ctx context.Context) {
    if a.myRd == nil { return }
    for {
        select {
        case <-ctx.Done(): return
        default:
        }
        record, err := a.myRd.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) { return }
            slog.Warn(fmt.Sprintf("my_probe ringbuf read failed: %v", err))
            continue
        }
        var evt myEventRaw
        if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
            continue
        }
        // 处理事件...
    }
}
```

---

## 代码生成

```bash
# 完整重新生成所有 eBPF Go bindings
cd cmd/tracer
rm -f *_bpfel.go *_bpfeb.go *.o
go generate ./...

# 仅生成某个探针
go generate -run my_probe ./...
```

---

## 测试

### Go 测试

```bash
# 所有内部包
go test ./internal/...

# 详细输出
go test -v ./internal/...

# 指定包
go test -v ./internal/remediation/

# 覆盖率
go test -cover ./internal/...
```

### eBPF 验证

```bash
# 检查 BPF 程序加载状态
sudo bpftool prog list | grep -A5 'tcp_sendmsg\|tcp_close\|inet_sock_set_state'

# 检查 map 数据
sudo bpftool map dump name events
sudo bpftool map dump name sampling_config

# 检查 TC 规则
sudo tc filter show dev eth0 egress

# 查看 BPF 日志
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### 手动验证数据通路

```bash
# 1. 启动 agent（模拟模式）
sudo SIMULATE_LATENCY=1 ./ebpf-local &

# 2. 检查指标
curl -s localhost:2112/metrics | grep 'ebpf_edge_calls_total\|ebpf_agent_up'

# 3. 触发异常（发送大量请求到本地服务）
ab -n 10000 -c 100 http://localhost:8080/

# 4. 观察异常检测日志
# 应出现: "Anomaly detected: ..." 或 "Expert rule matched: ..."

# 5. 检查 MCP
curl -s localhost:50052/healthz
```

---

## 调试

### 日志

所有日志通过 `slog` 输出到 stderr：

```bash
# 按级别过滤
sudo ./ebpf-local 2>&1 | grep -E 'WARN|Anomaly|matched'

# 实时查看拓扑
sudo ./ebpf-local 2>&1 | grep 'Call Topology' -A 50
```

### Prometheus

```bash
# 查看所有 eBPF 指标
curl -s localhost:2112/metrics | grep '^ebpf_'

# 检查组件健康
curl -s localhost:2112/metrics | grep 'ebpf_agent_health'
```

### Go pprof

```bash
# 如果编译了 net/http/pprof
go tool pprof http://localhost:6060/debug/pprof/heap
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=10
```

---

## 发布 checklist

1. `make test` — 所有测试通过
2. `make lint` — go vet 无报错
3. `make generate` — eBPF bindings 最新
4. `go build -o /dev/null ./cmd/tracer/` — 编译成功
5. 手测 `sudo ./ebpf-local` — 无 panic
6. `curl localhost:2112/metrics | grep ebpf_agent_up` — 返回 1
7. `curl localhost:50052/healthz` — 返回 ok
8. 审查 `git diff --stat` 确认变更范围
9. 更新 CHANGELOG.md
