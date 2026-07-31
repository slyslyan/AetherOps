// bpf/http_probe.c — HTTP/gRPC uprobe 探针
//
// Reference design pattern: Pixie Stirling HTTP protocol detection (pixie-io/pixie)
// Implementation written independently, no source code copied.
//
// 通过 uprobe 挂载 Go HTTP/gRPC 函数，解析请求路径、方法、状态码
//
// Go 1.17+ 寄存器 ABI (amd64):
//   Arg0 (receiver / first param) -> RAX
//   Arg1 -> RBX
//   Arg2 -> RCX
//   Arg3 -> RDI
//   Arg4 -> RSI
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// HTTP 事件结构体
struct http_event {
    __u32 pid;
    __u64 timestamp_ns;
    __u32 status_code;
    __u16 method;        // 1=GET, 2=POST, 3=PUT, 4=DELETE
    __u8  path[128];
    __u8  host[64];
    __u32 duration_ns;
};

// 存储请求开始时间 (key = pid_tgid, value = timestamp_ns)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, __u64);
} http_start SEC(".maps");

// HTTP 事件 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} http_events SEC(".maps");

// ---------- HTTP 服务端 ----------

// 挂钩 net/http.(*conn).readRequest 入口 — 记录请求开始时间
// 符号: net/http.(*conn).readRequest
SEC("uprobe")
int uprobe_http_read_request(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&http_start, &pid_tgid, &ts, BPF_ANY);
    return 0;
}

// 挂钩 net/http.(*response).WriteHeader 入口 — 捕获 HTTP 状态码
// Go: func (r *response) WriteHeader(statusCode int)
// 寄存器: receiver->AX, statusCode->BX
SEC("uprobe")
int uprobe_http_write_header(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *start_ts = bpf_map_lookup_elem(&http_start, &pid_tgid);
    if (!start_ts) return 0;

    // Go arg1 (statusCode) -> RBX
    int status_code = (int)ctx->bx;
    __u64 now = bpf_ktime_get_ns();

    struct http_event *evt = bpf_ringbuf_reserve(&http_events, sizeof(*evt), 0);
    if (!evt) return 0;

    evt->pid = pid_tgid >> 32;
    evt->timestamp_ns = *start_ts;
    evt->status_code = status_code;
    evt->method = 0;
    evt->duration_ns = (__u32)(now - *start_ts);
    __builtin_memset(evt->path, 0, sizeof(evt->path));
    __builtin_memset(evt->host, 0, sizeof(evt->host));

    bpf_ringbuf_submit(evt, 0);
    bpf_map_delete_elem(&http_start, &pid_tgid);
    return 0;
}

// ---------- gRPC 客户端调用 ----------

// 挂钩 google.golang.org/grpc.(*ClientConn).Invoke 入口
// 捕获 gRPC 调用的 method 字符串
// 符号: google.golang.org/grpc.(*ClientConn).Invoke
SEC("uprobe")
int uprobe_grpc_invoke(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();

    // Go string 在寄存器 ABI 中: {data uintptr, len int}
    // method 是 Arg2 (RCX) -> string.data, string.len 在下一个 slot
    // 但 Go 的寄存器分配会更复杂: context.Context (interface{})
    // 占 2 个 slot (type, value), 所以 method (string) 从 Arg2=RCX 开始
    // method.data 在 RCX
    __u64 method_ptr = (__u64)ctx->cx;

    struct http_event *evt = bpf_ringbuf_reserve(&http_events, sizeof(*evt), 0);
    if (!evt) return 0;

    evt->pid = pid_tgid >> 32;
    evt->timestamp_ns = ts;
    evt->status_code = 0;
    evt->duration_ns = 0;
    evt->method = 0;
    __builtin_memset(evt->path, 0, sizeof(evt->path));
    __builtin_memset(evt->host, 0, sizeof(evt->host));

    if (method_ptr != 0) {
        bpf_probe_read_user_str(evt->path, sizeof(evt->path), (void *)method_ptr);
    }

    bpf_map_update_elem(&http_start, &pid_tgid, &ts, BPF_ANY);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
