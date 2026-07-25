// bpf/trace_context.c — 分布式追踪上下文提取
//
// 通过 kprobe tcp_sendmsg 读取 HTTP payload，扫描标准 Trace Header，
// 提取 TraceID/SpanID 并注入拓扑事件，实现"指标-拓扑-trace"三位一体。
//
// 支持的 Trace Header:
//   - W3C:   traceparent: 00-<trace_id>-<span_id>-<flags>
//   - Jaeger: uber-trace-id: <trace_id>:<span_id>:...
//   - Datadog: x-datadog-trace-id: <trace_id>

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TRACE_SOURCE_W3C     1
#define TRACE_SOURCE_JAEGER  2
#define TRACE_SOURCE_DATADOG 3
#define TRACE_SOURCE_GENERIC 4

struct ebpf_trace_event {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u32 pid;
	__u64 timestamp_ns;
	__u8  trace_id[16];   // 二进制编码的 TraceID
	__u8  span_id[8];     // 二进制编码的 SpanID
	__u8  trace_source;   // 1=W3C, 2=Jaeger, 3=Datadog, 4=generic
	__u8  pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} trace_context_events SEC(".maps");

// 将 hex 字符转为 4-bit 值
static __always_inline int hex_to_nibble(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

// 将 2 字符 hex 转为 1 字节
static __always_inline int hex_byte(const char *s, __u8 *out) {
	int hi = hex_to_nibble(s[0]);
	int lo = hex_to_nibble(s[1]);
	if (hi < 0 || lo < 0) return -1;
	*out = (__u8)((hi << 4) | lo);
	return 0;
}

// 解析 W3C traceparent: "00-<32 hex trace_id>-<16 hex span_id>-<2 hex flags>"
static __always_inline int parse_w3c_traceparent(const char *buf, int max, __u8 *trace_id, __u8 *span_id) {
	// "traceparent: 00-" 共 16 字符，跳过
	int pos = 0;
	// prefix is "traceparent: 00-";
	int prefix_len = 16;
	if (max < prefix_len + 32 + 1 + 16) return -1;

	// 简单前缀匹配（展开）
	if (buf[0]  != 't') return -1;
	if (buf[1]  != 'r') return -1;
	if (buf[2]  != 'a') return -1;
	if (buf[3]  != 'c') return -1;
	if (buf[4]  != 'e') return -1;
	if (buf[5]  != 'p') return -1;
	if (buf[6]  != 'a') return -1;
	if (buf[7]  != 'r') return -1;
	if (buf[8]  != 'e') return -1;
	if (buf[9]  != 'n') return -1;
	if (buf[10] != 't') return -1;
	if (buf[11] != ':') return -1;
	if (buf[12] != ' ') return -1;
	if (buf[13] != '0') return -1;
	if (buf[14] != '0') return -1;
	if (buf[15] != '-') return -1;
	pos = prefix_len;

	// 读取 32 hex trace_id → 16 bytes
	for (int i = 0; i < 16; i++) {
		if (hex_byte(buf + pos + i*2, &trace_id[i]) < 0) return -1;
	}
	pos += 32;
	if (buf[pos] != '-') return -1;
	pos++;

	// 读取 16 hex span_id → 8 bytes
	for (int i = 0; i < 8; i++) {
		if (hex_byte(buf + pos + i*2, &span_id[i]) < 0) return -1;
	}

	return 0;
}

// 扫描 HTTP header payload 中的 trace header
static __always_inline int scan_trace_headers(const char *buf, int max, __u8 *trace_id, __u8 *span_id, __u8 *source) {
	// 尝试 W3C traceparent
	if (parse_w3c_traceparent(buf, max, trace_id, span_id) == 0) {
		*source = TRACE_SOURCE_W3C;
		return 0;
	}

	// 尝试 Jaeger "uber-trace-id: <trace_hex>:<span_hex>:..."
	if (max > 14 + 36) {
		int match = 1;
		if (buf[0]  != 'u') match = 0;
		if (buf[1]  != 'b') match = 0;
		if (buf[2]  != 'e') match = 0;
		if (buf[3]  != 'r') match = 0;
		if (buf[4]  != '-') match = 0;
		if (buf[5]  != 't') match = 0;
		if (buf[6]  != 'r') match = 0;
		if (buf[7]  != 'a') match = 0;
		if (buf[8]  != 'c') match = 0;
		if (buf[9]  != 'e') match = 0;
		if (buf[10] != '-') match = 0;
		if (buf[11] != 'i') match = 0;
		if (buf[12] != 'd') match = 0;
		if (buf[13] != ':') match = 0;
		if (match) {
			int pos = 14;
			if (buf[pos] == ' ') pos++;
			// trace_id: up to 32 hex chars → 16 bytes
			for (int i = 0; i < 16 && pos + 1 < max; i++) {
				if (buf[pos] == ':') break;
				if (hex_byte(buf + pos, &trace_id[i]) == 0) {
					pos += 2;
				} else {
					break;
				}
			}
			// span_id: after ':' separator
			if (buf[pos] == ':') {
				pos++;
				for (int i = 0; i < 8 && pos + 1 < max; i++) {
					if (buf[pos] == ':' || buf[pos] == '\r' || buf[pos] == '\n') break;
					if (hex_byte(buf + pos, &span_id[i]) == 0) {
						pos += 2;
					} else {
						break;
					}
				}
			}
			*source = TRACE_SOURCE_JAEGER;
			return 0;
		}
	}

	// 尝试 Datadog "x-datadog-trace-id: <decimal_id>"
	if (max > 20) {
		int match = 1;
		if (buf[0]  != 'x') match = 0;
		if (buf[1]  != '-') match = 0;
		if (buf[2]  != 'd') match = 0;
		if (buf[3]  != 'a') match = 0;
		if (buf[4]  != 't') match = 0;
		if (buf[5]  != 'a') match = 0;
		if (buf[6]  != 'd') match = 0;
		if (buf[7]  != 'o') match = 0;
		if (buf[8]  != 'g') match = 0;
		if (buf[9]  != '-') match = 0;
		if (buf[10] != 't') match = 0;
		if (buf[11] != 'r') match = 0;
		if (buf[12] != 'a') match = 0;
		if (buf[13] != 'c') match = 0;
		if (buf[14] != 'e') match = 0;
		if (buf[15] != '-') match = 0;
		if (buf[16] != 'i') match = 0;
		if (buf[17] != 'd') match = 0;
		if (buf[18] != ':') match = 0;
		if (match) {
			int pos = 20;
			if (buf[pos] == ' ') pos++;
			// Datadog trace-id is a decimal uint64 (max 20 digits)
			__u64 dd_id = 0;
			for (int i = 0; i < 20 && pos < max; i++) {
				char c = buf[pos];
				if (c < '0' || c > '9') break;
				dd_id = dd_id * 10 + (__u64)(c - '0');
				pos++;
			}
			// Store as big-endian u64 in first 8 bytes of trace_id
			for (int i = 7; i >= 0; i--) {
				trace_id[i] = (__u8)(dd_id & 0xFF);
				dd_id >>= 8;
			}
			*source = TRACE_SOURCE_DATADOG;
			return 0;
		}
	}

	return -1;
}

SEC("kprobe/tcp_sendmsg")
int kprobe_trace_context(struct pt_regs *ctx) {
	struct sock *sk = (struct sock *)ctx->di;
	if (!sk) return 0;

	// 读取地址信息
	__u32 saddr = 0, daddr = 0;
	__u16 sport = 0, dport = 0;
	__u16 family = 0;
	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
	if (family != 2) return 0;

	BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
	__u16 dport_be;
	BPF_CORE_READ_INTO(&dport_be, sk, __sk_common.skc_dport);
	dport = __builtin_bswap16(dport_be);

	// 读取 payload 前 256 字节（覆盖典型 HTTP header block）
	struct msghdr *msg_hdr = (struct msghdr *)ctx->si;
	if (!msg_hdr) return 0;

	const struct iovec *iov_arr;
	BPF_CORE_READ_INTO(&iov_arr, msg_hdr, msg_iter.__iov);

	struct iovec iov;
	long ret = bpf_probe_read_kernel(&iov, sizeof(iov), iov_arr);
	if (ret < 0) return 0;

	char payload[256];
	__builtin_memset(payload, 0, sizeof(payload));
	int read_len = sizeof(payload) < iov.iov_len ? sizeof(payload) : (int)iov.iov_len;
	ret = bpf_probe_read_user(payload, read_len, iov.iov_base);
	if (ret < 0) return 0;

	// 扫描 trace headers
	__u8 trace_id[16] = {};
	__u8 span_id[8] = {};
	__u8 source = 0;
	if (scan_trace_headers(payload, sizeof(payload), trace_id, span_id, &source) < 0) {
		return 0;
	}

	struct ebpf_trace_event *evt = bpf_ringbuf_reserve(&trace_context_events, sizeof(*evt), 0);
	if (!evt) return 0;

	evt->saddr = saddr;
	evt->daddr = daddr;
	evt->sport = sport;
	evt->dport = dport;
	evt->pid = bpf_get_current_pid_tgid() >> 32;
	evt->timestamp_ns = bpf_ktime_get_ns();
	evt->trace_source = source;
	__builtin_memcpy(evt->trace_id, trace_id, 16);
	__builtin_memcpy(evt->span_id, span_id, 8);

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
