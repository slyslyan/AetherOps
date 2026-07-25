// bpf/proto_classifier.c — 应用协议自动发现
//
// 通过 kprobe tcp_sendmsg 读取 payload 前若干字节的 magic bytes，
// 自动识别协议类型并标注拓扑边。不解析协议内容，仅做分类。
//
// 识别的协议:
//   - HTTP/1.x: 以 "GET"/"POST"/"PUT"/"DELETE"/"HEAD"/"PATCH"/"HTTP/" 开头的文本
//   - HTTP/2:   连接前导 "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
//   - Redis:    RESP 协议 '*' 前缀
//   - MySQL:    MySQL 二进制包头（3 字节长度 + 1 字节 seq）+ 端口 3306

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 协议类型枚举
#define PROTO_UNKNOWN 0
#define PROTO_HTTP1   1
#define PROTO_HTTP2   2
#define PROTO_MYSQL   3
#define PROTO_REDIS   4

struct proto_event {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8  detected_proto;
	__u8  confidence;
	__u8  pad[2];
	__u32 pid;
	__u8  comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} proto_events SEC(".maps");

// 检查是否为 HTTP/1.x 方法前缀
static __always_inline int is_http1_method(const char *buf) {
	// GET /, POST /, PUT /, DELETE /, HEAD /, PATCH /
	if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' ') return 1;
	if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T' && buf[4] == ' ') return 1;
	if (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T' && buf[3] == ' ') return 1;
	if (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E' && buf[4] == 'T' && buf[5] == 'E' && buf[6] == ' ') return 1;
	if (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D' && buf[4] == ' ') return 1;
	if (buf[0] == 'P' && buf[1] == 'A' && buf[2] == 'T' && buf[3] == 'C' && buf[4] == 'H' && buf[5] == ' ') return 1;
	// HTTP/1.x response: "HTTP/1."
	if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P' && buf[4] == '/' && buf[5] == '1' && buf[6] == '.') return 1;
	return 0;
}

// 检查是否为 HTTP/2 连接前导
static __always_inline int is_http2_preface(const char *buf) {
	// "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" (24 bytes)
	if (buf[0]  != 'P') return 0;
	if (buf[1]  != 'R') return 0;
	if (buf[2]  != 'I') return 0;
	if (buf[3]  != ' ') return 0;
	if (buf[4]  != '*') return 0;
	if (buf[5]  != ' ') return 0;
	if (buf[6]  != 'H') return 0;
	if (buf[7]  != 'T') return 0;
	if (buf[8]  != 'T') return 0;
	if (buf[9]  != 'P') return 0;
	if (buf[10] != '/') return 0;
	if (buf[11] != '2') return 0;
	return 1;
}

// 检查是否为 Redis RESP 协议
static __always_inline int is_redis_resp(const char *buf) {
	return (buf[0] == '*' && buf[1] >= '0' && buf[1] <= '9');
}

static __always_inline int classify_proto(const char *buf, int buf_max, __u16 dport) {
	if (buf_max < 12) return PROTO_UNKNOWN;

	if (is_http2_preface(buf)) return PROTO_HTTP2;
	if (is_http1_method(buf)) return PROTO_HTTP1;
	if (is_redis_resp(buf)) return PROTO_REDIS;

	// MySQL 端口启发式：3306 端口且二进制包头 (3 字节小端长度 < 16MB)
	// MySQL 包头: 3 字节 payload 长度 (max 16MB-1) + 1 字节 sequence_id
	if (dport == 3306) {
		__u32 pkt_len = (__u8)buf[0] | ((__u8)buf[1] << 8) | ((__u8)buf[2] << 16);
		if (pkt_len > 0 && pkt_len < 0xFFFFFF) {
			return PROTO_MYSQL;
		}
	}

	return PROTO_UNKNOWN;
}

static __always_inline void fill_comm(char *dst, int max) {
	// bpf_get_current_comm fills up to 16 bytes
	bpf_get_current_comm(dst, max > 16 ? 16 : max);
}

SEC("kprobe/tcp_sendmsg")
int kprobe_proto_classify(struct pt_regs *ctx) {
	struct sock *sk = (struct sock *)ctx->di;
	if (!sk) return 0;

	// 读取地址信息
	__u32 saddr = 0, daddr = 0;
	__u16 sport = 0, dport = 0;
	__u16 family = 0;
	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);

	if (family == 2) {
		BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
	} else {
		return 0;
	}

	BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
	__u16 dport_be;
	BPF_CORE_READ_INTO(&dport_be, sk, __sk_common.skc_dport);
	dport = __builtin_bswap16(dport_be);

	// 读取 payload 前 32 字节
	struct msghdr *msg_hdr = (struct msghdr *)ctx->si;
	if (!msg_hdr) return 0;

	const struct iovec *iov_arr;
	BPF_CORE_READ_INTO(&iov_arr, msg_hdr, msg_iter.__iov);

	struct iovec iov;
	long ret = bpf_probe_read_kernel(&iov, sizeof(iov), iov_arr);
	if (ret < 0) return 0;

	char payload[32];
	__builtin_memset(payload, 0, sizeof(payload));
	ret = bpf_probe_read_user(payload, sizeof(payload) < iov.iov_len ? sizeof(payload) : iov.iov_len, iov.iov_base);
	if (ret < 0) return 0;

	int proto = classify_proto(payload, sizeof(payload), dport);
	if (proto == PROTO_UNKNOWN) return 0;

	struct proto_event *evt = bpf_ringbuf_reserve(&proto_events, sizeof(*evt), 0);
	if (!evt) return 0;

	evt->saddr = saddr;
	evt->daddr = daddr;
	evt->sport = sport;
	evt->dport = dport;
	evt->detected_proto = (__u8)proto;
	evt->confidence = 80; // 启发式，默认 80% 置信度
	evt->pid = bpf_get_current_pid_tgid() >> 32;
	fill_comm((char *)evt->comm, sizeof(evt->comm));

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
