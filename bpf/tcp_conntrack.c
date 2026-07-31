// bpf/tcp_conntrack.c — TCP connection lifecycle tracking via tracepoint
//
// Reference: iovisor/bcc libbpf-tools/tcpstates (BSD-2 License)
// Adapted from BCC tcpstates tracepoint pattern.
//
// Uses tracepoint/sock/inet_sock_set_state instead of kprobe, which:
//   - Catches all TCP state transitions (connect, accept, close)
//   - Provides sport/dport/family/saddr/daddr directly (no BPF_CORE_READ needed)
//   - Works on kernels where kprobe is restricted

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// TCP state constants (enum tcp_state from kernel, not always in vmlinux.h).
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_SYN_RECV    3
#define TCP_FIN_WAIT1   4
#define TCP_CLOSE_WAIT  8
#define TCP_LAST_ACK    9

struct conn_event {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8  role;
	__u8  pad;
	__u64 duration_ns;
	__u32 pid;
	__u8  comm[16];
	__u8  pad2[4];
};

struct conn_info {
	__u64 start_ns;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u32 pid;
	__u8  role;
};

// Track in-flight connections by socket pointer.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, __u64);
	__type(value, struct conn_info);
} conn_track SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} conn_events SEC(".maps");

// Per-flow rate limit (1 emission per second).
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u64);
} conn_rate_limit SEC(".maps");

static __u64 flow_hash(__u32 sa, __u32 da, __u16 sp, __u16 dp) {
	return (__u64)sa ^ (__u64)da ^ ((__u64)sp << 16) ^ (__u64)dp;
}

// Convert tracepoint __u8[4] saddr to little-endian uint32.
// The tracepoint stores the raw big-endian bytes from inet_saddr.
// Go side reads via binary.LittleEndian + uint32ToIP, so the uint32
// must be byte-reversed: IP 10.0.0.1 → bytes 0A 00 00 01 → uint32 0x0100000A.
static __always_inline __u32 ipv4_from_bytes(const __u8 addr[4]) {
	return ((__u32)addr[0]) |
	       ((__u32)addr[1] << 8) |
	       ((__u32)addr[2] << 16) |
	       ((__u32)addr[3] << 24);
}

SEC("tracepoint/sock/inet_sock_set_state")
int tp_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	int oldstate = ctx->oldstate;
	int newstate = ctx->newstate;

	if (ctx->family != 2)  // AF_INET only
		return 0;

	__u64 sk_ptr = (__u64)ctx->skaddr;
	if (!sk_ptr)
		return 0;

	// ── Connection established: record start time ──
	if (newstate == TCP_ESTABLISHED) {
		struct conn_info info = {};
		info.start_ns = bpf_ktime_get_ns();
		info.family = ctx->family;
		info.sport = ctx->sport;
		info.dport = ctx->dport;
		info.saddr = ipv4_from_bytes(ctx->saddr);
		info.daddr = ipv4_from_bytes(ctx->daddr);
		info.pid = bpf_get_current_pid_tgid() >> 32;

		// Determine role from previous state:
		// SYN_SENT → ESTABLISHED = client (active open, role=1)
		// SYN_RECV → ESTABLISHED = server (passive accept, role=2)
		info.role = (oldstate == TCP_SYN_SENT) ? 1 : 2;

		bpf_map_update_elem(&conn_track, &sk_ptr, &info, BPF_ANY);
		return 0;
	}

	// ── Connection closing: compute duration, emit event ──
	if (oldstate != TCP_ESTABLISHED)
		return 0;
	if (newstate != TCP_FIN_WAIT1 && newstate != TCP_CLOSE_WAIT &&
	    newstate != TCP_LAST_ACK)
		return 0;

	struct conn_info *info = bpf_map_lookup_elem(&conn_track, &sk_ptr);
	if (!info)
		return 0;

	__u64 now = bpf_ktime_get_ns();
	__u64 duration_ns = now - info->start_ns;

	// Rate limit: one emission per flow per second.
	__u64 fk = flow_hash(info->saddr, info->daddr, info->sport, info->dport);
	__u64 *last = bpf_map_lookup_elem(&conn_rate_limit, &fk);
	if (last && (now - *last) < 1000000000ULL)
		goto cleanup;
	bpf_map_update_elem(&conn_rate_limit, &fk, &now, BPF_ANY);

	// Skip connections shorter than 1ms (failed / aborted).
	if (duration_ns < 1000000ULL)
		goto cleanup;

	struct conn_event *evt = bpf_ringbuf_reserve(&conn_events, sizeof(*evt), 0);
	if (!evt)
		goto cleanup;

	__builtin_memset(evt, 0, sizeof(*evt));
	evt->saddr = info->saddr;
	evt->daddr = info->daddr;
	evt->sport = info->sport;
	evt->dport = info->dport;
	evt->family = info->family;
	evt->role = info->role;
	evt->duration_ns = duration_ns;
	evt->pid = info->pid;
	bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

	bpf_ringbuf_submit(evt, 0);

cleanup:
	bpf_map_delete_elem(&conn_track, &sk_ptr);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
