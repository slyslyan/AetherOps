// bpf/tcp_rtt.c — TCP RTT via kernel SRTT (cilium/ebpf tcprtt pattern)
//
// Reference: cilium/ebpf examples/tcprtt (MIT License)
// github.com/cilium/ebpf/tree/main/examples/tcprtt
//
// Uses fentry/tcp_close to read the kernel's smoothed RTT (srtt_us)
// directly from tcp_sock. The kernel TCP stack maintains srtt_us from
// ACK round-trip timing — more reliable than manual send/recv pairing.
//
// Requirements: Linux 5.5+ with BTF (for fentry + CO-RE)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct net_event {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8  pad[2];
	__u64 delta;    // srtt_us >> 3 * 1000 (microseconds → nanoseconds)
	__u32 pid;
	__u8  comm[16];
	__u8  pad2[4];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} rtt_events SEC(".maps");

// Per-flow rate limit to avoid flooding the ring buffer on close storms.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);   // flow hash
	__type(value, __u64); // last emission ns
} rtt_rate_limit SEC(".maps");

// Sampling config map (user-space writable, key=0 → interval_ns).
// Kept for Go-side adaptive sampling compatibility; unused in fentry path.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} rtt_sampling_config SEC(".maps");

static __u64 flow_key(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport) {
	return (__u64)saddr ^ (__u64)daddr ^ ((__u64)sport << 16) ^ (__u64)dport;
}

SEC("fentry/tcp_close")
int BPF_PROG(tcp_close, struct sock *sk)
{
	if (!sk)
		return 0;

	// Read kernel SRTT — smoothed RTT in microseconds (<<3).
	// A value of 0 means the TCP stack hasn't gathered enough samples.
	__u32 srtt_us = BPF_CORE_READ((struct tcp_sock *)sk, srtt_us);
	if (srtt_us == 0)
		return 0;

	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != 2) // AF_INET only
		return 0;

	__u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	__u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	__u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	__u16 dport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));

	// Apply per-flow rate limit (1s).
	__u64 fk = flow_key(saddr, daddr, sport, dport);
	__u64 *last = bpf_map_lookup_elem(&rtt_rate_limit, &fk);
	__u64 now = bpf_ktime_get_ns();
	if (last && (now - *last) < 1000000000ULL) // 1 second
		return 0;
	bpf_map_update_elem(&rtt_rate_limit, &fk, &now, BPF_ANY);

	// srtt_us is microseconds << 3 → convert to nanoseconds.
	__u64 rtt_ns = (__u64)(srtt_us >> 3) * 1000;

	struct net_event *evt = bpf_ringbuf_reserve(&rtt_events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	__builtin_memset(evt, 0, sizeof(*evt));
	evt->saddr = saddr;
	evt->daddr = daddr;
	evt->sport = sport;
	evt->dport = dport;
	evt->family = family;
	evt->delta = rtt_ns;
	evt->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

	bpf_ringbuf_submit(evt, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
