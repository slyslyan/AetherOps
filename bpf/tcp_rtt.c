// bpf/tcp_rtt.c — Request-level RTT via tcp_sendmsg → tcp_recvmsg
//
// Hooks tcp_sendmsg to record the send timestamp and tcp_recvmsg kretprobe
// to compute the real request-response round-trip time. Keyed by sk_ptr so
// the same socket's send and recv are correctly paired, even with connection
// pooling where tcp_close never fires.
//
// This fills the blind spot left by tcp_conntrack (which only measures
// connection lifetime) for long-lived pooled connections (MySQL, Redis, etc.).

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
    __u64 delta;
    __u32 pid;
    __u8  comm[16];
    __u8  pad2[4];
};

struct rtt_track_info {
    __u64 send_ts_ns;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u32 pid;
};

// Track in-flight sends by socket pointer.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct rtt_track_info);
} rtt_track SEC(".maps");

// Output ring buffer — same net_event format as net_trace.c for zero Go-side changes.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rtt_events SEC(".maps");

// Per-flow sampling rate limit (100 µs).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} rtt_rate_limit SEC(".maps");

const __u64 rtt_sampling_interval_ns = 100000; // 100 µs — RTT events are sparser than sendmsg

static __u64 rtt_flow_key(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport) {
    return (__u64)saddr ^ (__u64)daddr ^ ((__u64)sport << 16) ^ (__u64)dport;
}

static int rtt_should_sample(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport) {
    __u64 key = rtt_flow_key(saddr, daddr, sport, dport);
    __u64 *last = bpf_map_lookup_elem(&rtt_rate_limit, &key);
    __u64 now = bpf_ktime_get_ns();
    if (last && (now - *last) < rtt_sampling_interval_ns) return 0;
    __u64 val = now;
    bpf_map_update_elem(&rtt_rate_limit, &key, &val, BPF_ANY);
    return 1;
}

// ---------- kprobe/tcp_sendmsg — record send timestamp ----------

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg_rtt(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)ctx->di;
    if (!sk) return 0;

    __u64 sk_ptr = (__u64)sk;
    struct rtt_track_info info = {};
    info.send_ts_ns = bpf_ktime_get_ns();
    info.pid = bpf_get_current_pid_tgid() >> 32;

    BPF_CORE_READ_INTO(&info.family, sk, __sk_common.skc_family);
    if (info.family == 2) {
        BPF_CORE_READ_INTO(&info.saddr, sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&info.daddr, sk, __sk_common.skc_daddr);
    } else if (info.family == 10) {
        struct in6_addr v6_rcv, v6_dst;
        BPF_CORE_READ_INTO(&v6_rcv, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&v6_dst, sk, __sk_common.skc_v6_daddr);
        info.saddr = v6_rcv.in6_u.u6_addr32[3];
        info.daddr = v6_dst.in6_u.u6_addr32[3];
    } else {
        return 0;
    }

    BPF_CORE_READ_INTO(&info.sport, sk, __sk_common.skc_num);
    __u16 dport_be;
    BPF_CORE_READ_INTO(&dport_be, sk, __sk_common.skc_dport);
    info.dport = __builtin_bswap16(dport_be);

    bpf_map_update_elem(&rtt_track, &sk_ptr, &info, BPF_ANY);
    return 0;
}

// ---------- kretprobe/tcp_recvmsg — compute RTT ----------

SEC("kretprobe/tcp_recvmsg")
int kretprobe_tcp_recvmsg_rtt(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)ctx->di;
    if (!sk) return 0;

    __u64 sk_ptr = (__u64)sk;
    struct rtt_track_info *info = bpf_map_lookup_elem(&rtt_track, &sk_ptr);
    if (!info) return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 delta_ns = now - info->send_ts_ns;

    // Skip implausibly long RTT (>30 s, likely keep-alive / idle timeout).
    if (delta_ns > 30000000000ULL) {
        bpf_map_delete_elem(&rtt_track, &sk_ptr);
        return 0;
    }

    if (rtt_should_sample(info->saddr, info->daddr, info->sport, info->dport)) {
        struct net_event *evt = bpf_ringbuf_reserve(&rtt_events, sizeof(*evt), 0);
        if (evt) {
            evt->saddr = info->saddr;
            evt->daddr = info->daddr;
            evt->sport = info->sport;
            evt->dport = info->dport;
            evt->family = info->family;
            evt->delta = delta_ns;
            evt->pid = info->pid;
            bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
            bpf_ringbuf_submit(evt, 0);
        }
    }

    bpf_map_delete_elem(&rtt_track, &sk_ptr);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
