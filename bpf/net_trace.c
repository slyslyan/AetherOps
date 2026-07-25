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

struct send_meta {
    __u64 ts;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u16 family;
};

// 入口存储：pid_tgid -> send_meta
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct send_meta);
} entry_store SEC(".maps");

// 事件 Ring Buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// ---------- 采样/去重 ----------
// flow_key = saddr ^ daddr ^ (sport<<16) ^ dport
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   // flow hash
    __type(value, __u64); // last emission ns
} rate_limit SEC(".maps");

// 采样配置 map（用户态可写，key=0 → value=采样间隔纳秒）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sampling_config SEC(".maps");

// 默认采样间隔 100ms
const __u64 default_sampling_interval_ns = 100000000;

static __u64 make_flow_key(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport) {
    return (__u64)saddr ^ (__u64)daddr ^ ((__u64)sport << 16) ^ (__u64)dport;
}

static int should_sample(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport) {
    __u64 key = make_flow_key(saddr, daddr, sport, dport);
    __u64 *last = bpf_map_lookup_elem(&rate_limit, &key);
    __u64 now = bpf_ktime_get_ns();
    __u32 cfg_key = 0;
    __u64 *interval_ptr = bpf_map_lookup_elem(&sampling_config, &cfg_key);
    __u64 interval_ns = interval_ptr ? *interval_ptr : default_sampling_interval_ns;
    if (last && (now - *last) < interval_ns) {
        return 0;
    }
    __u64 val = now;
    bpf_map_update_elem(&rate_limit, &key, &val, BPF_ANY);
    return 1;
}

// ---------- kprobe ----------
SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)ctx->di;
    if (!sk) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct send_meta meta = {};
    meta.ts = bpf_ktime_get_ns();

    BPF_CORE_READ_INTO(&meta.family, sk, __sk_common.skc_family);

    if (meta.family == 2) {
        BPF_CORE_READ_INTO(&meta.saddr, sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&meta.daddr, sk, __sk_common.skc_daddr);
    } else if (meta.family == 10) {
        struct in6_addr v6_rcv, v6_dst;
        BPF_CORE_READ_INTO(&v6_rcv, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&v6_dst, sk, __sk_common.skc_v6_daddr);
        meta.saddr = v6_rcv.in6_u.u6_addr32[3];
        meta.daddr = v6_dst.in6_u.u6_addr32[3];
    } else {
        return 0;
    }

    BPF_CORE_READ_INTO(&meta.sport, sk, __sk_common.skc_num);
    __u16 dport_be;
    BPF_CORE_READ_INTO(&dport_be, sk, __sk_common.skc_dport);
    meta.dport = __builtin_bswap16(dport_be);

    bpf_map_update_elem(&entry_store, &pid_tgid, &meta, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe_tcp_sendmsg(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct send_meta *meta = bpf_map_lookup_elem(&entry_store, &pid_tgid);
    if (!meta) return 0;

    // 采样/去重检查
    if (!should_sample(meta->saddr, meta->daddr, meta->sport, meta->dport)) {
        bpf_map_delete_elem(&entry_store, &pid_tgid);
        return 0;
    }

    struct net_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) {
        bpf_map_delete_elem(&entry_store, &pid_tgid);
        return 0;
    }

    evt->saddr = meta->saddr;
    evt->daddr = meta->daddr;
    evt->sport = meta->sport;
    evt->dport = meta->dport;
    evt->family = meta->family;
    evt->delta = bpf_ktime_get_ns() - meta->ts;
    evt->pid = pid_tgid >> 32;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);
    bpf_map_delete_elem(&entry_store, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
