// bpf/redis_trace.c — Redis RESP 协议解析探针
//
// 通过 kprobe tcp_sendmsg 拦截 Redis 请求，解析 RESP 首行提取命令名。
// 仅提取前 16 字节命令名（GET/SET/MGET 等），不做全量 key/value 解析。
//
// RESP 格式: *<argc>\r\n$<len>\r\n<command>\r\n...
// 例: *3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct redis_event {
	__u32 pid;
	__u32 data_len;
	__u64 timestamp_ns;
	__u8  command[16];
	__u8  pad[4];
};

// 可配置 Redis 端口（默认 6379）
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u16);
} redis_ports SEC(".maps");

// Redis 事件 Ring Buffer
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} redis_events SEC(".maps");

// RESP 命令名前缀表（用于快速分类，展开比较，无循环）
// 常见命令: GET, SET, MGET, MSET, DEL, EXPIRE, INCR, DECR, LPUSH, RPUSH,
//           LPOP, RPOP, HGET, HSET, HGETALL, EVAL, PING, AUTH, SELECT
static __always_inline int match_command(const char *buf, int len) {
	// 单字符命令（不存在于 Redis）
	// 两字符命令: 无常见
	// 三字符: GET, SET, DEL, INCR
	if (len >= 3) {
		if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T')  return 1;  // GET
		if (buf[0] == 'S' && buf[1] == 'E' && buf[2] == 'T')  return 2;  // SET
		if (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L')  return 3;  // DEL
	}
	// 四字符: MGET, MSET, INCR, DECR, LPOP, RPOP, EVAL, HGET, HSET, PING, AUTH
	if (len >= 4) {
		if (buf[0] == 'M' && buf[1] == 'G' && buf[2] == 'E' && buf[3] == 'T') return 4;   // MGET
		if (buf[0] == 'M' && buf[1] == 'S' && buf[2] == 'E' && buf[3] == 'T') return 5;   // MSET
		if (buf[0] == 'I' && buf[1] == 'N' && buf[2] == 'C' && buf[3] == 'R') return 6;   // INCR
		if (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'C' && buf[3] == 'R') return 7;   // DECR
		if (buf[0] == 'L' && buf[1] == 'P' && buf[2] == 'O' && buf[3] == 'P') return 8;   // LPOP
		if (buf[0] == 'R' && buf[1] == 'P' && buf[2] == 'O' && buf[3] == 'P') return 9;   // RPOP
		if (buf[0] == 'E' && buf[1] == 'V' && buf[2] == 'A' && buf[3] == 'L') return 10;  // EVAL
		if (buf[0] == 'H' && buf[1] == 'G' && buf[2] == 'E' && buf[3] == 'T') return 11;  // HGET
		if (buf[0] == 'H' && buf[1] == 'S' && buf[2] == 'E' && buf[3] == 'T') return 12;  // HSET
		if (buf[0] == 'P' && buf[1] == 'I' && buf[2] == 'N' && buf[3] == 'G') return 13;  // PING
		if (buf[0] == 'A' && buf[1] == 'U' && buf[2] == 'T' && buf[3] == 'H') return 14;  // AUTH
	}
	// 五字符: LPUSH, RPUSH, EXPIRE, DECR, SELECT
	if (len >= 5) {
		if (buf[0] == 'L' && buf[1] == 'P' && buf[2] == 'U' && buf[3] == 'S' && buf[4] == 'H') return 15; // LPUSH
		if (buf[0] == 'R' && buf[1] == 'P' && buf[2] == 'U' && buf[3] == 'S' && buf[4] == 'H') return 16; // RPUSH
		if (buf[0] == 'S' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E' && buf[4] == 'C' && len >= 6 && buf[5] == 'T') return 17; // SELECT
	}
	// 六字符: EXPIRE, HGETALL
	if (len >= 6) {
		if (buf[0] == 'E' && buf[1] == 'X' && buf[2] == 'P' && buf[3] == 'I' && buf[4] == 'R' && buf[5] == 'E') return 18; // EXPIRE
		if (buf[0] == 'H' && buf[1] == 'G' && buf[2] == 'E' && buf[3] == 'T' && buf[4] == 'A' && buf[5] == 'L' && len >= 7 && buf[6] == 'L') return 19; // HGETALL
	}
	return 0; // unknown or not matched
}

// 从 payload 指针中扫描 RESP 命令名（无循环，BPF verifier 安全）
// 返回命令长度，0 表示未识别
// RESP 格式: *N\r\n$L\r\nCMD\r\n...
// 例: *3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n
// pos=0: '*'  pos=1-2: N  pos=3: '\r' pos=4: '\n'
// pos=5: '$'  pos=6-7: L  pos=8: '\r' pos=9: '\n'
// pos=10+: CMD
static __always_inline int scan_resp_command(const char *buf, int buf_max, char *cmd_out, int cmd_max) {
	if (buf_max < 10) return 0;
	if (buf[0] != '*') return 0;

	// 跳过 '*' + 数字 + '\r\n'
	// 支持 1-2 位数字的参数计数 (max 99 args)
	int pos = 1;
	if (buf[pos] >= '0' && buf[pos] <= '9') {
		pos++;
		// 可选的第二位数字
		if (pos < buf_max && buf[pos] >= '0' && buf[pos] <= '9') pos++;
	}
	if (pos + 1 >= buf_max) return 0;
	if (buf[pos] != '\r' || buf[pos+1] != '\n') return 0;
	pos += 2;

	// 期望 '$' + 数字 + '\r\n'
	if (pos >= buf_max || buf[pos] != '$') return 0;
	pos++;
	int cmd_len = 0;
	if (pos < buf_max && buf[pos] >= '0' && buf[pos] <= '9') {
		cmd_len = buf[pos] - '0';
		pos++;
		// 可选的第二位数字
		if (pos < buf_max && buf[pos] >= '0' && buf[pos] <= '9') {
			cmd_len = cmd_len * 10 + (buf[pos] - '0');
			pos++;
		}
	}
	if (cmd_len <= 0 || cmd_len > cmd_max) return 0;
	if (pos + 1 >= buf_max) return 0;
	if (buf[pos] != '\r' || buf[pos+1] != '\n') return 0;
	pos += 2;

	// 读取命令名（展开复制，最多 16 字节，BPF verifier 安全）
	if (pos + cmd_len > buf_max) return 0;
	int n = cmd_len < cmd_max ? cmd_len : cmd_max;
	if (n > 0)  cmd_out[0] = buf[pos];
	if (n > 1)  cmd_out[1] = buf[pos+1];
	if (n > 2)  cmd_out[2] = buf[pos+2];
	if (n > 3)  cmd_out[3] = buf[pos+3];
	if (n > 4)  cmd_out[4] = buf[pos+4];
	if (n > 5)  cmd_out[5] = buf[pos+5];
	if (n > 6)  cmd_out[6] = buf[pos+6];
	if (n > 7)  cmd_out[7] = buf[pos+7];
	if (n > 8)  cmd_out[8] = buf[pos+8];
	if (n > 9)  cmd_out[9] = buf[pos+9];
	if (n > 10) cmd_out[10]= buf[pos+10];
	if (n > 11) cmd_out[11]= buf[pos+11];
	if (n > 12) cmd_out[12]= buf[pos+12];
	if (n > 13) cmd_out[13]= buf[pos+13];
	if (n > 14) cmd_out[14]= buf[pos+14];
	if (n > 15) cmd_out[15]= buf[pos+15];
	return n;
}

SEC("kprobe/tcp_sendmsg")
int kprobe_redis_sendmsg(struct pt_regs *ctx) {
	struct sock *sk = (struct sock *)ctx->di;
	if (!sk) return 0;

	// 读取目标端口，检查是否为 Redis
	__u16 dport_be;
	BPF_CORE_READ_INTO(&dport_be, sk, __sk_common.skc_dport);
	__u16 dport = __builtin_bswap16(dport_be);

	__u32 port_key = 0;
	__u16 *cfg_port = bpf_map_lookup_elem(&redis_ports, &port_key);
	__u16 redis_port = cfg_port ? *cfg_port : 6379;
	if (dport != redis_port) return 0;

	// 读取 msghdr 中的 payload
	struct msghdr *msg_hdr = (struct msghdr *)ctx->si;
	if (!msg_hdr) return 0;

	// 从 iov_iter 读取 iov 指针数组（kernel 指针）
	const struct iovec *iov_arr;
	BPF_CORE_READ_INTO(&iov_arr, msg_hdr, msg_iter.__iov);

	// 读取第一个 struct iovec（kernel 内存中的结构体）
	struct iovec iov;
	long ret = bpf_probe_read_kernel(&iov, sizeof(iov), iov_arr);
	if (ret < 0) return 0;

	// 读取 payload 数据（最多 64 字节，从用户态内存）
	char payload[64];
	__builtin_memset(payload, 0, sizeof(payload));
	ret = bpf_probe_read_user(payload, sizeof(payload) < iov.iov_len ? sizeof(payload) : iov.iov_len, iov.iov_base);
	if (ret < 0) return 0;

	// 解析 RESP 命令
	char cmd[16];
	__builtin_memset(cmd, 0, sizeof(cmd));
	int cmd_len = scan_resp_command(payload, sizeof(payload), cmd, sizeof(cmd));
	int cmd_id = match_command(cmd, cmd_len);

	struct redis_event *evt = bpf_ringbuf_reserve(&redis_events, sizeof(*evt), 0);
	if (!evt) return 0;

	evt->pid = bpf_get_current_pid_tgid() >> 32;
	evt->timestamp_ns = bpf_ktime_get_ns();
	evt->data_len = (__u32)(iov.iov_len < 65536 ? iov.iov_len : 65535);
	__builtin_memcpy(evt->command, cmd, sizeof(cmd));

	// 将命令 ID 写入 command 的最后一个字节以便用户态快速分类
	if (cmd_id > 0) {
		evt->pad[0] = (__u8)cmd_id;
	}

	bpf_ringbuf_submit(evt, 0);

	// 如果命令已识别，记录命令 ID 用于消重
	// (命令 ID 0 表示未知命令或非法 RESP)

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
