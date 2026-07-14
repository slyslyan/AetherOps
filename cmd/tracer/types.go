package main

// netEventRaw 对应 eBPF net_trace.c 中的 net_event 结构体（48 字节）。
type netEventRaw struct {
	Saddr  uint32   // 源 IP（IPv4 小端序）
	Daddr  uint32   // 目标 IP（IPv4 小端序）
	Sport  uint16   // 源端口
	Dport  uint16   // 目标端口
	Family uint16   // 地址族（AF_INET=2, AF_INET6=10）
	Pad    [2]byte  // 填充对齐到 4 字节
	Delta  uint64   // 延迟（纳秒）
	Pid    uint32   // 进程 ID
	Comm   [16]byte // 进程名
	Pad2   [4]byte  // 填充到 48 字节
}

// connEventRaw 对应 eBPF tcp_conntrack.c 中的 conn_event 结构体。
type connEventRaw struct {
	Saddr      uint32   // 源 IP
	Daddr      uint32   // 目标 IP
	Sport      uint16   // 源端口
	Dport      uint16   // 目标端口
	Family     uint16   // 地址族
	Role       uint8    // 角色: 1=client, 2=server
	Pad        [1]byte  // 填充
	DurationNs uint64   // 连接持续时间（纳秒）
	Pid        uint32   // 进程 ID
	Comm       [16]byte // 进程名
	Pad2       [4]byte  // 填充
}

// httpEventRaw 对应 eBPF http_probe.c 中的 http_event 结构体。
type httpEventRaw struct {
	Pid         uint32    // 进程 ID
	TimestampNs uint64    // 时间戳（纳秒）
	StatusCode  uint32    // HTTP 状态码
	Method      uint16    // HTTP 方法（1=GET, 2=POST, 3=PUT...）
	Path        [128]byte // 请求路径
	Host        [64]byte  // Host 头
	DurationNs  uint32    // 请求耗时（纳秒）
}
