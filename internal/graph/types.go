package graph

import "net"

// Suspicion 表示一个嫌疑节点（根因分析的输出结果）。
type Suspicion struct {
	Node      string
	Score     float64
	AvgLat    float64
	CallCount int64
	IsIPPort  bool
}

// SuspicionCluster 对嫌疑节点按分数相近程度进行分组。
type SuspicionCluster struct {
	Nodes []Suspicion
}

// uint32ToIP 将小端序 uint32 转换为 net.IP。
func Uint32ToIP(val uint32) net.IP {
	ip := make(net.IP, 4)
	ip[0] = byte(val & 0xff)
	ip[1] = byte((val >> 8) & 0xff)
	ip[2] = byte((val >> 16) & 0xff)
	ip[3] = byte((val >> 24) & 0xff)
	return ip
}

// connEventRaw 对应 eBPF tcp_conntrack.c 中的 conn_event 结构体。
type ConnEventRaw struct {
	Saddr      uint32
	Daddr      uint32
	Sport      uint16
	Dport      uint16
	Family     uint16
	Role       uint8
	Pad        [1]byte
	DurationNs uint64
	Pid        uint32
	Comm       [16]byte
	Pad2       [4]byte
}

// httpEventRaw 对应 eBPF http_probe.c 中的 http_event 结构体。
type HTTPEventRaw struct {
	Pid         uint32
	TimestampNs uint64
	StatusCode  uint32
	Method      uint16
	Path        [128]byte
	Host        [64]byte
	DurationNs  uint32
}
