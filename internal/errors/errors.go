// Package errors defines sentinel errors used throughout ebpfagent.
// Wrap with fmt.Errorf("context: %w", sentinelErr) to add context.
package errors

import "fmt"

// Config errors
var (
	ErrInvalidConfig = fmt.Errorf("invalid configuration")
)

// eBPF load/attach errors
var (
	ErrEBPFLoad       = fmt.Errorf("eBPF object load failed")
	ErrKprobeAttach   = fmt.Errorf("kprobe attach failed")
	ErrRingBufCreate  = fmt.Errorf("ring buffer create failed")
	ErrRemoveMemlock  = fmt.Errorf("remove memlock failed")
	ErrHTTPProbeLoad  = fmt.Errorf("HTTP probe load failed")
)

// TC drop errors
var (
	ErrTCCmd          = fmt.Errorf("tc command failed")
	ErrTCMapDelete    = fmt.Errorf("tc eBPF map delete failed")
	ErrInvalidIface   = fmt.Errorf("invalid network interface")
	ErrInvalidIP      = fmt.Errorf("invalid IP address")
)

// Mitigation errors
var (
	ErrHTTPRequest    = fmt.Errorf("HTTP request to target failed")
	ErrPprofGen       = fmt.Errorf("pprof flamegraph generation failed")
	ErrPacketCapture  = fmt.Errorf("packet capture failed")
	ErrFeishuNotify   = fmt.Errorf("Feishu notification failed")
)

// Policy errors
var (
	ErrPolicyFileLoad = fmt.Errorf("policy file load failed")
	ErrPolicyDenied   = fmt.Errorf("action denied by policy")
)

// gRPC errors
var (
	ErrGRPCListen     = fmt.Errorf("gRPC listen failed")
	ErrGRPCStreamSend = fmt.Errorf("gRPC stream send failed")
)

// MCP errors
var (
	ErrMCPInvalidArgs = fmt.Errorf("invalid MCP tool arguments")
)
