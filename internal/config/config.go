package config

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	apperrors "ebpf-autoheal/internal/errors"
)

// Config 包含所有可调参数，通过环境变量覆盖默认值。
type Config struct {
	// ===== 分析参数 =====
	P95Multiplier      float64 // 异常延迟阈值 = 当前 P95 × 此倍数（默认 1.2）
	MinLatThresholdMs  float64 // 最小延迟阈值（毫秒，默认 10）
	CallQPSThreshold   float64 // 调用量 QPS 基线最小值（默认 0=禁用）
	CallQPSDropRatio   float64 // QPS 降至基线的此比例时触发异常（默认 0.3）
	CallAnomalyWeight  float64 // 调用量异常在综合分数中的权重（默认 2.0）
	AnalysisWindowSec  float64 // QPS 计算的时间窗口（秒，默认 15）
	HistoryMatchMinSim float64 // Jaccard 历史匹配最小相似度（默认 0.6）
	HistoryExpireMin   float64 // 历史记录过期时间（分钟，默认 10）

	// ===== 自愈参数 =====
	MitigationCooldownSec float64 // 同一节点的自愈冷却时间（秒，默认 120）
	ProfileDurationSec    int     // pprof 火焰图采集时长（秒，默认 10）
	MaxSuspects           int     // 根因分析返回的最大嫌疑节点数（默认 5）

	// ===== 调度参数 =====
	TopologyPrintInterval int // 拓扑打印间隔（秒，默认 10）
	AnalysisInterval      int // 分析间隔（秒，默认 15）

	// ===== 网络地址 =====
	MetricsAddr string // Prometheus metrics 监听地址（默认 ":2112"）
	MCPAddr     string // MCP HTTP 监听地址（默认 ":50052"）

	// ===== eBPF 探针 =====
	HTTPProbeTarget string // uprobe 目标二进制路径（默认 "/proc/self/exe"）
	TCDropTTL       int    // TC drop 规则 TTL（分钟，默认 5）

	// ===== 自适应采样 =====
	AdaptiveSamplingThreshold  float64 // 触发高频采样的异常分数阈值（默认 5.0）
	NormalSamplingIntervalNs   uint64  // 正常采样间隔纳秒（默认 100ms）
	AdaptiveSamplingIntervalNs uint64  // 异常模式采样间隔纳秒（默认 10ms）

	// ===== 安全开关 =====
	DryRun bool // 影子模式：诊断 + 决策全流程但不实际执行自愈（默认 false）

}

// LoadFromEnv 从环境变量加载配置。
// 环境变量前缀 CFG_
func LoadFromEnv() *Config {
	metricsAddr := envStr("CFG_METRICS_ADDR", ":2112")
	if port := os.Getenv("AETHEROPS_METRICS_PORT"); port != "" {
		metricsAddr = ":" + port
	}

	return &Config{
		P95Multiplier:         envFloat("CFG_P95_MULTIPLIER", 1.2),
		MinLatThresholdMs:     envFloat("CFG_MIN_LAT_MS", 10),
		CallQPSThreshold:      envFloat("CFG_CALL_QPS_THRESHOLD", 0),
		CallQPSDropRatio:      envFloat("CFG_CALL_QPS_DROP_RATIO", 0.3),
		CallAnomalyWeight:     envFloat("CFG_CALL_ANOMALY_WEIGHT", 2.0),
		AnalysisWindowSec:     envFloat("CFG_ANALYSIS_WINDOW_SEC", 15),
		HistoryMatchMinSim:    envFloat("CFG_HISTORY_MIN_SIM", 0.6),
		HistoryExpireMin:      envFloat("CFG_HISTORY_EXPIRE_MIN", 10),
		MitigationCooldownSec: envFloat("CFG_MITIGATION_COOLDOWN_SEC", 120),
		ProfileDurationSec:    envInt("CFG_PROFILE_DURATION", 10),
		MaxSuspects:           envInt("CFG_MAX_SUSPECTS", 5),
		TopologyPrintInterval: envInt("CFG_PRINT_INTERVAL", 10),
		AnalysisInterval:      envInt("CFG_ANALYSIS_INTERVAL", 15),
		MetricsAddr:           metricsAddr,
		MCPAddr:               envStr("CFG_MCP_ADDR", ":50052"),
		HTTPProbeTarget:       envStr("CFG_HTTP_PROBE_TARGET", "/proc/self/exe"),
		TCDropTTL:                  envInt("CFG_TC_DROP_TTL", 5),
		AdaptiveSamplingThreshold:  envFloat("CFG_ADAPTIVE_SAMPLING_THRESHOLD", 5.0),
		NormalSamplingIntervalNs:   uint64(envInt("CFG_NORMAL_SAMPLING_NS", 100000000)),
		AdaptiveSamplingIntervalNs: uint64(envInt("CFG_ADAPTIVE_SAMPLING_NS", 10000000)),
		DryRun:                     envBool("DRY_RUN", false),
	}
}

// Validate 检查配置值是否合理，返回所有不合理项。
func (c *Config) Validate() error {
	var errs []string
	if c.P95Multiplier <= 0 {
		errs = append(errs, "P95Multiplier must be positive")
	}
	if c.MinLatThresholdMs < 0 {
		errs = append(errs, "MinLatThresholdMs must be >= 0")
	}
	if c.MitigationCooldownSec < 0 {
		errs = append(errs, "MitigationCooldownSec must be >= 0")
	}
	if c.ProfileDurationSec <= 0 {
		errs = append(errs, "ProfileDurationSec must be positive")
	}
	if c.MaxSuspects <= 0 {
		errs = append(errs, "MaxSuspects must be positive")
	}
	if c.TopologyPrintInterval <= 0 {
		errs = append(errs, "TopologyPrintInterval must be positive")
	}
	if c.AnalysisInterval <= 0 {
		errs = append(errs, "AnalysisInterval must be positive")
	}

	if c.AnalysisWindowSec <= 0 {
		errs = append(errs, "AnalysisWindowSec must be positive")
	}
	if c.CallQPSDropRatio < 0 || c.CallQPSDropRatio > 1 {
		errs = append(errs, "CallQPSDropRatio must be in [0, 1]")
	}
	if c.CallAnomalyWeight < 0 {
		errs = append(errs, "CallAnomalyWeight must be >= 0")
	}
	if c.TCDropTTL <= 0 {
		errs = append(errs, "TCDropTTL must be positive")
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid config (%s): %w", join(errs, "; "), apperrors.ErrInvalidConfig)
	}
	return nil
}

func join(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	s := strs[0]
	for _, v := range strs[1:] {
		s += sep + v
	}
	return s
}

func envFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v == "1" || v == "true" || v == "yes"
}

// Cooldown 管理自愈冷却期，防止同一节点被频繁自愈。
type Cooldown struct {
	mu      sync.Mutex
	entries map[string]time.Time
	ttl     time.Duration
}

// NewCooldown 创建冷却期管理器。
func NewCooldown(ttl time.Duration) *Cooldown {
	return &Cooldown{
		entries: make(map[string]time.Time),
		ttl:     ttl,
	}
}

// IsOnCooldown 检查节点是否在冷却期内。
func (c *Cooldown) IsOnCooldown(nodeID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ttl <= 0 {
		return false
	}
	expiry, ok := c.entries[nodeID]
	if !ok {
		return false
	}
	if time.Now().Before(expiry) {
		return true
	}
	delete(c.entries, nodeID)
	return false
}

// Set 设置节点的冷却期。
func (c *Cooldown) Set(nodeID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ttl <= 0 {
		return
	}
	c.entries[nodeID] = time.Now().Add(c.ttl)
}

// Expire 清理过期冷却记录。
func (c *Cooldown) Expire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for id, expiry := range c.entries {
		if now.After(expiry) {
			delete(c.entries, id)
		}
	}
}
