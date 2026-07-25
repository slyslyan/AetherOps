package remediation

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// CanaryPhase 金丝雀执行阶段。
type CanaryPhase int

const (
	CanaryPhasePending   CanaryPhase = iota // 等待执行
	CanaryPhaseObserving                    // 观察中
	CanaryPhaseRollout                      // 全量推广
	CanaryPhaseRollback                     // 回滚中
)

// CanaryResult 金丝雀执行结果。
type CanaryResult struct {
	Phase          CanaryPhase
	TargetNode     string
	Action         RemediationActionType
	ObserveSeconds int
	ScoreBefore    float64
	ScoreAfter     float64
	RolledOut      bool
	RollbackReason string
}

// CanaryConfig 金丝雀配置。
type CanaryConfig struct {
	ObserveDuration   time.Duration // 观察窗口，默认 30s
	ScoreImproveRatio float64       // 异常分数需改善的比例，默认 0.3（降低 30%）
	MaxCanaryRetries  int           // 金丝雀失败最大重试次数，默认 1
}

// DefaultCanaryConfig 返回默认金丝雀配置。
func DefaultCanaryConfig() CanaryConfig {
	return CanaryConfig{
		ObserveDuration:   30 * time.Second,
		ScoreImproveRatio: 0.3,
		MaxCanaryRetries:  1,
	}
}

// CanaryExecutor 管理金丝雀自愈的两阶段执行。
type CanaryExecutor struct {
	mu      sync.Mutex
	config  CanaryConfig
	history map[string][]CanaryResult
	active  map[string]*CanaryResult
}

// NewCanaryExecutor 创建金丝雀执行器。
func NewCanaryExecutor(cfg CanaryConfig) *CanaryExecutor {
	return &CanaryExecutor{
		config:  cfg,
		history: make(map[string][]CanaryResult),
		active:  make(map[string]*CanaryResult),
	}
}

// IsCanaryRequired 判断某动作是否需要金丝雀流程。
// TC_DROP 可瞬间回滚，跳过金丝雀；破坏性操作必须走金丝雀。
func IsCanaryRequired(action RemediationActionType) bool {
	switch action {
	case ActionTCPDrop, ActionScaleUp:
		return false
	case ActionPodRestart, ActionConfigChange, ActionScaleDown, ActionImageRollback:
		return true
	default:
		return true
	}
}

// ExecuteCanary 执行金丝雀自愈。返回 true 表示全量推广成功，false 表示已回滚。
func (ce *CanaryExecutor) ExecuteCanary(
	targetNode string,
	action RemediationActionType,
	scoreBefore float64,
	doMitigate func(scope string) error,
	observeScore func() float64,
) (bool, error) {
	ce.mu.Lock()
	if _, exists := ce.active[targetNode]; exists {
		ce.mu.Unlock()
		return false, fmt.Errorf("canary already in progress for %s", targetNode)
	}
	result := &CanaryResult{
		Phase:       CanaryPhasePending,
		TargetNode:  targetNode,
		Action:      action,
		ScoreBefore: scoreBefore,
	}
	ce.active[targetNode] = result
	ce.mu.Unlock()

	defer func() {
		ce.mu.Lock()
		delete(ce.active, targetNode)
		ce.history[targetNode] = append(ce.history[targetNode], *result)
		ce.mu.Unlock()
	}()

	// Phase 1: Apply to canary scope (1 pod / 1 instance)
	slog.Info(fmt.Sprintf("[Canary] Phase 1 — applying %s to %s (canary scope)", action, targetNode))
	result.Phase = CanaryPhaseObserving

	if err := doMitigate("canary"); err != nil {
		result.RollbackReason = fmt.Sprintf("canary apply failed: %v", err)
		slog.Error(fmt.Sprintf("[Canary] Phase 1 FAILED: %v", err))
		return false, ce.rollback(targetNode, action, result)
	}

	// Phase 2: Observe
	slog.Info(fmt.Sprintf("[Canary] Phase 2 — observing %s for %v", targetNode, ce.config.ObserveDuration))
	time.Sleep(ce.config.ObserveDuration)

	result.ScoreAfter = observeScore()
	result.ObserveSeconds = int(ce.config.ObserveDuration.Seconds())

	improvement := result.ScoreBefore - result.ScoreAfter
	improveRatio := improvement / result.ScoreBefore

	slog.Info(fmt.Sprintf("[Canary] Observation: score %.2f → %.2f (improvement %.1f%%)",
		result.ScoreBefore, result.ScoreAfter, improveRatio*100))

	if improveRatio < ce.config.ScoreImproveRatio {
		result.RollbackReason = fmt.Sprintf(
			"canary score not improved enough: %.1f%% < %.0f%% threshold",
			improveRatio*100, ce.config.ScoreImproveRatio*100,
		)
		slog.Warn(fmt.Sprintf("[Canary] Phase 2 FAILED: %s — rolling back", result.RollbackReason))
		return false, ce.rollback(targetNode, action, result)
	}

	// Phase 3: Full rollout
	slog.Info(fmt.Sprintf("[Canary] Phase 3 — full rollout of %s to %s", action, targetNode))
	result.Phase = CanaryPhaseRollout

	if err := doMitigate("full"); err != nil {
		result.RollbackReason = fmt.Sprintf("full rollout failed: %v", err)
		slog.Error(fmt.Sprintf("[Canary] Phase 3 FAILED: %v", err))
		return false, ce.rollback(targetNode, action, result)
	}

	result.RolledOut = true
	slog.Info(fmt.Sprintf("[Canary] SUCCESS — %s fully rolled out to %s", action, targetNode))
	return true, nil
}

func (ce *CanaryExecutor) rollback(targetNode string, action RemediationActionType, result *CanaryResult) error {
	result.Phase = CanaryPhaseRollback
	slog.Warn(fmt.Sprintf("[Canary] Rolling back %s on %s", action, targetNode))
	// Rollback for TC_DROP is handled by TTL auto-expiry
	// For POD_RESTART we rely on K8s auto-recovery
	// For CONFIG_CHANGE this is a no-op (config was only applied to canary scope)
	return fmt.Errorf("canary failed for %s: %s", targetNode, result.RollbackReason)
}

// GetHistory 返回节点的金丝雀历史。
func (ce *CanaryExecutor) GetHistory(targetNode string) []CanaryResult {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	return append([]CanaryResult{}, ce.history[targetNode]...)
}
