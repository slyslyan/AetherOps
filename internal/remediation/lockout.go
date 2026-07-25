package remediation

import (
	"fmt"
	"sync"
	"time"
)

// LockoutEntry 记录一次自愈触发事件。
type LockoutEntry struct {
	TargetNode string
	Action     RemediationActionType
	Timestamp  time.Time
}

// LockoutConfig 频繁自愈锁定配置。
type LockoutConfig struct {
	WindowDuration  time.Duration // 滑动窗口大小，默认 10 分钟
	MaxTriggers     int           // 窗口内最大触发次数，默认 3
	LockoutDuration time.Duration // 锁定期时长，默认 30 分钟
}

// DefaultLockoutConfig 返回默认锁定配置。
func DefaultLockoutConfig() LockoutConfig {
	return LockoutConfig{
		WindowDuration:  10 * time.Minute,
		MaxTriggers:     3,
		LockoutDuration: 30 * time.Minute,
	}
}

// LockoutTracker 滑动窗口计数器，防止频繁自愈。
// 在窗口内同一服务触发次数超过阈值后，锁定自动操作并强制人工介入。
type LockoutTracker struct {
	mu       sync.Mutex
	config   LockoutConfig
	entries  map[string][]LockoutEntry
	locked   map[string]time.Time // node -> lockout expiry
}

// NewLockoutTracker 创建锁定追踪器。
func NewLockoutTracker(cfg LockoutConfig) *LockoutTracker {
	return &LockoutTracker{
		config:  cfg,
		entries: make(map[string][]LockoutEntry),
		locked:  make(map[string]time.Time),
	}
}

// Record 记录一次自愈触发。返回 true 表示已触发锁定，需人工介入。
func (lt *LockoutTracker) Record(targetNode string, action RemediationActionType) (locked bool, reason string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	// 检查是否已在锁定期
	if expiry, ok := lt.locked[targetNode]; ok {
		if time.Now().Before(expiry) {
			return true, fmt.Sprintf("service %s is locked until %s", targetNode, expiry.Format("15:04:05"))
		}
		delete(lt.locked, targetNode)
	}

	now := time.Now()
	lt.entries[targetNode] = append(lt.entries[targetNode], LockoutEntry{
		TargetNode: targetNode,
		Action:     action,
		Timestamp:  now,
	})

	// 清理窗口外的旧记录
	cutoff := now.Add(-lt.config.WindowDuration)
	recent := lt.entries[targetNode][:0]
	for _, e := range lt.entries[targetNode] {
		if e.Timestamp.After(cutoff) {
			recent = append(recent, e)
		}
	}
	lt.entries[targetNode] = recent

	if len(recent) >= lt.config.MaxTriggers {
		lt.locked[targetNode] = now.Add(lt.config.LockoutDuration)
		delete(lt.entries, targetNode)
		return true, fmt.Sprintf(
			"triggered %d times in %v — locked for %v, requires human intervention",
			len(recent), lt.config.WindowDuration, lt.config.LockoutDuration,
		)
	}

	return false, ""
}

// IsLocked 检查节点是否被锁定。
func (lt *LockoutTracker) IsLocked(targetNode string) bool {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if expiry, ok := lt.locked[targetNode]; ok {
		if time.Now().Before(expiry) {
			return true
		}
		delete(lt.locked, targetNode)
	}
	return false
}

// Unlock 人工解锁指定节点。
func (lt *LockoutTracker) Unlock(targetNode string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	delete(lt.locked, targetNode)
	delete(lt.entries, targetNode)
}

// LockedNodes 返回所有被锁定的节点。
func (lt *LockoutTracker) LockedNodes() []string {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	nodes := make([]string, 0, len(lt.locked))
	for node, expiry := range lt.locked {
		if time.Now().Before(expiry) {
			nodes = append(nodes, node)
		} else {
			delete(lt.locked, node)
		}
	}
	return nodes
}
