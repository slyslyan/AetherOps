package remediation

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"ebpf-autoheal/internal/graph"
)

// PolicyEffect 表示策略的评估效果。
type PolicyEffect string

const (
	EffectDeny  PolicyEffect = "deny"
	EffectAllow PolicyEffect = "allow"
	EffectWarn  PolicyEffect = "warn"
)

// RemediationActionType 自愈动作类型。
type RemediationActionType string

const (
	ActionTCPDrop       RemediationActionType = "TC_DROP"
	ActionPodRestart    RemediationActionType = "POD_RESTART"
	ActionScaleUp       RemediationActionType = "SCALE_UP"
	ActionScaleDown     RemediationActionType = "SCALE_DOWN"
	ActionConfigChange  RemediationActionType = "CONFIG_CHANGE"
	ActionImageRollback RemediationActionType = "IMAGE_ROLLBACK"
)

// PolicyAction 描述一个待评估的自愈动作。
type PolicyAction struct {
	Action      RemediationActionType `json:"action"`
	TargetNode  string                `json:"target_node"`
	TargetIP    string                `json:"target_ip,omitempty"`
	Namespace   string                `json:"namespace,omitempty"`
	Replicas    int                   `json:"replicas,omitempty"`
	ScaleChange int                   `json:"scale_change,omitempty"`
	Timestamp   time.Time             `json:"timestamp"`
}

// PolicyCondition 策略条件。
type PolicyCondition struct {
	Actions              []string `json:"actions,omitempty"`
	ProtectedNamespaces  []string `json:"protected_namespaces,omitempty"`
	ProtectedServices    []string `json:"protected_services,omitempty"`
	ProtectedIPs         []string `json:"protected_ips,omitempty"`
	MaxReplicasPercent   int      `json:"max_replicas_percent,omitempty"`
	MaxReplicas          int      `json:"max_replicas,omitempty"`
	MaxConcurrentActions int      `json:"max_concurrent_actions,omitempty"`
	BlockTimeRanges      []string `json:"block_time_ranges,omitempty"`
	BlockDays            []string `json:"block_days,omitempty"`
	RequireHumanApproval bool     `json:"require_human_approval,omitempty"`
	IfLabel              string   `json:"if_label,omitempty"`
	MatchPattern         string   `json:"match_pattern,omitempty"`
}

// PolicyRule 一条完整的策略规则。
type PolicyRule struct {
	ID          string          `json:"id"`
	Description string          `json:"description"`
	Effect      PolicyEffect    `json:"effect"`
	Conditions  PolicyCondition `json:"conditions"`
	Priority    int             `json:"priority,omitempty"`
}

// PolicyResult 策略评估结果。
type PolicyResult struct {
	Allowed   bool     `json:"allowed"`
	Denied    bool     `json:"denied"`
	Warned    bool     `json:"warned"`
	Reasons   []string `json:"reasons"`
	MatchedBy []string `json:"matched_by"`
}

// Engine 管理所有策略规则并提供评估能力。
type Engine struct {
	mu       sync.RWMutex
	rules    []PolicyRule
	filePath string
	cooldown map[string]int64
}

// NewEngine 创建策略引擎并加载默认 + 外部策略。
func NewEngine(policyFilePath string) *Engine {
	pe := &Engine{
		rules:    defaultPolicies(),
		cooldown: make(map[string]int64),
	}

	if policyFilePath != "" {
		if data, err := os.ReadFile(policyFilePath); err == nil {
			var externalRules []PolicyRule
			if err := json.Unmarshal(data, &externalRules); err == nil {
				pe.mergeRules(externalRules)
				slog.Info(fmt.Sprintf("Policy engine: loaded %d rules from %s", len(externalRules), policyFilePath))
			} else {
				slog.Info(fmt.Sprintf("Policy engine: failed to parse %s: %v, using defaults", policyFilePath, err))
			}
		} else {
			slog.Info(fmt.Sprintf("Policy engine: no policy file at %s, using defaults", policyFilePath))
		}
	} else {
		slog.Info(fmt.Sprintf("Policy engine: loaded %d default rules", len(pe.rules)))
	}

	return pe
}

// Check 评估一个自愈动作是否通过所有策略。
func (pe *Engine) Check(action PolicyAction) PolicyResult {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	result := PolicyResult{
		Allowed:   true,
		MatchedBy: []string{},
		Reasons:   []string{},
	}

	for _, rule := range pe.rules {
		if !pe.matchRule(rule, action) {
			continue
		}

		result.MatchedBy = append(result.MatchedBy, rule.ID)
		reason := fmt.Sprintf("[%s] %s", rule.ID, rule.Description)

		switch rule.Effect {
		case EffectDeny:
			result.Denied = true
			result.Allowed = false
			result.Reasons = append(result.Reasons, "DENY: "+reason)
		case EffectWarn:
			result.Warned = true
			result.Reasons = append(result.Reasons, "WARN: "+reason)
		}

		key := string(action.Action)
		if rule.Conditions.MaxConcurrentActions > 0 {
			pe.cooldown[key]++
		}
	}

	return result
}

// GetReport 返回所有已加载策略的状态报告。
func (pe *Engine) GetReport() map[string]interface{} {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	rules := make([]map[string]interface{}, len(pe.rules))
	for i, r := range pe.rules {
		rules[i] = map[string]interface{}{
			"id":          r.ID,
			"description": r.Description,
			"effect":      string(r.Effect),
			"priority":    r.Priority,
		}
	}

	return map[string]interface{}{
		"status":       "active",
		"rule_count":   len(pe.rules),
		"rules":        rules,
		"cooldown_map": pe.cooldown,
	}
}

func (pe *Engine) mergeRules(external []PolicyRule) {
	existing := make(map[string]int)
	for i, r := range pe.rules {
		existing[r.ID] = i
	}
	for _, ext := range external {
		if idx, ok := existing[ext.ID]; ok {
			pe.rules[idx] = ext
		} else {
			pe.rules = append(pe.rules, ext)
		}
	}
}

func (pe *Engine) matchRule(rule PolicyRule, action PolicyAction) bool {
	cond := rule.Conditions

	// Action type must match if specified (AND gate).
	if len(cond.Actions) > 0 {
		matched := false
		for _, a := range cond.Actions {
			if strings.EqualFold(a, string(action.Action)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Accumulate non-action condition checks so that all conditions are
	// evaluated (no short-circuit) and combined with OR semantics.
	hasNonActionCondition := false
	nonActionMatched := false

	if len(cond.ProtectedNamespaces) > 0 && action.Namespace != "" {
		hasNonActionCondition = true
		if matchAnyPrefix(action.Namespace, cond.ProtectedNamespaces) {
			nonActionMatched = true
		}
	}

	if len(cond.ProtectedServices) > 0 && action.TargetNode != "" {
		hasNonActionCondition = true
		if matchAnyPrefix(action.TargetNode, cond.ProtectedServices) {
			nonActionMatched = true
		}
	}

	if len(cond.ProtectedIPs) > 0 && action.TargetIP != "" {
		hasNonActionCondition = true
		for _, ip := range cond.ProtectedIPs {
			if action.TargetIP == ip {
				nonActionMatched = true
				break
			}
		}
	}

	if cond.MatchPattern != "" && action.TargetNode != "" {
		hasNonActionCondition = true
		if matchAnyPattern(action.TargetNode, []string{cond.MatchPattern}) {
			nonActionMatched = true
		}
	}

	if cond.MaxReplicasPercent > 0 && action.Replicas > 0 {
		hasNonActionCondition = true
		maxChanges := int(float64(action.Replicas) * float64(cond.MaxReplicasPercent) / 100.0)
		if maxChanges < 1 {
			maxChanges = 1
		}
		if action.ScaleChange > maxChanges {
			nonActionMatched = true
		}
	}

	if cond.MaxConcurrentActions > 0 {
		hasNonActionCondition = true
		key := string(action.Action)
		if pe.cooldown[key] >= int64(cond.MaxConcurrentActions) {
			nonActionMatched = true
		}
	}

	if len(cond.BlockTimeRanges) > 0 {
		hasNonActionCondition = true
		if isTimeBlocked(cond.BlockTimeRanges, cond.BlockDays) {
			nonActionMatched = true
		}
	}

	// Action-only rule: action type match is sufficient.
	if !hasNonActionCondition {
		return true
	}
	return nonActionMatched
}

func defaultPolicies() []PolicyRule {
	return []PolicyRule{
		{
			ID:          "max-replica-restart",
			Description: "禁止单次操作重启/变更超过 20% 的副本",
			Effect:      EffectDeny,
			Conditions: PolicyCondition{
				Actions:            []string{"POD_RESTART", "SCALE_DOWN"},
				MaxReplicasPercent: 20,
			},
			Priority: 100,
		},
		{
			ID:          "protect-control-plane",
			Description: "禁止对 K8s 控制平面组件执行自愈操作",
			Effect:      EffectDeny,
			Conditions: PolicyCondition{
				ProtectedNamespaces: []string{"kube-system", "kube-public"},
				Actions:             []string{"TC_DROP", "POD_RESTART", "SCALE_DOWN"},
			},
			Priority: 100,
		},
		{
			ID:          "protect-critical-data-services",
			Description: "禁止对核心数据层执行破坏性操作",
			Effect:      EffectDeny,
			Conditions: PolicyCondition{
				ProtectedServices: []string{"mysql", "redis", "etcd", "minio", "postgresql"},
				Actions:           []string{"TC_DROP", "POD_RESTART", "SCALE_DOWN"},
			},
			Priority: 90,
		},
		{
			ID:          "protect-localhost",
			Description: "禁止对本地回环地址执行 TC 限流",
			Effect:      EffectDeny,
			Conditions: PolicyCondition{
				ProtectedIPs: []string{"127.0.0.1", "::1"},
				Actions:      []string{"TC_DROP"},
			},
			Priority: 100,
		},
		{
			ID:          "high-risk-require-approval",
			Description: "高风险操作需要人工审批",
			Effect:      EffectWarn,
			Conditions: PolicyCondition{
				RequireHumanApproval: true,
				Actions:              []string{"POD_RESTART", "SCALE_DOWN", "CONFIG_CHANGE"},
			},
			Priority: 80,
		},
		{
			ID:          "max-concurrent-tc-drop",
			Description: "全局最多同时进行 5 个 TC 限流操作",
			Effect:      EffectDeny,
			Conditions: PolicyCondition{
				Actions:              []string{"TC_DROP"},
				MaxConcurrentActions: 5,
			},
			Priority: 70,
		},
		{
			ID:          "daytime-ddl-block",
			Description: "禁止在业务高峰时段（9:00-18:00）执行 CONFIG_CHANGE",
			Effect:      EffectDeny,
			Conditions: PolicyCondition{
				Actions:         []string{"CONFIG_CHANGE"},
				BlockTimeRanges: []string{"09:00-18:00"},
				BlockDays:       []string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday"},
			},
			Priority: 80,
		},
	}
}

func isTimeBlocked(ranges []string, days []string) bool {
	now := time.Now()
	weekday := now.Weekday().String()

	if len(days) > 0 {
		dayMatch := false
		for _, d := range days {
			if d == weekday {
				dayMatch = true
				break
			}
		}
		if !dayMatch {
			return false
		}
	}

	currentMinutes := now.Hour()*60 + now.Minute()
	for _, tr := range ranges {
		parts := strings.Split(tr, "-")
		if len(parts) != 2 {
			continue
		}
		startParts := strings.Split(parts[0], ":")
		endParts := strings.Split(parts[1], ":")
		if len(startParts) != 2 || len(endParts) != 2 {
			continue
		}
		startMin := parseIntOrZero(startParts[0])*60 + parseIntOrZero(startParts[1])
		endMin := parseIntOrZero(endParts[0])*60 + parseIntOrZero(endParts[1])
		if currentMinutes >= startMin && currentMinutes < endMin {
			return true
		}
	}
	return false
}

func parseIntOrZero(s string) int {
	var v int
	fmt.Sscanf(s, "%d", &v)
	return v
}

func matchAnyPrefix(name string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(strings.ToLower(name), strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func matchAnyPattern(name string, patterns []string) bool {
	for _, pat := range patterns {
		matched, err := regexp.MatchString(pat, name)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// CheckBeforeMitigation 是 policy guard 的快捷入口，从单个 Suspicion 构造 PolicyAction。
func (pe *Engine) CheckBeforeMitigation(suspect graph.Suspicion) bool {
	action := PolicyAction{
		Action:     ActionTCPDrop,
		TargetNode: suspect.Node,
		Timestamp:  time.Now(),
	}

	if suspect.IsIPPort {
		parts := strings.Split(suspect.Node, ":")
		if len(parts) >= 1 {
			action.TargetIP = parts[0]
		}
	}

	nodeLower := strings.ToLower(suspect.Node)
	switch {
	case strings.Contains(nodeLower, "kube-system") || strings.Contains(nodeLower, "kube-proxy") ||
		strings.Contains(nodeLower, "coredns") || strings.Contains(nodeLower, "traefik"):
		action.Namespace = "kube-system"
	case strings.Contains(nodeLower, "mysql") || strings.Contains(nodeLower, "redis"):
		action.Namespace = "data-plane"
	}

	if strings.HasPrefix(nodeLower, "mysql") || strings.HasPrefix(nodeLower, "redis") ||
		strings.HasPrefix(nodeLower, "etcd") {
		action.Namespace = "data-plane"
	}

	result := pe.Check(action)

	if result.Denied {
		slog.Warn(fmt.Sprintf("POLICY GUARD: Action DENIED for %s", suspect.Node))
		for _, reason := range result.Reasons {
			slog.Info(fmt.Sprintf("   - %s", reason))
		}
		slog.Info(fmt.Sprintf("   - Matched rules: %v", result.MatchedBy))
		auditLog("DENY", action, result)
		return false
	}

	if result.Warned {
		slog.Warn(fmt.Sprintf("POLICY GUARD: Action WARNED for %s (executing with caution)", suspect.Node))
		for _, reason := range result.Reasons {
			slog.Info(fmt.Sprintf("   - %s", reason))
		}
		auditLog("WARN", action, result)
	}

	return true
}

func auditLog(decision string, action PolicyAction, result PolicyResult) {
	entry := map[string]interface{}{
		"type":       "policy_audit",
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"decision":   decision,
		"action":     action,
		"reasons":    result.Reasons,
		"matched_by": result.MatchedBy,
	}
	data, _ := json.Marshal(entry)
	slog.Info(fmt.Sprintf("AUDIT:%s", string(data)))
}
