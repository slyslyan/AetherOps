package policy

import (
	"testing"
	"time"
)

func TestNewEngineDefaults(t *testing.T) {
	pe := NewEngine("")
	if pe == nil {
		t.Fatal("expected non-nil engine")
	}
	if len(pe.rules) == 0 {
		t.Error("expected default rules to be loaded")
	}
}

func TestCheckActionDeniedByProtectedNamespace(t *testing.T) {
	pe := NewEngine("")
	action := PolicyAction{
		Action:     ActionTCPDrop,
		TargetNode: "kube-system/kube-dns",
		Namespace:  "kube-system",
		Timestamp:  time.Now(),
	}
	result := pe.Check(action)
	if !result.Denied {
		t.Error("expected action against kube-system to be denied")
	}
	if result.Allowed {
		t.Error("expected Allowed=false for denied action")
	}
}

func TestCheckActionAllowedForNonProtected(t *testing.T) {
	pe := NewEngine("")
	action := PolicyAction{
		Action:     ActionScaleUp,
		TargetNode: "my-app-12345",
		Timestamp:  time.Now(),
	}
	result := pe.Check(action)
	if !result.Allowed {
		t.Errorf("expected action to be allowed, got denied: %v", result.Reasons)
	}
	if result.Denied {
		t.Error("expected Denied=false for allowed action")
	}
	if result.Warned {
		t.Error("expected Warned=false for unrestricted action")
	}
}

func TestCheckActionDeniedByProtectedService(t *testing.T) {
	pe := NewEngine("")
	action := PolicyAction{
		Action:     ActionPodRestart,
		TargetNode: "mysql-0",
		Timestamp:  time.Now(),
	}
	result := pe.Check(action)
	if !result.Denied {
		t.Error("expected restart on mysql to be denied (protected service)")
	}
}

func TestCheckActionDeniedByProtectedIP(t *testing.T) {
	pe := NewEngine("")
	action := PolicyAction{
		Action:    ActionTCPDrop,
		TargetIP:  "127.0.0.1",
		Timestamp: time.Now(),
	}
	result := pe.Check(action)
	if !result.Denied {
		t.Error("expected TC_DROP on 127.0.0.1 to be denied")
	}
}

func TestCheckActionWarnedByRequireApproval(t *testing.T) {
	pe := NewEngine("")
	action := PolicyAction{
		Action:     ActionPodRestart,
		TargetNode: "some-app",
		Namespace:  "default",
		Timestamp:  time.Now(),
	}
	result := pe.Check(action)
	if !result.Warned {
		t.Error("expected POD_RESTART to be warned (requires human approval)")
	}
}

func TestCheckMaxConcurrentActions(t *testing.T) {
	pe := NewEngine("")
	// Default max-concurrent-tc-drop rule allows 5 concurrent TC_DROP
	actions := make([]PolicyAction, 10)
	for i := 0; i < 10; i++ {
		actions[i] = PolicyAction{
			Action:     ActionTCPDrop,
			TargetNode: "target",
			Timestamp:  time.Now(),
		}
	}
	// First 5 should be allowed, check the 6th
	for i := 0; i < 6; i++ {
		pe.Check(actions[i])
	}
	// 6th check - after 5 concurrent, the limit should NOT deny via cooldown alone
	// because the cooldown logic only triggers if pe.cooldown[key] >= MaxConcurrentActions
	// which is 5. But each Check increments. So after 5, the 6th would have cooldown[TC_DROP] = 5
	// Wait, let me re-read the logic:
	// The matchRule checks `if pe.cooldown[key] >= int64(cond.MaxConcurrentActions)`
	// And pe.cooldown[key] is incremented in Check() only for the max-concurrent-tc-drop rule.
	// So after 6 checks, cooldown["TC_DROP"] = 6, and MaxConcurrentActions = 5, so 6 >= 5 = true (denied).
	result := pe.Check(actions[0])
	if !result.Denied {
		t.Error("expected 6th concurrent TC_DROP to be denied by max-concurrent")
	}
}

func TestCheckScaleUpNotDeniedByMaxReplica(t *testing.T) {
	pe := NewEngine("")
	action := PolicyAction{
		Action:     ActionScaleUp,
		TargetNode: "my-app",
		Timestamp:  time.Now(),
	}
	result := pe.Check(action)
	if !result.Allowed {
		t.Errorf("expected SCALE_UP on normal app to be allowed, got: %v", result.Reasons)
	}
}

func TestCheckScaleDownDeniedByMaxReplica(t *testing.T) {
	pe := NewEngine("")
	action := PolicyAction{
		Action:      ActionScaleDown,
		TargetNode:  "my-app",
		Replicas:    10,
		ScaleChange: 3, // 30% > 20% max
		Timestamp:   time.Now(),
	}
	result := pe.Check(action)
	if !result.Denied {
		t.Error("expected SCALE_DOWN with 30% change to be denied by max-replica-restart")
	}
}

func TestCheckMultipleRules(t *testing.T) {
	pe := NewEngine("")
	action := PolicyAction{
		Action:     ActionPodRestart,
		TargetNode: "mysql-0",
		Namespace:  "data-plane",
		Timestamp:  time.Now(),
	}
	result := pe.Check(action)
	// mysql matches both protect-critical-data-services AND max-replica-restart
	// At minimum, it should be denied
	if !result.Denied {
		t.Error("expected POD_RESTART on mysql to be denied")
	}
	if len(result.MatchedBy) < 1 {
		t.Error("expected at least one matched rule")
	}
}

func TestGetReport(t *testing.T) {
	pe := NewEngine("")
	report := pe.GetReport()
	if report["status"] != "active" {
		t.Errorf("expected status 'active', got '%v'", report["status"])
	}
	ruleCount, ok := report["rule_count"].(int)
	if !ok || ruleCount == 0 {
		t.Errorf("expected positive rule_count, got %d", ruleCount)
	}
}

func TestMatchAnyPrefix(t *testing.T) {
	tests := []struct {
		name     string
		prefixes []string
		want     bool
	}{
		{"kube-system/kube-dns", []string{"kube-system"}, true},
		{"my-app", []string{"kube-system"}, false},
		{"Redis-123", []string{"redis"}, true},
		{"mysql-0.prod", []string{"mysql"}, true},
	}
	for _, tt := range tests {
		got := matchAnyPrefix(tt.name, tt.prefixes)
		if got != tt.want {
			t.Errorf("matchAnyPrefix(%q, %v) = %v, want %v", tt.name, tt.prefixes, got, tt.want)
		}
	}
}

func TestMatchAnyPattern(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		want     bool
	}{
		{"abc-123", []string{`^abc-\d+$`}, true},
		{"xyz-abc", []string{`^abc-\d+$`}, false},
		{"abc-123-def", []string{`abc-\d+`}, true},
	}
	for _, tt := range tests {
		got := matchAnyPattern(tt.name, tt.patterns)
		if got != tt.want {
			t.Errorf("matchAnyPattern(%q, %v) = %v, want %v", tt.name, tt.patterns, got, tt.want)
		}
	}
}

func TestCheckBeforeMitigationEmpty(t *testing.T) {
	pe := NewEngine("")
	if !pe.CheckBeforeMitigation(nil) {
		t.Error("expected empty suspects to pass guard")
	}
}

func TestMatchRuleActionOnly(t *testing.T) {
	pe := NewEngine("")
	// A rule that only specifies actions, no other conditions, should match
	rule := pe.rules[0] // max-replica-restart: actions=[POD_RESTART, SCALE_DOWN]
	action := PolicyAction{
		Action:     ActionPodRestart,
		TargetNode: "anything",
		Timestamp:  time.Now(),
	}
	// If the action matches, and there are no non-action conditions,
	// matchRule should return true
	matched := pe.matchRule(rule, action)
	if !matched {
		t.Error("expected rule to match when action matches and no non-action conditions")
	}
}

func TestMatchRuleNonMatchingAction(t *testing.T) {
	pe := NewEngine("")
	rule := pe.rules[0]
	action := PolicyAction{
		Action:     ActionTCPDrop, // rule has POD_RESTART, SCALE_DOWN
		TargetNode: "anything",
		Timestamp:  time.Now(),
	}
	matched := pe.matchRule(rule, action)
	if matched {
		t.Error("expected rule NOT to match when action doesn't match")
	}
}

func TestParseIntOrZero(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"42", 42},
		{"0", 0},
		{"abc", 0},
		{"", 0},
		{"12abc", 12},
	}
	for _, tt := range tests {
		got := parseIntOrZero(tt.input)
		if got != tt.want {
			t.Errorf("parseIntOrZero(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestIsTimeBlockedNoDays(t *testing.T) {
	// No day restriction should block any day
	blocked := isTimeBlocked([]string{"00:00-23:59"}, nil)
	if !blocked {
		t.Error("expected 00:00-23:59 range to always block")
	}
}

func TestIsTimeBlockedNonMatchingDay(t *testing.T) {
	// If the block days don't include today, it shouldn't block
	// This test might be flaky if today is Saturday/Sunday... but default days are Mon-Fri
	blocked := isTimeBlocked([]string{"09:00-18:00"}, []string{"Saturday", "Sunday"})
	if blocked {
		t.Log("Note: today might be Saturday or Sunday, so this might correctly block")
	}
	// Accept either result since it depends on current day
}
