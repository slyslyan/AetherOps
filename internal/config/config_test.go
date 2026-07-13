package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadFromEnvDefaults(t *testing.T) {
	cfg := LoadFromEnv()
	if cfg.P95Multiplier != 1.2 {
		t.Errorf("expected P95Multiplier 1.2, got %f", cfg.P95Multiplier)
	}
	if cfg.MinLatThresholdMs != 10 {
		t.Errorf("expected MinLatThresholdMs 10, got %f", cfg.MinLatThresholdMs)
	}
	if cfg.ProfileDurationSec != 10 {
		t.Errorf("expected ProfileDurationSec 10, got %d", cfg.ProfileDurationSec)
	}
	if cfg.MaxSuspects != 5 {
		t.Errorf("expected MaxSuspects 5, got %d", cfg.MaxSuspects)
	}
	if !cfg.LabelGuardEnabled {
		t.Error("expected LabelGuardEnabled true by default")
	}
	if cfg.LabelGuardMax != 100 {
		t.Errorf("expected LabelGuardMax 100, got %d", cfg.LabelGuardMax)
	}
	if cfg.MetricsAddr != ":2112" {
		t.Errorf("expected MetricsAddr ':2112', got '%s'", cfg.MetricsAddr)
	}
	if cfg.GRPCAddr != ":50051" {
		t.Errorf("expected GRPCAddr ':50051', got '%s'", cfg.GRPCAddr)
	}
	if cfg.MCPAddr != ":50052" {
		t.Errorf("expected MCPAddr ':50052', got '%s'", cfg.MCPAddr)
	}
	if cfg.HTTPProbeTarget != "/proc/self/exe" {
		t.Errorf("expected HTTPProbeTarget '/proc/self/exe', got '%s'", cfg.HTTPProbeTarget)
	}
	if cfg.TCDropTTL != 5 {
		t.Errorf("expected TCDropTTL 5, got %d", cfg.TCDropTTL)
	}
}

func TestLoadFromEnvOverrides(t *testing.T) {
	os.Setenv("CFG_P95_MULTIPLIER", "2.5")
	os.Setenv("CFG_MAX_SUSPECTS", "10")
	os.Setenv("CFG_LABEL_GUARD_ENABLED", "0")
	defer func() {
		os.Unsetenv("CFG_P95_MULTIPLIER")
		os.Unsetenv("CFG_MAX_SUSPECTS")
		os.Unsetenv("CFG_LABEL_GUARD_ENABLED")
	}()

	cfg := LoadFromEnv()
	if cfg.P95Multiplier != 2.5 {
		t.Errorf("expected P95Multiplier 2.5, got %f", cfg.P95Multiplier)
	}
	if cfg.MaxSuspects != 10 {
		t.Errorf("expected MaxSuspects 10, got %d", cfg.MaxSuspects)
	}
	if cfg.LabelGuardEnabled {
		t.Error("expected LabelGuardEnabled false")
	}
}

func TestMetricsAddrFromEnvOverride(t *testing.T) {
	os.Setenv("CFG_METRICS_ADDR", ":9090")
	defer os.Unsetenv("CFG_METRICS_ADDR")
	cfg := LoadFromEnv()
	if cfg.MetricsAddr != ":9090" {
		t.Errorf("expected MetricsAddr ':9090', got '%s'", cfg.MetricsAddr)
	}
}

func TestMetricsAddrFromAetheropsPort(t *testing.T) {
	os.Setenv("AETHEROPS_METRICS_PORT", "9093")
	defer os.Unsetenv("AETHEROPS_METRICS_PORT")
	cfg := LoadFromEnv()
	if cfg.MetricsAddr != ":9093" {
		t.Errorf("expected MetricsAddr ':9093' from AETHEROPS_METRICS_PORT, got '%s'", cfg.MetricsAddr)
	}
}

func TestLoadFromEnvInvalidFloat(t *testing.T) {
	os.Setenv("CFG_P95_MULTIPLIER", "not-a-number")
	defer os.Unsetenv("CFG_P95_MULTIPLIER")

	cfg := LoadFromEnv()
	if cfg.P95Multiplier != 1.2 {
		t.Errorf("expected default 1.2 for invalid env, got %f", cfg.P95Multiplier)
	}
}

func TestValidateOK(t *testing.T) {
	cfg := LoadFromEnv()
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestValidateP95MultiplierZero(t *testing.T) {
	cfg := LoadFromEnv()
	cfg.P95Multiplier = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for P95Multiplier=0")
	}
}

func TestValidateProfileDurationZero(t *testing.T) {
	cfg := LoadFromEnv()
	cfg.ProfileDurationSec = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for ProfileDurationSec=0")
	}
}

func TestValidateAnalysisIntervalZero(t *testing.T) {
	cfg := LoadFromEnv()
	cfg.AnalysisInterval = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for AnalysisInterval=0")
	}
}

func TestValidateLabelGuardMaxZero(t *testing.T) {
	cfg := LoadFromEnv()
	cfg.LabelGuardMax = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for LabelGuardMax=0")
	}
}

func TestCooldownSetAndCheck(t *testing.T) {
	cd := NewCooldown(5 * time.Minute)
	cd.Set("node-a")
	if !cd.IsOnCooldown("node-a") {
		t.Error("expected node-a to be on cooldown")
	}
	if cd.IsOnCooldown("node-b") {
		t.Error("expected node-b not to be on cooldown")
	}
}

func TestCooldownExpiry(t *testing.T) {
	cd := NewCooldown(1 * time.Millisecond)
	cd.Set("node-a")
	time.Sleep(2 * time.Millisecond)
	if cd.IsOnCooldown("node-a") {
		t.Error("expected node-a cooldown to have expired")
	}
}

func TestCooldownDisabled(t *testing.T) {
	cd := NewCooldown(0)
	cd.Set("node-a")
	if cd.IsOnCooldown("node-a") {
		t.Error("expected disabled cooldown to always return false")
	}
}

func TestCooldownExpire(t *testing.T) {
	cd := NewCooldown(1 * time.Millisecond)
	cd.Set("node-a")
	cd.Set("node-b")
	time.Sleep(2 * time.Millisecond)
	cd.Expire()

	if cd.IsOnCooldown("node-a") || cd.IsOnCooldown("node-b") {
		t.Error("expected both nodes to be expired")
	}
}
