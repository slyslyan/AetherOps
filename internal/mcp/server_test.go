package mcp

import (
	"testing"

	"ebpf-autoheal/internal/graph"
	"ebpf-autoheal/internal/remediation"
)

func TestNewServer(t *testing.T) {
	s := NewServer(":0", nil, nil, nil, Config{})
	if s == nil {
		t.Fatal("expected non-nil server")
	}
	if s.addr != ":0" {
		t.Errorf("expected addr ':0', got '%s'", s.addr)
	}
	if s.mcp == nil {
		t.Error("expected MCP server to be initialized")
	}
}

func TestNewServerWithDependencies(t *testing.T) {
	g := graph.NewServiceGraph()
	pe := remediation.NewEngine("")
	ms := remediation.NewService(nil, pe)
	cfg := Config{ProfileDurationSec: 15}

	s := NewServer(":50052", g, ms, pe, cfg)
	if s.graph != g {
		t.Error("expected graph to be stored")
	}
	if s.mitigation != ms {
		t.Error("expected mitigation service to be stored")
	}
	if s.policy != pe {
		t.Error("expected policy engine to be stored")
	}
	if s.cfg.ProfileDurationSec != 15 {
		t.Errorf("expected ProfileDurationSec 15, got %d", s.cfg.ProfileDurationSec)
	}
}

func TestPublishAnomaly(t *testing.T) {
	s := NewServer(":0", nil, nil, nil, Config{})
	// Should not panic
	s.PublishAnomaly("node-1", 95.0, 200.0, 1000, []string{"node-1", "node-2"})
}

func TestShutdownWithoutStart(t *testing.T) {
	s := NewServer(":0", nil, nil, nil, Config{})
	// Should not panic
	err := s.Shutdown(nil)
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

func TestStartAndShutdown(t *testing.T) {
	s := NewServer(":0", nil, nil, nil, Config{})
	if err := s.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	// Should not block or panic
	s.Shutdown(nil)
}
