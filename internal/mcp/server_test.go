package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestStreamableEndpointInitialize(t *testing.T) {
	s := NewServer(":0", nil, nil, nil, Config{})
	ts := httptest.NewServer(s.streamable)
	defer ts.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`
	resp, err := http.Post(ts.URL+"/mcp", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("POST /mcp failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var r struct {
		JSONRPC string `json:"jsonrpc"`
		Result  struct {
			ServerInfo struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
		Error *struct{} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if r.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %q", r.JSONRPC)
	}
	if r.Error != nil {
		t.Errorf("expected no error in initialize response, got %v", r.Error)
	}
	if !strings.EqualFold(r.Result.ServerInfo.Name, "AetherOps") {
		t.Errorf("expected serverInfo.name AetherOps, got %q", r.Result.ServerInfo.Name)
	}
}
