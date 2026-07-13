package grpc

import (
	"testing"
	"time"
)

func TestNewDedupTracker(t *testing.T) {
	d := newDedupTracker(60*time.Second, 80.0)
	if d == nil {
		t.Fatal("expected non-nil dedup tracker")
	}
	if d.window != 60*time.Second {
		t.Errorf("expected window 60s, got %v", d.window)
	}
	if d.minScore != 80.0 {
		t.Errorf("expected minScore 80, got %f", d.minScore)
	}
	if len(d.entries) != 0 {
		t.Errorf("expected empty entries, got %d", len(d.entries))
	}
}

func TestShouldSendAboveThreshold(t *testing.T) {
	d := newDedupTracker(60*time.Second, 50.0)
	send, suppressed := d.shouldSend("node-a", 90.0)
	if !send {
		t.Error("expected score >= minScore to send")
	}
	if suppressed != 0 {
		t.Errorf("expected 0 suppressed for first send, got %d", suppressed)
	}
}

func TestShouldSendBelowThresholdFirstTime(t *testing.T) {
	d := newDedupTracker(60*time.Second, 50.0)
	send, suppressed := d.shouldSend("node-a", 10.0)
	if !send {
		t.Error("expected first send even below threshold (no prior entry)")
	}
	if suppressed != 0 {
		t.Errorf("expected 0 suppressed, got %d", suppressed)
	}
}

func TestShouldSendDedupWithinWindow(t *testing.T) {
	d := newDedupTracker(60*time.Second, 50.0)

	// First event below threshold — should send
	d.shouldSend("node-a", 30.0)

	// Second event within window — should be suppressed
	send, suppressed := d.shouldSend("node-a", 30.0)
	if send {
		t.Error("expected send=false for duplicate within window")
	}
	if suppressed != 1 {
		t.Errorf("expected suppressed count 1, got %d", suppressed)
	}

	// Third event within window — should be suppressed with count=2
	_, suppressed = d.shouldSend("node-a", 30.0)
	if suppressed != 2 {
		t.Errorf("expected suppressed count 2, got %d", suppressed)
	}
}

func TestShouldSendAfterWindowExpiry(t *testing.T) {
	d := newDedupTracker(1*time.Millisecond, 50.0)

	d.shouldSend("node-a", 30.0)
	time.Sleep(5 * time.Millisecond)

	// After window expiry, should send again
	send, suppressed := d.shouldSend("node-a", 30.0)
	if !send {
		t.Error("expected send after window expiry")
	}
	if suppressed != 0 {
		t.Errorf("expected 0 suppressed after window expiry, got %d", suppressed)
	}
}

func TestShouldSendDifferentNodes(t *testing.T) {
	d := newDedupTracker(60*time.Second, 50.0)

	d.shouldSend("node-a", 30.0)
	send, _ := d.shouldSend("node-b", 30.0)
	if !send {
		t.Error("expected different nodes to not suppress each other")
	}
}

func TestCleanupExpired(t *testing.T) {
	d := newDedupTracker(1*time.Millisecond, 50.0)

	d.shouldSend("node-a", 30.0)
	d.shouldSend("node-b", 30.0)
	time.Sleep(5 * time.Millisecond)

	d.cleanupExpired()

	d.mu.Lock()
	entryCount := len(d.entries)
	d.mu.Unlock()

	if entryCount != 0 {
		t.Errorf("expected all entries cleaned up, got %d", entryCount)
	}
}

func TestShouldSendAboveThresholdNoDedup(t *testing.T) {
	d := newDedupTracker(60*time.Second, 50.0)

	// Events above threshold should always send regardless of dedup
	send, _ := d.shouldSend("node-a", 90.0)
	if !send {
		t.Error("expected high-score event to send")
	}

	// Another high score event should also send (above threshold bypasses dedup)
	send, _ = d.shouldSend("node-a", 95.0)
	if !send {
		t.Error("expected second high-score event to also send")
	}
}

func TestNewServer(t *testing.T) {
	s := NewServer(":0", nil, nil)
	if s == nil {
		t.Fatal("expected non-nil server")
	}
	if s.addr != ":0" {
		t.Errorf("expected addr ':0', got '%s'", s.addr)
	}
	if cap(s.anomalyCh) != 100 {
		t.Errorf("expected anomalyCh buffer 100, got %d", cap(s.anomalyCh))
	}
}
