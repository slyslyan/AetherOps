package remediation

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"ebpf-autoheal/internal/config"
	"ebpf-autoheal/internal/graph"
)

func newTestConfig() *config.Config {
	return &config.Config{
		ProfileDurationSec: 5,
	}
}

type mockPolicyChecker struct{}

func (m mockPolicyChecker) CheckBeforeMitigation(suspect graph.Suspicion) bool {
	return true
}

type denyPolicyChecker struct{}

func (d denyPolicyChecker) CheckBeforeMitigation(suspect graph.Suspicion) bool {
	return false
}

func TestNewService(t *testing.T) {
	s := NewService(newTestConfig(), mockPolicyChecker{})
	if s == nil {
		t.Fatal("expected non-nil service")
	}
	if s.httpClient == nil {
		t.Error("expected httpClient to be initialized")
	}
	if s.httpClient.Timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", s.httpClient.Timeout)
	}
	if s.protected["127.0.0.1"] != true {
		t.Error("expected 127.0.0.1 to be protected")
	}
	if s.protected["::1"] != true {
		t.Error("expected ::1 to be protected")
	}
	if s.outputDir == "" {
		t.Error("expected outputDir to be set")
	}
}

func TestNewServiceCustomOutputDir(t *testing.T) {
	tmpDir := t.TempDir()
	os.Setenv("AETHEROPS_OUTPUT_DIR", tmpDir)
	defer os.Unsetenv("AETHEROPS_OUTPUT_DIR")

	s := NewService(newTestConfig(), mockPolicyChecker{})
	if s.outputDir != tmpDir {
		t.Errorf("expected outputDir %s, got %s", tmpDir, s.outputDir)
	}
}

func TestOutputFile(t *testing.T) {
	tmpDir := t.TempDir()
	defer os.Unsetenv("AETHEROPS_OUTPUT_DIR")

	s := NewService(newTestConfig(), mockPolicyChecker{})
	s.outputDir = tmpDir

	f, err := s.outputFile("test-*.txt")
	if err != nil {
		t.Fatalf("outputFile failed: %v", err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	if filepath.Dir(f.Name()) != tmpDir {
		t.Errorf("expected file in %s, got %s", tmpDir, f.Name())
	}
	if _, err := os.Stat(f.Name()); err != nil {
		t.Errorf("expected file to exist: %v", err)
	}
}

func TestCleanupOldOutput(t *testing.T) {
	tmpDir := t.TempDir()

	oldFile := filepath.Join(tmpDir, "old.txt")
	os.WriteFile(oldFile, []byte("old"), 0644)
	os.Chtimes(oldFile, time.Now().Add(-2*time.Hour), time.Now().Add(-2*time.Hour))

	newFile := filepath.Join(tmpDir, "new.txt")
	os.WriteFile(newFile, []byte("new"), 0644)

	s := NewService(newTestConfig(), mockPolicyChecker{})
	s.outputDir = tmpDir
	s.cleanupOldOutput()

	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Errorf("expected old file to be deleted")
	}
	if _, err := os.Stat(newFile); err != nil {
		t.Errorf("expected new file to still exist: %v", err)
	}
}

func TestPerformMitigationNoSuspects(t *testing.T) {
	s := NewService(newTestConfig(), mockPolicyChecker{})
	s.PerformMitigation(nil, nil, nil, nil)
}

func TestPerformMitigationPolicyDenied(t *testing.T) {
	s := NewService(newTestConfig(), denyPolicyChecker{})
	suspects := []graph.Suspicion{
		{Node: "192.168.1.1:8080", Score: 95, IsIPPort: true},
	}
	s.PerformMitigation(suspects, nil, nil, nil)
}

func TestPerformMitigationNonIPNode(t *testing.T) {
	s := NewService(newTestConfig(), mockPolicyChecker{})
	suspects := []graph.Suspicion{
		{Node: "my-service", Score: 95, IsIPPort: false},
	}
	s.PerformMitigation(suspects, nil, nil, nil)
}

func TestPerformMitigationProtectedIP(t *testing.T) {
	s := NewService(newTestConfig(), mockPolicyChecker{})
	suspects := []graph.Suspicion{
		{Node: "127.0.0.1:8080", Score: 95, IsIPPort: true},
	}
	s.PerformMitigation(suspects, nil, nil, nil)
}

func TestPerformMitigationInvalidIP(t *testing.T) {
	s := NewService(newTestConfig(), mockPolicyChecker{})
	suspects := []graph.Suspicion{
		{Node: "not-an-ip:8080", Score: 95, IsIPPort: true},
	}
	s.PerformMitigation(suspects, nil, nil, nil)
}

func TestRunWithTimeout(t *testing.T) {
	err := runWithTimeout(exec.Command("sleep", "0"), time.Second)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestOutputDirCreated(t *testing.T) {
	tmpDir := filepath.Join(t.TempDir(), "nonexistent", "subdir")
	os.Setenv("AETHEROPS_OUTPUT_DIR", tmpDir)
	defer os.Unsetenv("AETHEROPS_OUTPUT_DIR")

	s := NewService(newTestConfig(), mockPolicyChecker{})
	if _, err := os.Stat(s.outputDir); os.IsNotExist(err) {
		t.Errorf("expected output dir %s to be created", s.outputDir)
	}
}
