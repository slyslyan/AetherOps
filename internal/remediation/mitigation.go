package remediation

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ebpf-autoheal/internal/config"
	apperrors "ebpf-autoheal/internal/errors"
	"ebpf-autoheal/internal/graph"
)

const maxResponseBody = 16 << 20

type TCExecutor interface {
	AddDropIP(ip string) error
	RemoveDropIP(ip string) error
	RemoveAll() error
}

type K8sClient interface {
	RestartPodByIP(ip string) error
	GetPodByIP(ip string) (string, string, error)
}

type PolicyChecker interface {
	CheckBeforeMitigation(suspect graph.Suspicion) bool
}

type Service struct {
	cfg            *config.Config
	policy         PolicyChecker
	protected      map[string]bool
	httpClient     *http.Client
	outputDir      string
	cooldown       *config.Cooldown
	lockoutTracker *LockoutTracker
	canaryExecutor *CanaryExecutor
}

// allowAllPolicy 在策略检查器为 nil 时作为默认值，允许所有自愈操作。
type allowAllPolicy struct{}

func (a *allowAllPolicy) CheckBeforeMitigation(suspect graph.Suspicion) bool { return true }

func NewService(cfg *config.Config, pc PolicyChecker) *Service {
	if cfg == nil {
		cfg = &config.Config{MitigationCooldownSec: 120}
	}
	if pc == nil {
		pc = &allowAllPolicy{}
	}
	outputDir := os.Getenv("AETHEROPS_OUTPUT_DIR")
	if outputDir == "" {
		home, _ := os.UserHomeDir()
		outputDir = filepath.Join(home, ".aetherops", "output")
	}
	os.MkdirAll(outputDir, 0755)

	return &Service{
		cfg:    cfg,
		policy: pc,
		protected: map[string]bool{
			"127.0.0.1": true,
			"::1":       true,
		},
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		outputDir:      outputDir,
		cooldown:       config.NewCooldown(time.Duration(cfg.MitigationCooldownSec) * time.Second),
		lockoutTracker: NewLockoutTracker(DefaultLockoutConfig()),
		canaryExecutor: NewCanaryExecutor(DefaultCanaryConfig()),
	}
}

func (s *Service) outputFile(pattern string) (*os.File, error) {
	return os.CreateTemp(s.outputDir, pattern)
}

func (s *Service) PerformMitigation(suspects []graph.Suspicion, g *graph.ServiceGraph, tcDrop TCExecutor, k8s K8sClient) {
	if len(suspects) == 0 {
		return
	}

	// Dry Run 影子模式：全流程诊断 + 决策，但不实际执行自愈指令
	if s.cfg.DryRun {
		slog.Info("[DryRun] 影子模式已启用 — 仅记录 AI 决策，不执行自愈")
		for i, suspect := range suspects {
			slog.Info(fmt.Sprintf("[DryRun] suspect #%d %s (score %.2f) — 策略检查通过，但未实际执行",
				i+1, suspect.Node, suspect.Score))
		}
		s.sendAlert(suspects, nil)
		return
	}

	var flameFiles []string

	// Walk the suspect chain: try each suspect in order (highest score first).
	// If the top suspect is blocked by policy, fall through to the next one.
	for i, suspect := range suspects {
		if !s.policy.CheckBeforeMitigation(suspect) {
			slog.Info(fmt.Sprintf("mitigation: suspect #%d %s blocked by policy, walking chain...", i+1, suspect.Node))
			continue
		}

		// Anti-Flapping 防抖：检查冷却期，防止对同一节点反复自愈
		if s.cooldown.IsOnCooldown(suspect.Node) {
			slog.Info(fmt.Sprintf("mitigation: suspect #%d %s is on cooldown — 冷却期内拒绝自动执行，升级为人工审批",
				i+1, suspect.Node))
			continue
		}

		// 频繁自愈锁定检查
		if locked, reason := s.lockoutTracker.Record(suspect.Node, ActionTCPDrop); locked {
			slog.Warn(fmt.Sprintf("mitigation: suspect #%d %s LOCKED -- %s", i+1, suspect.Node, reason))
			continue
		}

		// 爆炸半径门控
		if g != nil {
			gate := GateByBlastRadius(g, suspect.Node)
			if !gate.Allowed {
				slog.Warn(fmt.Sprintf("mitigation: suspect #%d %s blocked by blast radius -- %s", i+1, suspect.Node, gate.Reason))
				continue
			}
			if gate.EscalateHuman {
				slog.Warn(fmt.Sprintf("mitigation: suspect #%d %s requires human review -- %s", i+1, suspect.Node, gate.Reason))
			}
		}

		slog.Info(fmt.Sprintf("mitigation triggered: suspect #%d %s (score %.2f)", i+1, suspect.Node, suspect.Score))

		if suspect.IsIPPort {
			parts := strings.Split(suspect.Node, ":")
			if len(parts) != 2 {
				continue
			}
			ip := parts[0]
			port := parts[1]

			if net.ParseIP(ip) == nil {
				slog.Info(fmt.Sprintf("   -> invalid IP from suspect: %s, skipping", ip))
				continue
			}

			if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
				slog.Info(fmt.Sprintf("   -> invalid port from suspect: %s, skipping", port))
				continue
			}

			if tcDrop == nil {
				slog.Info(fmt.Sprintf("   -> TC executor not configured, skipping TC drop for %s", ip))
			} else if s.protected[ip] {
				slog.Info(fmt.Sprintf("   -> protected IP, skipping: %s", ip))
			} else if err := tcDrop.AddDropIP(ip); err != nil {
				slog.Info(fmt.Sprintf("   -> TC drop failed: %v", err))
			}

			if svg, err := s.fetchCPUProfileSVG(ip, port); err == nil {
				f, _ := s.outputFile("cpu-*.svg")
				if f != nil {
					f.Write(svg)
					flameFiles = append(flameFiles, f.Name())
					f.Close()
				}
			}
			if heapSVG, err := s.fetchHeapProfileSVG(ip, port); err == nil {
				f, _ := s.outputFile("heap-*.svg")
				if f != nil {
					f.Write(heapSVG)
					flameFiles = append(flameFiles, f.Name())
					f.Close()
				}
			}
			if gorData, err := s.fetchText(fmt.Sprintf("http://%s/debug/pprof/goroutine?debug=2", joinHostPort(ip, port)), "goroutine dump"); err == nil {
				f, _ := s.outputFile("goroutine-*.txt")
				if f != nil {
					f.Write(gorData)
					flameFiles = append(flameFiles, f.Name())
					f.Close()
				}
			}
			if threadData, err := s.fetchText(fmt.Sprintf("http://%s/debug/pprof/threadcreate?debug=1", joinHostPort(ip, port)), "thread dump"); err == nil {
				f, _ := s.outputFile("thread-*.txt")
				if f != nil {
					f.Write(threadData)
					flameFiles = append(flameFiles, f.Name())
					f.Close()
				}
			}
			s.capturePackets(ip, s.cfg.ProfileDurationSec)
		} else {
			slog.Info(fmt.Sprintf("   -> non-IP:Port node, mitigation not supported: %s", suspect.Node))
		}

		s.cooldown.Set(suspect.Node)
		s.sendAlert(suspects, flameFiles)
		s.cleanupOldOutput()
		return
	}

	// All suspects blocked by policy or on cooldown.
	slog.Info("mitigation: all suspects blocked, no action taken")
	s.sendAlert(suspects, flameFiles)
}

func (s *Service) fetchCPUProfileSVG(targetIP, targetPort string) ([]byte, error) {
	url := fmt.Sprintf("http://%s/debug/pprof/profile?seconds=%d", joinHostPort(targetIP, targetPort), s.cfg.ProfileDurationSec)
	return s.fetchPprofSVG(url, "cpu profile")
}

func (s *Service) fetchHeapProfileSVG(targetIP, targetPort string) ([]byte, error) {
	url := fmt.Sprintf("http://%s/debug/pprof/heap", joinHostPort(targetIP, targetPort))
	return s.fetchPprofSVG(url, "heap profile")
}

func (s *Service) fetchPprofSVG(url, desc string) ([]byte, error) {
	slog.Info(fmt.Sprintf("   -> fetching %s: %s", desc, url))
	resp, err := s.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("request %s failed (%v): %w", desc, err, apperrors.ErrHTTPRequest)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
		return nil, fmt.Errorf("%s returned %d (%s): %w", desc, resp.StatusCode, string(body), apperrors.ErrHTTPRequest)
	}
	profileData, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("read %s failed (%v): %w", desc, err, apperrors.ErrHTTPRequest)
	}
	tmpProfile, err := os.CreateTemp("", "profile-*.pb.gz")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpProfile.Name())
	if _, err := tmpProfile.Write(profileData); err != nil {
		return nil, err
	}
	tmpProfile.Close()

	tmpSVG, err := os.CreateTemp("", "flame-*.svg")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpSVG.Name())
	tmpSVG.Close()

	cmd := exec.Command("go", "tool", "pprof", "-svg", "-output", tmpSVG.Name(), tmpProfile.Name())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := runWithTimeout(cmd, 5*time.Minute); err != nil {
		return nil, fmt.Errorf("generate flamegraph failed (%v, stderr: %s): %w", err, stderr.String(), apperrors.ErrPprofGen)
	}
	svgData, err := os.ReadFile(tmpSVG.Name())
	if err != nil {
		return nil, fmt.Errorf("read SVG failed (%v): %w", err, apperrors.ErrPprofGen)
	}
	slog.Info(fmt.Sprintf("   -> %s flamegraph generated, size %d bytes", desc, len(svgData)))
	return svgData, nil
}

func (s *Service) fetchText(url, desc string) ([]byte, error) {
	slog.Info(fmt.Sprintf("   -> fetching %s: %s", desc, url))
	resp, err := s.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
		return nil, fmt.Errorf("%s returned %d (%s): %w", desc, resp.StatusCode, string(body), apperrors.ErrHTTPRequest)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, err
	}
	slog.Info(fmt.Sprintf("   -> %s fetched, size %d bytes", desc, len(data)))
	return data, nil
}

func (s *Service) capturePackets(targetIP string, durationSec int) {
	if net.ParseIP(targetIP) == nil {
		slog.Info(fmt.Sprintf("   -> invalid IP for packet capture: %s", targetIP))
		return
	}
	f, err := s.outputFile("capture-*.pcap")
	if err != nil {
		slog.Info(fmt.Sprintf("   -> create capture file failed: %v", err))
		return
	}
	fname := f.Name()
	f.Close()

	slog.Info(fmt.Sprintf("   -> capturing packets for IP %s, duration %ds, file %s", targetIP, durationSec, fname))
	cmd := exec.Command("tcpdump", "-i", "any", "-w", fname, "-s", "0", "-W", "1", "-G", fmt.Sprintf("%d", durationSec), "host", targetIP)
	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()
	select {
	case <-time.After(time.Duration(durationSec+2) * time.Second):
		cmd.Process.Signal(syscall.SIGTERM)
		if fi, err := os.Stat(fname); err == nil && fi.Size() > 100<<20 {
			os.Remove(fname)
			slog.Info(fmt.Sprintf("   -> capture too large (%d bytes), removed", fi.Size()))
		} else {
			slog.Info(fmt.Sprintf("   -> capture saved: %s (%d bytes)", fname, fi.Size()))
		}
	case err := <-done:
		if err != nil {
			slog.Info(fmt.Sprintf("   -> capture failed: %v", err))
		} else if fi, err := os.Stat(fname); err == nil {
			slog.Info(fmt.Sprintf("   -> capture saved: %s (%d bytes)", fname, fi.Size()))
		}
	}
}

func (s *Service) sendAlert(suspects []graph.Suspicion, flameFilenames []string) {
	webhookURL := os.Getenv("FEISHU_WEBHOOK")
	if webhookURL == "" {
		slog.Info("   -> Feishu webhook not configured, skipping")
		return
	}

	var sb strings.Builder
	sb.WriteString("【eBPF Root Cause Alert】\n")
	sb.WriteString(fmt.Sprintf("Time: %s\n", time.Now().Format("15:04:05")))
	sb.WriteString("Suspects:\n")
	for i, s := range suspects {
		if i >= 3 {
			break
		}
		sb.WriteString(fmt.Sprintf("- %s (score: %.2f, avg latency: %.2f ms, calls: %d)\n",
			s.Node, s.Score, s.AvgLat, s.CallCount))
	}
	if len(flameFilenames) > 0 {
		sb.WriteString("Flamegraph files: ")
		for _, f := range flameFilenames {
			sb.WriteString(f + " ")
		}
		sb.WriteString("\n")
	}
	sb.WriteString("Please investigate.")

	payload := fmt.Sprintf(`{"msg_type":"text","content":{"text":"%s"}}`, sb.String())
	resp, err := s.httpClient.Post(webhookURL, "application/json", bytes.NewBufferString(payload))
	if err != nil {
		slog.Info(fmt.Sprintf("   -> Feishu notification failed: %v", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
		slog.Info(fmt.Sprintf("   -> Feishu notification error: %d %s", resp.StatusCode, string(body)))
	} else {
		slog.Info("   -> Feishu notification sent")
	}
}

func (s *Service) cleanupOldOutput() {
	entries, err := os.ReadDir(s.outputDir)
	if err != nil {
		return
	}
	deadline := time.Now().Add(-1 * time.Hour)
	for _, e := range entries {
		fi, err := e.Info()
		if err == nil && fi.ModTime().Before(deadline) {
			os.Remove(filepath.Join(s.outputDir, e.Name()))
		}
	}
}

func runWithTimeout(cmd *exec.Cmd, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	go func() {
		<-ctx.Done()
		if cmd.Process != nil {
			cmd.Process.Signal(syscall.SIGTERM)
		}
	}()
	return cmd.Run()
}

func joinHostPort(ip, port string) string {
	if net.ParseIP(ip) != nil && net.ParseIP(ip).To4() == nil {
		return fmt.Sprintf("[%s]:%s", ip, port)
	}
	return fmt.Sprintf("%s:%s", ip, port)
}
