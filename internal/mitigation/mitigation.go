package mitigation

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	apperrors "ebpf-autoheal/internal/errors"
	"ebpf-autoheal/internal/config"
	"ebpf-autoheal/internal/graph"
)

// 最大响应体大小：16MB
const maxResponseBody = 16 << 20

// TCExecutor 封装 eBPF TC 丢包操作。
type TCExecutor interface {
	AddDropIP(ip string) error
	RemoveDropIP(ip string) error
	RemoveAll() error
}

// K8sClient 封装 K8s Pod 操作。
type K8sClient interface {
	RestartPodByIP(ip string) error
	GetPodByIP(ip string) (string, string, error) // namespace, name, error
}

// PolicyChecker 提供策略检查能力。
type PolicyChecker interface {
	CheckBeforeMitigation(suspects []graph.Suspicion) bool
}

// Service 管理自愈操作。
type Service struct {
	cfg        *config.Config
	policy     PolicyChecker
	protected  map[string]bool
	httpClient *http.Client
	outputDir  string
}

// NewService 创建自愈服务。
func NewService(cfg *config.Config, pc PolicyChecker) *Service {
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
		httpClient: &http.Client{Timeout: 10 * time.Second},
		outputDir:  outputDir,
	}
}

// outputFile 在输出目录中创建文件并返回完整路径。
func (s *Service) outputFile(pattern string) (*os.File, error) {
	return os.CreateTemp(s.outputDir, pattern)
}

// PerformMitigation 对嫌疑节点执行自愈操作。
func (s *Service) PerformMitigation(suspects []graph.Suspicion, tcDrop TCExecutor, k8s K8sClient) {
	if len(suspects) == 0 {
		return
	}
	top := suspects[0]

	if !s.policy.CheckBeforeMitigation(suspects) {
		slog.Info(fmt.Sprintf("mitigation: policy guard denied action for %s, skipping", top.Node))
		return
	}

	slog.Info(fmt.Sprintf("mitigation triggered: suspect %s (score %.2f)", top.Node, top.Score))

	var flameFiles []string

	if top.IsIPPort {
		parts := strings.Split(top.Node, ":")
		if len(parts) != 2 {
			return
		}
		ip := parts[0]
		port := parts[1]

		// 验证 IP 格式，防止 SSRF / 路径遍历
		if net.ParseIP(ip) == nil {
			slog.Info(fmt.Sprintf("   -> invalid IP from suspect: %s, skipping mitigation", ip))
			return
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
		if gorData, err := s.fetchText(fmt.Sprintf("http://%s:%s/debug/pprof/goroutine?debug=2", ip, port), "goroutine dump"); err == nil {
			f, _ := s.outputFile("goroutine-*.txt")
			if f != nil {
				f.Write(gorData)
				flameFiles = append(flameFiles, f.Name())
				f.Close()
			}
		}
		if threadData, err := s.fetchText(fmt.Sprintf("http://%s:%s/debug/pprof/threadcreate?debug=1", ip, port), "thread dump"); err == nil {
			f, _ := s.outputFile("thread-*.txt")
			if f != nil {
				f.Write(threadData)
				flameFiles = append(flameFiles, f.Name())
				f.Close()
			}
		}
		s.capturePackets(ip, s.cfg.ProfileDurationSec)
	} else {
		slog.Info(fmt.Sprintf("   -> non-IP:Port node, mitigation not supported: %s", top.Node))
	}

	s.sendAlert(suspects, flameFiles)
	s.cleanupOldOutput()
}

// ---- pprof 火焰图 ----

func (s *Service) fetchCPUProfileSVG(targetIP, targetPort string) ([]byte, error) {
	url := fmt.Sprintf("http://%s:%s/debug/pprof/profile?seconds=%d", targetIP, targetPort, s.cfg.ProfileDurationSec)
	return s.fetchPprofSVG(url, "cpu profile")
}

func (s *Service) fetchHeapProfileSVG(targetIP, targetPort string) ([]byte, error) {
	url := fmt.Sprintf("http://%s:%s/debug/pprof/heap", targetIP, targetPort)
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
	cmd = withTimeoutDefault(cmd)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
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

// ---- tcpdump ----

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
		// 限制 pcap 文件大小
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

// ---- 飞书通知 ----

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

// cleanupOldOutput 清理超过 1 小时的旧输出文件。
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

// withTimeoutDefault 为命令添加默认超时（5 分钟）。
func withTimeoutDefault(cmd *exec.Cmd) *exec.Cmd {
	timer := time.AfterFunc(5*time.Minute, func() {
		cmd.Process.Signal(syscall.SIGTERM)
	})
	go func() {
		cmd.Wait()
		timer.Stop()
	}()
	return cmd
}
