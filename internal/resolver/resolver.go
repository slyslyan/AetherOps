package resolver

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const cacheTTL = 30 * time.Second
const maxCacheSize = 1000

// ServiceIdentity 提供 PID 到服务名的解析。
type ServiceIdentity struct {
	mu          sync.RWMutex
	cache       map[uint32]*cacheEntry
	podResolver PodNameResolver // optional K8s pod name lookup
}

type cacheEntry struct {
	name      string
	expiresAt time.Time
}

// PodNameResolver 通过 Pod UID 查询 Pod 名。
type PodNameResolver func(podUID string) string

// NewServiceIdentity 创建服务身份解析器。
func NewServiceIdentity(resolver PodNameResolver) *ServiceIdentity {
	return &ServiceIdentity{
		cache:       make(map[uint32]*cacheEntry),
		podResolver: resolver,
	}
}

// Resolve 根据 PID 返回服务名。
func (r *ServiceIdentity) Resolve(pid uint32, comm string) string {
	r.mu.RLock()
	entry, ok := r.cache[pid]
	r.mu.RUnlock()
	if ok && time.Now().Before(entry.expiresAt) {
		return entry.name
	}

	name := r.resolveSlow(pid, comm)

	r.mu.Lock()
	r.cache[pid] = &cacheEntry{name: name, expiresAt: time.Now().Add(cacheTTL)}
	if len(r.cache) > maxCacheSize {
		r.evictLocked()
	}
	r.mu.Unlock()

	return name
}

func (r *ServiceIdentity) resolveSlow(pid uint32, fallback string) string {
	if name := resolveFromCgroup(pid, r.podResolver); name != "" {
		return name
	}
	if name := resolveFromCmdline(pid); name != "" {
		return name
	}
	return fallback
}

func (r *ServiceIdentity) evictLocked() {
	now := time.Now()
	for pid, entry := range r.cache {
		if now.After(entry.expiresAt) {
			delete(r.cache, pid)
		}
	}
}

func resolveFromCgroup(pid uint32, podResolver PodNameResolver) string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, "pod"); idx >= 0 {
			rest := line[idx:]
			if end := strings.Index(rest, "/"); end > 3 {
				podUID := rest[3:end]
				if podUID != "" {
					if podResolver != nil {
						podName := podResolver(podUID)
						if podName != "" {
							return podName
						}
					}
					if len(podUID) > 12 {
						return "pod-" + podUID[:12]
					}
					return "pod-" + podUID
				}
			}
		}
		if strings.HasPrefix(line, "/docker/") {
			cid := strings.TrimPrefix(line, "/docker/")
			if len(cid) > 12 {
				return "container-" + cid[:12]
			}
		}
	}
	return ""
}

func resolveFromCmdline(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	parts := strings.Split(string(data), "\x00")
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}
	path := parts[0]
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		return path[idx+1:]
	}
	return path
}
