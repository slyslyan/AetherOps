package main

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"regexp"
	"time"

	apperrors "ebpf-autoheal/internal/errors"
	"ebpf-autoheal/internal/metrics"
)

var validIface = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

func (a *App) addDropIP(ipStr string) error {
	if net.ParseIP(ipStr) == nil {
		return fmt.Errorf("invalid IP (%s): %w", ipStr, apperrors.ErrInvalidIP)
	}

	a.tcDropRulesMu.Lock()
	a.tcDropRules[ipStr] = time.Now().Add(a.tcDropTTL)
	a.tcDropRulesMu.Unlock()

	if a.tcDropProg != nil {
		ip := ipToUint32(ipStr)
		if ip != 0 {
			var val uint8
			err := a.tcDropObjs.TcDropIps.Put(ip, val)
			if err == nil {
				slog.Info("eBPF TC drop active", "ip", ipStr, "ttl", a.tcDropTTL)
				metrics.Mitigation.WithLabelValues(ipStr, "ebpf_tc_drop").Inc()
				return nil
			}
			slog.Warn("eBPF TC map write failed, falling back to tc command", "error", err)
		}
	}

	if !validIface.MatchString(a.ifaceName) {
		return fmt.Errorf("invalid interface name (%s): %w", a.ifaceName, apperrors.ErrInvalidIface)
	}

	if out, err := exec.Command("tc", "qdisc", "replace", "dev", a.ifaceName, "root", "handle", "1:", "prio", "bands", "4").CombinedOutput(); err != nil {
		slog.Warn("tc qdisc replace prio failed", "error", err, "output", string(out))
	}
	if out, err := exec.Command("tc", "qdisc", "replace", "dev", a.ifaceName, "parent", "1:3", "netem", "loss", "100%").CombinedOutput(); err != nil {
		slog.Warn("tc qdisc replace netem failed", "error", err, "output", string(out))
	}
	cmd := exec.Command("tc", "filter", "add", "dev", a.ifaceName, "protocol", "ip", "parent", "1:", "prio", "1", "u32",
		"match", "ip", "dst", ipStr, "flowid", "1:3")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("tc command drop failed (%v): %w", err, apperrors.ErrTCCmd)
	}
	slog.Info("tc command drop active", "ip", ipStr, "ttl", a.tcDropTTL)
	metrics.Mitigation.WithLabelValues(ipStr, "tc_cmd_drop").Inc()
	return nil
}

func (a *App) removeDropIP(ipStr string) error {
	a.tcDropRulesMu.Lock()
	delete(a.tcDropRules, ipStr)
	a.tcDropRulesMu.Unlock()

	if a.tcDropProg != nil {
		ip := ipToUint32(ipStr)
		if ip != 0 {
			if err := a.tcDropObjs.TcDropIps.Delete(ip); err != nil {
				return fmt.Errorf("eBPF map delete failed (%v): %w", err, apperrors.ErrTCMapDelete)
			}
			slog.Info("eBPF TC drop removed", "ip", ipStr)
			return nil
		}
	}

	if !validIface.MatchString(a.ifaceName) {
		return fmt.Errorf("invalid interface name (%s): %w", a.ifaceName, apperrors.ErrInvalidIface)
	}
	cmd := exec.Command("tc", "filter", "del", "dev", a.ifaceName, "parent", "1:", "prio", "1", "u32",
		"match", "ip", "dst", ipStr, "flowid", "1:3")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("tc filter delete failed (%v): %w", err, apperrors.ErrTCCmd)
	}
	slog.Info("tc command drop removed", "ip", ipStr)
	return nil
}

func (a *App) cleanupExpiredTCRules() {
	a.tcDropRulesMu.Lock()
	var expired []string
	now := time.Now()
	for ip, expiry := range a.tcDropRules {
		if now.After(expiry) {
			expired = append(expired, ip)
		}
	}
	for _, ip := range expired {
		delete(a.tcDropRules, ip)
	}
	a.tcDropRulesMu.Unlock()

	for _, ip := range expired {
		slog.Info(fmt.Sprintf("TC drop rule expired for IP %s, removing", ip))
		if err := a.removeDropIP(ip); err != nil {
			slog.Info(fmt.Sprintf("remove expired TC drop rule failed: %v", err))
		}
	}
}

func (a *App) removeAllTCRules() {
	a.tcDropRulesMu.Lock()
	defer a.tcDropRulesMu.Unlock()

	if a.tcDropProg != nil && a.tcDropObjs.TcDropIps != nil {
		var ip uint32
		entries := a.tcDropObjs.TcDropIps.Iterate()
		for entries.Next(&ip, nil) {
			a.tcDropObjs.TcDropIps.Delete(ip)
		}
	}
	a.tcDropRules = make(map[string]time.Time)

	if !validIface.MatchString(a.ifaceName) {
		slog.Info(fmt.Sprintf("invalid interface name for TC cleanup: %s", a.ifaceName))
		return
	}
	if err := exec.Command("tc", "filter", "del", "dev", a.ifaceName, "parent", "1:").Run(); err != nil {
		slog.Info(fmt.Sprintf("TC filter cleanup failed: %v", err))
	} else {
		slog.Info("All TC drop rules removed")
	}
}

func ipToUint32(ipStr string) uint32 {
	parsed := net.ParseIP(ipStr)
	if parsed == nil || len(parsed) != 16 {
		return 0
	}
	ipv4 := parsed.To4()
	if ipv4 == nil {
		return 0
	}
	return uint32(ipv4[0]) | uint32(ipv4[1])<<8 | uint32(ipv4[2])<<16 | uint32(ipv4[3])<<24
}
