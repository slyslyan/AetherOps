#!/bin/bash
# cleanup.sh — 故障清理原语（全部幂等：先尝试删除，忽略错误）
# 使用 exec_ssh/exec_sudo 在服务器上执行

# ============================================================
# 全局清理：清除所有可能的故障注入残留
# ============================================================

cleanup_all() {
    log_step "全局故障清理"

    log_info "清除 tc qdisc 规则..."
    exec_sudo "tc qdisc del dev ${SERVER_IFACE} root 2>/dev/null" || true
    exec_sudo "tc qdisc del dev eth0 root 2>/dev/null" || true
    exec_sudo "tc qdisc del dev ens33 root 2>/dev/null" || true
    exec_sudo "tc qdisc del dev cni0 root 2>/dev/null" || true

    log_info "清除 iptables OUTPUT 链..."
    exec_sudo "iptables -D OUTPUT -p tcp --dport ${MYSQL_PORT} -j REJECT --reject-with tcp-reset 2>/dev/null" || true
    exec_sudo "iptables -D OUTPUT -p udp --dport 53 -j DROP 2>/dev/null" || true

    log_info "清除 iptables NAT 表..."
    exec_sudo "iptables -t nat -D OUTPUT -p tcp --dport ${BACKEND_PORT} -j DNAT --to-destination 127.0.0.1:15999 2>/dev/null" || true
    exec_sudo "iptables -t nat -F OUTPUT 2>/dev/null" || true

    log_info "清除网络分区规则..."
    exec_sudo "iptables -D OUTPUT -d 192.168.1.100 -j DROP 2>/dev/null" || true
    exec_sudo "iptables -D INPUT -s 192.168.1.100 -j DROP 2>/dev/null" || true

    log_info "终止 stress-ng 进程..."
    exec_sudo "pkill -9 stress-ng 2>/dev/null" || true

    log_info "终止 mock HTTP 服务器..."
    exec_sudo "pkill -9 -f 'python3.*HTTPServer' 2>/dev/null" || true
    exec_sudo "pkill -9 -f 'python3.*http.server' 2>/dev/null" || true

    log_info "终止 dd 后台进程..."
    exec_sudo "pkill -9 dd 2>/dev/null" || true

    log_ok "全局清理完成"
}

# ============================================================
# 单项清理
# ============================================================

cleanup_netem() {
    log_info "清除 tc netem 规则..."
    exec_sudo "tc qdisc del dev ${SERVER_IFACE} root 2>/dev/null" || true
    exec_sudo "tc qdisc del dev eth0 root 2>/dev/null" || true
    exec_sudo "tc qdisc del dev cni0 root 2>/dev/null" || true
    exec_sudo "tc qdisc del dev ens33 root 2>/dev/null" || true
    log_ok "tc netem 已清除"
}

cleanup_iptables_reject() {
    local port="${1:-${MYSQL_PORT}}"
    log_info "清除 TCP REJECT 规则 (port ${port})..."
    exec_sudo "iptables -D OUTPUT -p tcp --dport ${port} -j REJECT --reject-with tcp-reset 2>/dev/null" || true
    log_ok "TCP REJECT 已清除"
}

cleanup_iptables_drop() {
    log_info "清除 DNS DROP 规则..."
    exec_sudo "iptables -D OUTPUT -p udp --dport 53 -j DROP 2>/dev/null" || true
    log_ok "DNS DROP 已清除"
}

cleanup_iptables_dnat() {
    log_info "清除 DNAT 规则..."
    exec_sudo "iptables -t nat -D OUTPUT -p tcp --dport ${BACKEND_PORT} -j DNAT --to-destination 127.0.0.1:15999 2>/dev/null" || true
    exec_sudo "iptables -t nat -F OUTPUT 2>/dev/null" || true
    log_ok "DNAT 规则已清除"
}

cleanup_cpu_stress() {
    log_info "终止 CPU 压力进程..."
    exec_sudo "pkill -9 stress-ng 2>/dev/null" || true
    exec_sudo "pkill -9 dd 2>/dev/null" || true
    log_ok "CPU 压力进程已终止"
}

cleanup_mock_http() {
    log_info "终止 mock HTTP 服务器..."
    exec_sudo "pkill -9 -f 'python3.*HTTPServer' 2>/dev/null" || true
    exec_sudo "pkill -9 -f 'python3.*http.server' 2>/dev/null" || true
    log_ok "Mock HTTP 服务器已终止"
}

cleanup_partition() {
    local target_ip="${1:-192.168.1.100}"
    log_info "清除网络分区规则 (${target_ip})..."
    exec_sudo "iptables -D OUTPUT -d ${target_ip} -j DROP 2>/dev/null" || true
    exec_sudo "iptables -D INPUT -s ${target_ip} -j DROP 2>/dev/null" || true
    log_ok "网络分区已清除"
}

# ============================================================
# 验证清理：确认无残留故障规则
# ============================================================

verify_no_residual_rules() {
    log_info "验证无残留故障规则..."

    local tc_rules ipt_out ipt_nat stress_procs
    tc_rules=$(exec_sudo "tc qdisc show 2>/dev/null | grep -c netem || true" 2>/dev/null)
    tc_rules=$(echo "${tc_rules:-0}" | tail -1 | tr -d '\n')
    ipt_out=$(exec_sudo "iptables -S OUTPUT 2>/dev/null | grep -cE 'REJECT|DROP' || true" 2>/dev/null)
    ipt_out=$(echo "${ipt_out:-0}" | tail -1 | tr -d '\n')
    ipt_nat=$(exec_sudo "iptables -t nat -S OUTPUT 2>/dev/null | grep -c DNAT || true" 2>/dev/null)
    ipt_nat=$(echo "${ipt_nat:-0}" | tail -1 | tr -d '\n')
    stress_procs=$(exec_sudo "pgrep -c 'stress-ng|python3.*HTTPServer' 2>/dev/null || true" 2>/dev/null)
    stress_procs=$(echo "${stress_procs:-0}" | tail -1 | tr -d '\n')

    local clean=true

    if [ "${tc_rules:-0}" -gt 0 ]; then
        log_warn "发现 ${tc_rules} 条 tc netem 规则残留"
        clean=false
    fi
    if [ "${ipt_out:-0}" -gt 0 ]; then
        log_warn "发现 ${ipt_out} 条 iptables REJECT/DROP 规则残留"
        clean=false
    fi
    if [ "${ipt_nat:-0}" -gt 0 ]; then
        log_warn "发现 ${ipt_nat} 条 iptables NAT DNAT 规则残留"
        clean=false
    fi
    if [ "${stress_procs:-0}" -gt 0 ]; then
        log_warn "发现 ${stress_procs} 个 stress/mock 进程残留"
        clean=false
    fi

    if [ "$clean" = true ]; then
        log_ok "无残留故障规则"
        return 0
    else
        log_warn "存在残留故障规则，已打印详情（可手动运行 cleanup_all）"
        return 1
    fi
}
