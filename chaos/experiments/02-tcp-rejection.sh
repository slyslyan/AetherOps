#!/bin/bash
# 实验 02: TCP 连接拒绝 (iptables REJECT MySQL 端口)
# 风险等级: HIGH
# 已知局限: iptables REJECT 在 netfilter 层发生，早于 TCP 协议栈处理，
#   eBPF kprobe (tcp_sendmsg/tcp_connect) 无法观测被 iptables 拒绝的连接。
#   ebpf_edge_errors_total 统计 TCP 层错误 (RST/timeout)，不含 netfilter 级拒绝。
# 实验价值: 验证注入/清理流程 + agent 对 iptables 操作的容忍度。
set -euo pipefail

EXP_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAOS_DIR="$(dirname "$EXP_SCRIPT_DIR")"

source "${CHAOS_DIR}/config.sh"
source "${CHAOS_DIR}/lib/common.sh"
source "${CHAOS_DIR}/lib/ssh-exec.sh"
source "${CHAOS_DIR}/lib/metrics.sh"
source "${CHAOS_DIR}/lib/inject.sh"
source "${CHAOS_DIR}/lib/cleanup.sh"

EXPERIMENT_ID="02"
EXPERIMENT_NAME="TCP Connection Rejection"
EXPERIMENT_DESCRIPTION="iptables REJECT MySQL 端口，验证 agent 容忍 iptables 操作 + 清理恢复"

pre_check() {
    log_step "实验 ${EXPERIMENT_ID}: ${EXPERIMENT_NAME} — Pre-Check"
    assert_steady_state || { log_fail "Pre-check 稳态校验失败"; return 1; }
    log_ok "Pre-check 通过"
    return 0
}

inject() {
    log_step "实验 ${EXPERIMENT_ID}: 注入故障"
    inject_tcp_reject "${MYSQL_PORT}"
    # 尝试生成 MySQL 连接流量（验证规则生效）
    exec_sudo "timeout 2 bash -c 'for i in 1 2 3; do echo >/dev/tcp/${CHAOS_SSH_HOST}/${MYSQL_PORT} 2>\&1; done'" 2>/dev/null || true
    log_info "MySQL 连接测试完成 (预期被 iptables REJECT)"
}

collect_metrics() {
    log_info "故障期指标采集..."
}

verify() {
    log_step "实验 ${EXPERIMENT_ID}: 断言验证"

    local pre_snap="${1}"
    local during_snap="${2}"
    local all_pass=true

    # [INFO] iptables REJECT 不可被 eBPF TCP kprobe 观测（netfilter 层早于 TCP 栈）
    log_info "iptables REJECT 在 netfilter 层 (已知局限: eBPF kprobe 在 TCP 层，无法观测)"

    # [INFO] errors 变化（预期不增加：REJECT 不经过 TCP 栈）
    assert_errors_increased "$pre_snap" "$during_snap" "3306" 1 || \
        log_info "errors_total 未增加 (已知局限: iptables REJECT 在 netfilter 层早于 TCP 栈)"

    # [PASS] Agent 健康
    assert_agent_healthy "$pre_snap" "$during_snap" || all_pass=false

    if [ "$all_pass" = true ]; then
        return 0
    else
        return 1
    fi
}

cleanup() {
    log_step "实验 ${EXPERIMENT_ID}: 清理"
    cleanup_iptables_reject "${MYSQL_PORT}"
    verify_no_residual_rules || true
}

post_check() {
    log_step "实验 ${EXPERIMENT_ID}: 恢复验证"

    local pre_snap="${1}"
    local post_snap="${2}"

    # 验证 iptables 规则已清除
    local ipt_count post_ipt
    ipt_count=$(exec_sudo "iptables -S OUTPUT 2>/dev/null | grep -cE 'REJECT|DROP' || true" 2>/dev/null)
    ipt_count=$(echo "${ipt_count:-0}" | tail -1 | tr -d '\n')
    if [ "${ipt_count:-0}" -gt 0 ]; then
        log_warn "iptables 残留 ${ipt_count} 条规则"
        return 1
    fi
    log_ok "iptables 规则已清除"

    assert_steady_state || log_warn "稳态校验未完全通过"
    return 0
}
