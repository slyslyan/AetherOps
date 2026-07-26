#!/bin/bash
# 实验 01: 网络延迟注入 (tc netem 200ms)
# 风险等级: LOW
# 验证: tc netem 200ms 网络延迟被 tcp_conntrack RTT 指标捕获，
#   anomaly_score 触发，agent 健康保持，清理恢复完整。
# 机制: tcp_conntrack 测量连接时长 (connect→close)，包含网络延迟，
#   不受 tcp_sendmsg 内核缓冲拷贝 (~μs) 限制。
set -euo pipefail

EXP_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAOS_DIR="$(dirname "$EXP_SCRIPT_DIR")"

source "${CHAOS_DIR}/config.sh"
source "${CHAOS_DIR}/lib/common.sh"
source "${CHAOS_DIR}/lib/ssh-exec.sh"
source "${CHAOS_DIR}/lib/metrics.sh"
source "${CHAOS_DIR}/lib/inject.sh"
source "${CHAOS_DIR}/lib/cleanup.sh"

EXPERIMENT_ID="01"
EXPERIMENT_NAME="Network Latency Injection"
EXPERIMENT_DESCRIPTION="tc netem 200ms 全局延迟，验证 tcp_conntrack RTT 异常检测"

pre_check() {
    log_step "实验 ${EXPERIMENT_ID}: ${EXPERIMENT_NAME} — Pre-Check"
    assert_steady_state || { log_fail "Pre-check 稳态校验失败"; return 1; }
    log_ok "Pre-check 通过"
    return 0
}

inject() {
    log_step "实验 ${EXPERIMENT_ID}: 注入故障"
    inject_netem_delay "200ms"
}

collect_metrics() {
    log_info "故障期指标采集..."
}

verify() {
    log_step "实验 ${EXPERIMENT_ID}: 断言验证"

    local pre_snap="${1}"
    local during_snap="${2}"
    local all_pass=true

    # [CRITICAL] 网络延迟被 conntrack RTT 捕获: latency_increased >= 1 边 ≥ 50ms
    assert_latency_increased "$pre_snap" "$during_snap" 1 50 || all_pass=false

    # [CRITICAL] anomaly_score 触发: 至少 1 条边 anomaly_score > baseline
    assert_anomaly_detected "$pre_snap" "$during_snap" 1 0.01 || all_pass=false

    # [CRITICAL] Agent 健康
    assert_agent_healthy "$pre_snap" "$during_snap" || all_pass=false

    if [ "$all_pass" = true ]; then
        return 0
    else
        return 1
    fi
}

cleanup() {
    log_step "实验 ${EXPERIMENT_ID}: 清理"
    cleanup_netem
    verify_no_residual_rules || true
}

post_check() {
    log_step "实验 ${EXPERIMENT_ID}: 恢复验证"

    local pre_snap="${1}"
    local post_snap="${2}"

    assert_anomaly_cleared "$pre_snap" "$post_snap" || {
        log_warn "anomaly_score 未完全清零 (P95 窗口滚动中)"
        return 1
    }
    assert_steady_state || log_warn "稳态校验未完全通过"
    return 0
}
