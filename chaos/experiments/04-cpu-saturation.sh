#!/bin/bash
# 实验 04: CPU 饱和 (stress-ng)
# 风险等级: LOW
# 验证: CPU 饱和增加内核处理延迟，eBPF agent 在 CPU 压力下保持健康
set -euo pipefail

EXP_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAOS_DIR="$(dirname "$EXP_SCRIPT_DIR")"

source "${CHAOS_DIR}/config.sh"
source "${CHAOS_DIR}/lib/common.sh"
source "${CHAOS_DIR}/lib/ssh-exec.sh"
source "${CHAOS_DIR}/lib/metrics.sh"
source "${CHAOS_DIR}/lib/inject.sh"
source "${CHAOS_DIR}/lib/cleanup.sh"

EXPERIMENT_ID="04"
EXPERIMENT_NAME="CPU Saturation"
EXPERIMENT_DESCRIPTION="stress-ng 打满 CPU，验证 eBPF agent 在 CPU 压力下保持健康 + 错误率不异常升高"

pre_check() {
    log_step "实验 ${EXPERIMENT_ID}: ${EXPERIMENT_NAME} — Pre-Check"
    assert_steady_state || { log_fail "Pre-check 稳态校验失败"; return 1; }
    log_ok "Pre-check 通过"
    return 0
}

inject() {
    log_step "实验 ${EXPERIMENT_ID}: 注入故障"
    inject_cpu_stress 2 60
    sleep 10
}

collect_metrics() {
    log_info "等待 CPU 压力生效..."
}

verify() {
    log_step "实验 ${EXPERIMENT_ID}: 断言验证"

    local pre_snap="${1}"
    local during_snap="${2}"
    local all_pass=true

    # [CRITICAL] 错误率不应该显著增加（区分 CPU vs 网络故障）
    local pre_errors during_errors
    pre_errors=$(grep "^ebpf_edge_errors_total{" "$pre_snap" 2>/dev/null | awk '{s+=$NF} END {printf "%.0f", s}')
    during_errors=$(grep "^ebpf_edge_errors_total{" "$during_snap" 2>/dev/null | awk '{s+=$NF} END {printf "%.0f", s}')
    pre_errors=$(echo "${pre_errors:-0}" | head -1 | tr -d '\n')
    during_errors=$(echo "${during_errors:-0}" | head -1 | tr -d '\n')
    local error_diff
    error_diff=$(awk "BEGIN {printf \"%.0f\", (${during_errors}) - (${pre_errors})}")
    log_info "Errors: ${pre_errors} -> ${during_errors} (+${error_diff})"
    if [ "$(awk "BEGIN {print (${error_diff} <= 2)}")" = "1" ]; then
        log_ok "错误率未显著增加 (符合 CPU 饱和特征)"
        assert_record "cpu_throttle_errors_low" "PASS" "+${error_diff}" "<= 2"
    else
        log_warn "错误率增加 +${error_diff}"
        assert_record "cpu_throttle_errors_low" "FAIL" "+${error_diff}" "<= 2"
        all_pass=false
    fi

    # [INFO] 异常分数（CPU 增加内核延迟，可能触发检测）
    assert_anomaly_detected "$pre_snap" "$during_snap" 1 0.01 || \
        log_info "anomaly_score 未触发 (已知局限: lifetime AvgLat 需要累积)"

    # [CRITICAL] Agent 必须在 CPU 压力下保持健康
    assert_agent_healthy "$pre_snap" "$during_snap" || all_pass=false

    if [ "$all_pass" = true ]; then
        return 0
    else
        return 1
    fi
}

cleanup() {
    log_step "实验 ${EXPERIMENT_ID}: 清理"
    cleanup_cpu_stress
    verify_no_residual_rules || true
}

post_check() {
    log_step "实验 ${EXPERIMENT_ID}: 恢复验证"

    local pre_snap="${1}"
    local post_snap="${2}"

    assert_anomaly_cleared "$pre_snap" "$post_snap" || log_warn "anomaly_score 未完全清零"
    assert_steady_state || log_warn "稳态校验未完全通过"
    return 0
}
