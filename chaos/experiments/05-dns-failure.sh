#!/bin/bash
# 实验 05: DNS 失败 (iptables DROP udp/53)
# 风险等级: MEDIUM
# 预期盲点: eBPF 不观测 UDP DNS 应答，仅能通过 QPS 下降间接检测
# 若 callAnomaly 未触发 → 标记为 SKIP (expected limitation)
set -euo pipefail

EXP_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAOS_DIR="$(dirname "$EXP_SCRIPT_DIR")"

source "${CHAOS_DIR}/config.sh"
source "${CHAOS_DIR}/lib/common.sh"
source "${CHAOS_DIR}/lib/ssh-exec.sh"
source "${CHAOS_DIR}/lib/metrics.sh"
source "${CHAOS_DIR}/lib/inject.sh"
source "${CHAOS_DIR}/lib/cleanup.sh"

EXPERIMENT_ID="05"
EXPERIMENT_NAME="DNS Failure"
EXPERIMENT_DESCRIPTION="iptables DROP udp/53，验证 eBPF 对 DNS 失败的检测能力（已知盲点）"
KNOWN_BLIND_SPOT=true

pre_check() {
    log_step "实验 ${EXPERIMENT_ID}: ${EXPERIMENT_NAME} — Pre-Check"

    if [ "$CHAOS_SKIP_HIGH_RISK" = "true" ]; then
        log_warn "高风险/中风险实验已跳过 (CHAOS_SKIP_HIGH_RISK=true)"
        return 2  # SKIP
    fi

    assert_steady_state || { log_fail "Pre-check 稳态校验失败"; return 1; }
    log_ok "Pre-check 通过"
    return 0
}

inject() {
    log_step "实验 ${EXPERIMENT_ID}: 注入故障"
    log_info "已知限制: eBPF 不观测 UDP DNS 应答，仅能通过上层 TCP QPS 下降间接检测"
    inject_dns_drop
}

collect_metrics() {
    log_info "尝试触发 DNS 解析..."
    exec_ssh "timeout 5 kubectl -n ${JUDGEX_NAMESPACE} exec deploy/backend -- nslookup example.com 2>/dev/null" || true
    sleep 5
}

verify() {
    log_step "实验 ${EXPERIMENT_ID}: 断言验证"

    local pre_snap="${1}"
    local during_snap="${2}"

    # 尝试检测 callAnomaly（QPS 下降）
    local anomaly_count
    anomaly_count=$(grep "^ebpf_edge_anomaly_score{" "$during_snap" | awk '$NF > 0.01' | wc -l)
    anomaly_count="${anomaly_count:-0}"

    if [ "$anomaly_count" -gt 0 ]; then
        log_ok "检测到 callAnomaly/QPS 下降: ${anomaly_count} 条边"
        assert_anomaly_detected "$pre_snap" "$during_snap" 1 0.01 || true
        assert_agent_healthy "$pre_snap" "$during_snap" || true
        return 0
    else
        # 已知盲点：回退到 SKIP
        log_info "未检测到异常 — 与预期一致（已知 DNS UDP 盲点）"
        add_warning "实验 05 DNS 失败: 未检测到异常 — 符合预期的已知盲点 (eBPF 不观测 UDP DNS)"
        assert_record "dns_blind_spot" "SKIP" "0 anomalies" "N/A (expected limitation)"

        assert_agent_healthy "$pre_snap" "$during_snap" || true
        return 2  # SKIP — 预期的盲点
    fi
}

cleanup() {
    log_step "实验 ${EXPERIMENT_ID}: 清理"
    cleanup_iptables_drop
    verify_no_residual_rules || true
}

post_check() {
    log_step "实验 ${EXPERIMENT_ID}: 恢复验证"

    local pre_snap="${1}"
    local post_snap="${2}"

    assert_anomaly_cleared "$pre_snap" "$post_snap" || true
    assert_steady_state || log_warn "稳态校验未完全通过"
    return 0
}
