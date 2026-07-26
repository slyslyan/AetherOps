#!/bin/bash
# 实验 03: HTTP 500 错误注入 (Python mock + iptables DNAT)
# 风险等级: HIGH — DNAT 流量劫持，异常残留会永久篡改业务流量
# eBPF 信号: uprobe_http 捕获 HTTP 500 状态码
set -euo pipefail

EXP_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAOS_DIR="$(dirname "$EXP_SCRIPT_DIR")"

source "${CHAOS_DIR}/config.sh"
source "${CHAOS_DIR}/lib/common.sh"
source "${CHAOS_DIR}/lib/ssh-exec.sh"
source "${CHAOS_DIR}/lib/metrics.sh"
source "${CHAOS_DIR}/lib/inject.sh"
source "${CHAOS_DIR}/lib/cleanup.sh"

EXPERIMENT_ID="03"
EXPERIMENT_NAME="HTTP 500 Error Injection"
EXPERIMENT_DESCRIPTION="iptables DNAT 劫持后端流量到 HTTP 500 mock，验证 uprobe HTTP 状态码检测"

pre_check() {
    log_step "实验 ${EXPERIMENT_ID}: ${EXPERIMENT_NAME} — Pre-Check"

    if [ "$CHAOS_SKIP_HIGH_RISK" = "true" ]; then
        log_warn "高风险实验已跳过 (CHAOS_SKIP_HIGH_RISK=true)"
        return 2  # SKIP
    fi

    assert_steady_state || { log_fail "Pre-check 稳态校验失败"; return 1; }
    log_ok "Pre-check 通过"
    return 0
}

inject() {
    log_step "实验 ${EXPERIMENT_ID}: 注入故障"

    # 获取 backend pod IP
    local backend_ip
    backend_ip=$(exec_sudo "kubectl -n ${JUDGEX_NAMESPACE} get pod -l app=backend -o jsonpath='{.items[0].status.podIP}' 2>/dev/null")
    if [ -z "$backend_ip" ]; then
        log_fail "无法获取 backend pod IP"
        return 1
    fi
    log_info "目标 Backend Pod IP: ${backend_ip}"

    inject_http_errors "$backend_ip" "${BACKEND_PORT}"

    # 二次确认 DNAT 规则已生效
    log_info "DNAT 规则验证:"
    exec_sudo "iptables -t nat -L OUTPUT -n" 2>/dev/null | grep -E "15999|DNAT" || log_warn "DNAT 规则未找到"
}

collect_metrics() {
    log_info "生成 HTTP 流量..."
    # 通过 K3s service 访问后端，触发 DNAT
    for i in $(seq 1 5); do
        exec_ssh "timeout 3 curl -s -o /dev/null -w '%{http_code}' http://localhost:${BACKEND_PORT}/api/test 2>/dev/null" || true
        sleep 1
    done
}

verify() {
    log_step "实验 ${EXPERIMENT_ID}: 断言验证"

    local pre_snap="${1}"
    local during_snap="${2}"
    local all_pass=true

    # [CRITICAL] HTTP 500 被 eBPF uprobe 捕获
    assert_http_status_seen "$during_snap" "500" || all_pass=false

    # [CRITICAL] anomaly_score 检测
    assert_anomaly_detected "$pre_snap" "$during_snap" 1 0.5 || all_pass=false

    # [INFO] 错误数增加
    assert_errors_increased "$pre_snap" "$during_snap" "" 0 || true

    # [INFO] Agent 健康
    assert_agent_healthy "$pre_snap" "$during_snap" || true

    if [ "$all_pass" = true ]; then
        return 0
    else
        return 1
    fi
}

cleanup() {
    log_step "实验 ${EXPERIMENT_ID}: 清理"

    # 优先清理 nat 表（风险最高）
    cleanup_iptables_dnat
    cleanup_mock_http

    # 确保所有 nat 规则已清除
    exec_sudo "iptables -t nat -F OUTPUT 2>/dev/null" || true
    log_info "nat 表 OUTPUT 链已 flush"

    verify_no_residual_rules || {
        log_warn "存在残留规则，强制再次清理..."
        exec_sudo "iptables -t nat -F OUTPUT 2>/dev/null" || true
        cleanup_mock_http
    }
}

post_check() {
    log_step "实验 ${EXPERIMENT_ID}: 恢复验证"

    local pre_snap="${1}"
    local post_snap="${2}"

    assert_anomaly_cleared "$pre_snap" "$post_snap" || {
        log_warn "anomaly_score 未完全清零"
        return 1
    }

    # 确认 DNAT 规则已清除
    local nat_rules
    nat_rules=$(exec_sudo "iptables -t nat -S OUTPUT 2>/dev/null | grep -c DNAT" || echo "0")
    if [ "${nat_rules:-0}" -gt 0 ]; then
        log_fail "DNAT 规则未完全清除 (${nat_rules} 条残留)"
        return 1
    fi

    assert_steady_state || log_warn "稳态校验未完全通过"
    return 0
}
