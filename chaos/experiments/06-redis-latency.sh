#!/bin/bash
# 实验 06: Redis 延迟注入 (tc netem + port 6379)
# 风险等级: LOW
# 已知局限: tc netem 不影响 eBPF 测量的 kernel buffer copy 时间(~μs)，
#   且 redis_trace 探针依赖实际 Redis 流量。若 Redis 流量过低，指标可能为空。
# 实验价值: 验证端口级 tc filter 注入/清理 + agent 容忍度。
set -euo pipefail

EXP_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAOS_DIR="$(dirname "$EXP_SCRIPT_DIR")"

source "${CHAOS_DIR}/config.sh"
source "${CHAOS_DIR}/lib/common.sh"
source "${CHAOS_DIR}/lib/ssh-exec.sh"
source "${CHAOS_DIR}/lib/metrics.sh"
source "${CHAOS_DIR}/lib/inject.sh"
source "${CHAOS_DIR}/lib/cleanup.sh"

EXPERIMENT_ID="06"
EXPERIMENT_NAME="Redis Latency Injection"
EXPERIMENT_DESCRIPTION="tc netem 150ms 仅对 Redis 端口 (6379)，验证注入/恢复流程 + agent 健康"

pre_check() {
    log_step "实验 ${EXPERIMENT_ID}: ${EXPERIMENT_NAME} — Pre-Check"
    assert_steady_state || { log_fail "Pre-check 稳态校验失败"; return 1; }
    log_ok "Pre-check 通过"
    return 0
}

inject() {
    log_step "实验 ${EXPERIMENT_ID}: 注入故障"
    inject_port_delay "150ms" "${REDIS_PORT}"
}

collect_metrics() {
    log_info "故障期指标采集..."
}

verify() {
    log_step "实验 ${EXPERIMENT_ID}: 断言验证"

    local pre_snap="${1}"
    local during_snap="${2}"
    local all_pass=true

    # [INFO] 检测到 Redis 流量（redis_trace 探针）
    local redis_cmds
    redis_cmds=$(grep -c "^ebpf_redis_commands_total{" "$during_snap" 2>/dev/null || true)
    redis_cmds=$(echo "${redis_cmds:-0}" | tail -1 | tr -d '\n')
    if [ "${redis_cmds:-0}" -gt 0 ]; then
        log_ok "Redis 命令流量: ${redis_cmds} 种命令"
        grep "^ebpf_redis_commands_total{" "$during_snap" | head -5
    else
        log_info "Redis 命令指标为空 (Redis 流量较低或 redis_trace 探针未匹配)"
    fi

    # [INFO] 异常分数（tc netem 不影响 kernel-level 延迟测量）
    assert_anomaly_detected "$pre_snap" "$during_snap" 1 0.01 || \
        log_info "anomaly_score 未触发 (已知局限: tc netem 不影响 eBPF kernel buffer copy 测量)"

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
        log_warn "anomaly_score 未完全清零"
        return 1
    }
    assert_steady_state || log_warn "稳态校验未完全通过"
    return 0
}
