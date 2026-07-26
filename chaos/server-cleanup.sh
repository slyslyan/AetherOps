#!/bin/bash
# server-cleanup.sh — ebpfagent 服务器清理脚本
# 功能:
#   1. 停止旧 ebpf-oj-monitor，仅保留 tracer
#   2. 校验 kprobe_events 无重复挂载
#   3. 确认单进程监听 :2112
#   4. 导出当前探针清单 + 指标快照作为基线
#   5. 前置稳态检查
#   6. 防误删保护（无 killall，先 SIGTERM 再 SIGKILL）
#
# 用法:
#   bash chaos/server-cleanup.sh           # 清理 + 基线
#   bash chaos/server-cleanup.sh --verify  # 仅验证，不清理

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# 加载依赖
source "${SCRIPT_DIR}/config.sh"
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/ssh-exec.sh"
source "${SCRIPT_DIR}/lib/metrics.sh"
source "${SCRIPT_DIR}/lib/cleanup.sh"

VERIFY_ONLY=false
OUTPUT_DIR="${PROJECT_DIR}/chaos/fixtures"

# 解析参数
case "${1:-}" in
    --verify|-v) VERIFY_ONLY=true ;;
esac

# ============================================================
# 工具函数
# ============================================================

print_section() { echo ""; echo -e "${BOLD}--- $* ---${NC}"; }

check_failures=0

check() {
    local desc="$1"
    local cmd="$2"
    print_section "$desc"
    if eval "$cmd"; then
        log_ok "$desc"
    else
        log_fail "$desc"
        check_failures=$((check_failures + 1))
    fi
}

# ============================================================
# 预检：SSH 连通性
# ============================================================

log_title "eBPF Agent 服务器清理脚本"
echo "  目标: ${CHAOS_SSH_USER}@${CHAOS_SSH_HOST}"
echo "  模式: $([ "$VERIFY_ONLY" = true ] && echo '仅验证' || echo '清理+基线')"
echo ""

print_section "SSH 连通性测试"
if test_ssh; then
    log_ok "SSH 连接正常"
else
    die "SSH 连接失败: ${CHAOS_SSH_USER}@${CHAOS_SSH_HOST}"
fi

# ============================================================
# Step 1: 列出所有 eBPF 相关进程
# ============================================================

print_section "当前 eBPF 相关进程"
exec_ssh "ps aux | grep -E 'ebpf|tracer|bpf' | grep -v grep" || log_info "无 eBPF 进程"

log_info "检查旧 agent (${OLD_AGENT_BINARY})..."
OLD_PID=$(exec_ssh "pgrep -f '${OLD_AGENT_BINARY}' 2>/dev/null" || echo "")
if [ -n "$OLD_PID" ]; then
    log_warn "发现旧 agent: PID=${OLD_PID}"
    exec_ssh "ps -p ${OLD_PID} -o pid,ppid,user,cmd --no-headers 2>/dev/null"
else
    log_ok "未发现旧 agent 进程"
fi

log_info "检查 tracer..."
TRACER_PID=$(exec_ssh "pgrep -f '/usr/local/bin/tracer' 2>/dev/null" || echo "")
if [ -n "$TRACER_PID" ]; then
    log_ok "tracer 运行中: PID=${TRACER_PID}"
    exec_ssh "ps -p ${TRACER_PID} -o pid,ppid,user,cmd --no-headers 2>/dev/null"
else
    log_warn "tracer 未运行"
fi

# ============================================================
# Step 2: 停止旧 agent
# ============================================================

if [ "$VERIFY_ONLY" != "true" ] && [ -n "$OLD_PID" ]; then
    print_section "停止旧 agent"

    log_info "查找旧 agent 的 systemd 服务..."
    local old_service
    old_service=$(exec_ssh "systemctl list-units --type=service --all 2>/dev/null | grep -E 'ebpf-oj|ebpfagent' | awk '{print \$1}'" || echo "")
    if [ -n "$old_service" ]; then
        log_info "发现 systemd 服务: ${old_service}，执行 systemctl stop..."
        exec_sudo "systemctl stop ${old_service} 2>/dev/null" || true
    fi

    log_info "发送 SIGTERM 到 PID ${OLD_PID}..."
    exec_sudo "kill -TERM ${OLD_PID} 2>/dev/null" || true
    sleep 3

    if exec_ssh "kill -0 ${OLD_PID} 2>/dev/null"; then
        log_warn "SIGTERM 未生效，发送 SIGKILL..."
        exec_sudo "kill -KILL ${OLD_PID} 2>/dev/null" || true
        sleep 2
    fi

    if exec_ssh "kill -0 ${OLD_PID} 2>/dev/null" 2>/dev/null; then
        log_fail "无法停止旧 agent (PID ${OLD_PID})，请手动检查"
    else
        log_ok "旧 agent 已停止"
    fi
fi

# ============================================================
# Step 3: 校验 kprobe_events 无重复
# ============================================================

check "kprobe_events 无重复挂载" '
    local probe_count total unique
    total=$(exec_sudo "cat /sys/kernel/debug/tracing/kprobe_events 2>/dev/null | wc -l")
    unique=$(exec_sudo "cat /sys/kernel/debug/tracing/kprobe_events 2>/dev/null | sort -u | wc -l")
    echo "  kprobe_events: total=${total:-0}, unique=${unique:-0}"
    [ "${total:-0}" -eq "${unique:-0}" ]
'

# 导出探针清单
print_section "导出探针清单"
mkdir -p "$OUTPUT_DIR"
BASELINE_FILE="${OUTPUT_DIR}/baseline-probes-$(date +%s).txt"
{
    echo "# kprobe_events snapshot — $(date -Iseconds)"
    exec_sudo "cat /sys/kernel/debug/tracing/kprobe_events 2>/dev/null"
    echo ""
    echo "# bpftool prog list"
    exec_sudo "bpftool prog list 2>/dev/null"
} > "$BASELINE_FILE"
log_ok "探针清单已导出: ${BASELINE_FILE}"

# ============================================================
# Step 4: 端口校验
# ============================================================

check "Metrics 端口 :2112 单进程监听" '
    local listener_count
    listener_count=$(exec_sudo "ss -tlnp | grep ':${TRACER_METRICS_PORT}' | wc -l")
    echo "  :2112 监听进程数: ${listener_count}"
    exec_sudo "ss -tlnp | grep ':${TRACER_METRICS_PORT}'"
    [ "${listener_count}" -eq 1 ]
'

check "MCP 端口 :50052 正常" '
    local mcp_health
    mcp_health=$(exec_ssh "curl -s localhost:${TRACER_MCP_PORT}/healthz 2>/dev/null")
    echo "  MCP healthz: ${mcp_health}"
    echo "${mcp_health}" | grep -q "ok"
'

check "Metrics 端点可访问" '
    local metrics_status
    metrics_status=$(exec_ssh "curl -s -o /dev/null -w \"%{http_code}\" localhost:${TRACER_METRICS_PORT}/metrics 2>/dev/null")
    echo "  :2112/metrics HTTP status: ${metrics_status}"
    [ "${metrics_status}" = "200" ]
'

# 导出指标基线
print_section "导出指标基线"
METRICS_BASELINE="${OUTPUT_DIR}/baseline-metrics-$(date +%s).txt"
fetch_metrics > "$METRICS_BASELINE"
log_ok "指标基线已导出: ${METRICS_BASELINE}"

# ============================================================
# Step 5: 稳态校验
# ============================================================

print_section "稳态校验"

check "Agent 运行中" '
    local up_val
    up_val=$(grep "^ebpf_agent_up" "${METRICS_BASELINE}" | awk "{print \$NF}" | head -1)
    echo "  ebpf_agent_up: ${up_val:-0}"
    [ "${up_val:-0}" = "1" ]
'

check "无现存异常 (max anomaly_score = 0)" '
    local max_score
    max_score=$(grep "^ebpf_edge_anomaly_score{" "${METRICS_BASELINE}" | awk "{print \$NF}" | sort -rn | head -1)
    echo "  max anomaly_score: ${max_score:-0}"
    awk "BEGIN {exit !(${max_score:-0} <= ${ANOMALY_CLEARED_MAX})}"
'

check "系统负载正常 (< 1.0)" '
    local load1
    load1=$(exec_ssh "cat /proc/loadavg | awk \"{print \\\$1}\"")
    echo "  loadavg 1min: ${load1}"
    awk "BEGIN {exit !(${load1} < 1.0)}"
'

check "无 iptables 残留规则" '
    local ipt_out
    ipt_out=$(exec_sudo "iptables -S OUTPUT 2>/dev/null | grep -cE \"REJECT|DROP\" || echo 0")
    echo "  iptables REJECT/DROP: ${ipt_out}"
    [ "${ipt_out:-0}" -eq 0 ]
'

check "无 tc netem 残留规则" '
    local tc_netem
    tc_netem=$(exec_sudo "tc qdisc show 2>/dev/null | grep -c netem || echo 0")
    echo "  tc netem qdiscs: ${tc_netem}"
    [ "${tc_netem:-0}" -eq 0 ]
'

check "无 stress-ng 残留进程" '
    local stress_count
    stress_count=$(exec_sudo "pgrep -c stress-ng 2>/dev/null || echo 0")
    echo "  stress-ng 进程: ${stress_count}"
    [ "${stress_count:-0}" -eq 0 ]
'

check "K3s pods 全部 Running" '
    exec_sudo "kubectl -n ${JUDGEX_NAMESPACE} get pods --no-headers 2>/dev/null"
    local non_ok
    non_ok=$(exec_sudo "kubectl -n ${JUDGEX_NAMESPACE} get pods --no-headers 2>/dev/null" | grep -vc "Running" || echo "0")
    [ "${non_ok:-0}" -eq 0 ]
'

check "JudgeX 健康检查 (/health)" '
    local health
    health=$(exec_sudo "${HEALTH_CHECK_CMD}" 2>/dev/null | tail -1 | tr -d '\n')
    echo "  /health HTTP status: ${health}"
    [ "${health}" = "200" ]
'

check "JudgeX 就绪检查 (/ready)" '
    local ready_out
    ready_out=$(exec_sudo "${READY_CHECK_CMD}" 2>/dev/null | tail -1 | tr -d '\n')
    echo "  ${ready_out}"
    echo "${ready_out}" | grep -q "ok"
'

# ============================================================
# Step 6: 打印指标摘要
# ============================================================

print_section "当前 eBPF 指标摘要"
print_metrics_summary "$METRICS_BASELINE" "baseline"

# ============================================================
# 结果
# ============================================================

echo ""
log_title "清理结果"
if [ "$check_failures" -eq 0 ]; then
    log_ok "所有检查通过 (0 failures)"
    echo ""
    echo "基线文件:"
    echo "  探针: ${BASELINE_FILE}"
    echo "  指标: ${METRICS_BASELINE}"
else
    log_fail "存在 ${check_failures} 项检查失败，请检查上方详情"
fi

if [ "$VERIFY_ONLY" = true ]; then
    log_info "仅验证模式 — 未修改服务器状态"
fi

exit "$check_failures"
