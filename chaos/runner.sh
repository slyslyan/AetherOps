#!/bin/bash
# runner.sh — ebpfagent 混沌工程主编排器
#
# 用法:
#   bash chaos/runner.sh                          # 运行全部实验
#   bash chaos/runner.sh --dry-run                # 干运行（仅打印指令）
#   bash chaos/runner.sh --skip-high-risk         # 跳过高风险实验
#   bash chaos/runner.sh --exp 01                 # 仅运行实验 01
#   bash chaos/runner.sh --exp 01,02,04           # 运行指定实验
#   bash chaos/runner.sh --cleanup-only           # 仅执行全局清理
#   bash chaos/runner.sh --enable-low-risk        # 仅低风险实验 (01/04)
#   bash chaos/runner.sh --verify                 # 仅稳态校验，不注入

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# ============================================================
# 加载依赖
# ============================================================
source "${SCRIPT_DIR}/config.sh"
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/ssh-exec.sh"
source "${SCRIPT_DIR}/lib/metrics.sh"
source "${SCRIPT_DIR}/lib/inject.sh"
source "${SCRIPT_DIR}/lib/cleanup.sh"
source "${SCRIPT_DIR}/lib/report.sh"

# ============================================================
# 参数解析
# ============================================================
SELECTED_EXPS=""
CLEANUP_ONLY=false
VERIFY_ONLY=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            CHAOS_DRY_RUN=true
            ;;
        --skip-high-risk)
            CHAOS_SKIP_HIGH_RISK=true
            ;;
        --enable-low-risk)
            CHAOS_ENABLE_HIGH_RISK=false
            ;;
        --exp)
            SELECTED_EXPS="${2}"
            shift
            ;;
        --cleanup-only)
            CLEANUP_ONLY=true
            ;;
        --verify|-v)
            VERIFY_ONLY=true
            ;;
        --yes|-y)
            CHAOS_FORCE_YES=true
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: bash runner.sh [--dry-run] [--skip-high-risk] [--enable-low-risk] [--exp 01[,02,...]] [--cleanup-only] [--verify] [--yes]"
            exit 1
            ;;
    esac
    shift
done

# ============================================================
# 排他锁
# ============================================================
exec 200>"${CHAOS_LOCK_FILE}"
if ! flock -n 200; then
    die "已有混沌实验在运行中（${CHAOS_LOCK_FILE} 被锁定）"
fi

# ============================================================
# 全局超时 (30 分钟)
# ============================================================
GLOBAL_TIMEOUT=$((CHAOS_MAX_RUNTIME_SEC))
START_TIME=$(now_epoch)

timeout_handler() {
    log_fail "全局超时 (${CHAOS_MAX_RUNTIME_SEC}s)，触发紧急清理..."
    cleanup_all
    log_info "清理完成，退出"
    exit 1
}
trap timeout_handler ALRM
# 设置闹钟（bash 内置 alarm）
if [ "$CHAOS_DRY_RUN" != "true" ]; then
    ( sleep "$GLOBAL_TIMEOUT"; kill -ALRM $$ ) &
    TIMEOUT_WATCHER=$!
fi

# ============================================================
# 全局 trap 清理
# ============================================================
trap_cleanup() {
    local exit_code=$?
    log_warn "脚本退出 (code=${exit_code})，执行全局清理..."
    if [ "$CHAOS_DRY_RUN" != "true" ]; then
        cleanup_all
    fi
    # 清理超时 watcher
    [ -n "${TIMEOUT_WATCHER:-}" ] && kill "$TIMEOUT_WATCHER" 2>/dev/null || true
    log_info "全局清理完成"
    exit "$exit_code"
}
trap trap_cleanup EXIT INT TERM

# ============================================================
# 清理模式
# ============================================================
if [ "$CLEANUP_ONLY" = true ]; then
    log_title "紧急清理模式"
    cleanup_all
    verify_no_residual_rules
    log_ok "清理完成"
    exit 0
fi

# ============================================================
# 验证模式
# ============================================================
if [ "$VERIFY_ONLY" = true ]; then
    log_title "稳态校验模式"
    assert_steady_state
    exit $?
fi

# ============================================================
# 预检
# ============================================================

log_title "ebpfagent 混沌工程"
echo "  目标:    ${CHAOS_SSH_USER}@${CHAOS_SSH_HOST}"
echo "  模式:    $([ "$CHAOS_DRY_RUN" = true ] && echo 'DRY RUN (仅打印不执行)' || echo 'LIVE')"
echo "  高风险:  $([ "$CHAOS_SKIP_HIGH_RISK" = true ] && echo '已跳过' || echo '允许')"
echo "  实验:    ${SELECTED_EXPS:-全部}"
echo "  超时:    ${CHAOS_MAX_RUNTIME_SEC}s"
echo "  运行 ID: ${RUN_ID}"
echo ""

log_step "预检"

if [ "$CHAOS_DRY_RUN" != "true" ]; then
    log_info "测试 SSH 连通性..."
    if ! test_ssh; then
        die "SSH 连接失败: ${CHAOS_SSH_USER}@${CHAOS_SSH_HOST}"
    fi
    log_ok "SSH 连接正常"

    log_info "检查 eBPF agent 状态..."
    agent_up=$(fetch_metrics | grep "^ebpf_agent_up" | awk '{print $NF}' | head -1)
    if [ "${agent_up:-0}" != "1" ]; then
        log_warn "eBPF agent 未运行 (ebpf_agent_up=${agent_up:-0})，继续但实验可能无法检测"
    else
        log_ok "eBPF agent 运行正常"
    fi

    log_info "检查无残留故障..."
    verify_no_residual_rules || {
        log_warn "存在残留故障规则，执行全局清理..."
        cleanup_all
    }

    log_info "稳态校验..."
    if ! assert_steady_state; then
        log_warn "稳态校验发现问题，建议先运行: bash chaos/server-cleanup.sh --verify"
        if [ "$CHAOS_FORCE_YES" = "true" ] || [ ! -t 0 ]; then
            log_info "--yes 或非交互终端，自动继续"
        else
            echo -n "是否继续? [y/N] "
            read -r response
            if [ "${response,,}" != "y" ]; then
                die "用户取消"
            fi
        fi
    fi
else
    log_info "DRY RUN — 跳过服务器连接检查"
fi

# ============================================================
# 构建实验列表
# ============================================================

ALL_EXPERIMENTS=("01" "04" "02" "05")
# 重新排序：先低风险，再中/高风险

declare -A EXP_ENABLED
for exp_id in "${ALL_EXPERIMENTS[@]}"; do
    risk="${EXPERIMENT_RISK[$exp_id]:-unknown}"

    # 风险过滤
    if [ "$risk" = "high" ] && [ "$CHAOS_SKIP_HIGH_RISK" = "true" ]; then
        EXP_ENABLED["$exp_id"]=false
        continue
    fi
    if { [ "$risk" = "high" ] || [ "$risk" = "medium" ]; } && [ "$CHAOS_ENABLE_HIGH_RISK" = "false" ]; then
        EXP_ENABLED["$exp_id"]=false
        continue
    fi

    # 实验选择过滤
    if [ -n "$SELECTED_EXPS" ]; then
        if echo "$SELECTED_EXPS" | tr ',' '\n' | grep -qx "$exp_id"; then
            EXP_ENABLED["$exp_id"]=true
        else
            EXP_ENABLED["$exp_id"]=false
        fi
    else
        EXP_ENABLED["$exp_id"]=true
    fi
done

log_info "实验计划:"
for exp_id in "${ALL_EXPERIMENTS[@]}"; do
enabled="${EXP_ENABLED[$exp_id]:-false}"
risk="${EXPERIMENT_RISK[$exp_id]:-?}"
    if [ "$enabled" = "true" ]; then
        echo "  [✓] 实验 ${exp_id} (风险: ${risk})"
    else
        echo "  [✗] 实验 ${exp_id} (风险: ${risk}) — 已跳过"
    fi
done

# ============================================================
# 执行单个实验
# ============================================================

run_experiment() {
    local exp_id="$1"
    local exp_script="${SCRIPT_DIR}/experiments/${exp_id}-*.sh"

    # 找到实际文件
    local actual_script
    actual_script=$(ls ${exp_script} 2>/dev/null | head -1)
    if [ -z "$actual_script" ]; then
        log_warn "实验脚本不存在: ${exp_script}"
        return 2
    fi

    log_title "执行实验 ${exp_id}"

    # 加载实验脚本
    source "$actual_script"

    log_info "实验: ${EXPERIMENT_ID} — ${EXPERIMENT_NAME}"
    log_info "描述: ${EXPERIMENT_DESCRIPTION}"

    local exp_start exp_end
    exp_start=$(now_epoch)

    # ---- Phase 1: Pre-check ----
    local pre_result=0
    if [ "$CHAOS_DRY_RUN" = "true" ]; then
        log_info "[DRY RUN] 跳过 pre_check()"
    else
        pre_check || pre_result=$?
    fi

    if [ "$pre_result" -eq 2 ]; then
        log_warn "实验 ${exp_id} 跳过"
        record_experiment_result "$exp_id" "$EXPERIMENT_NAME" "SKIP" "$exp_start" "$(now_epoch)" "" "" ""
        return 0
    elif [ "$pre_result" -ne 0 ]; then
        log_fail "Pre-check 失败，跳过实验"
        record_experiment_result "$exp_id" "$EXPERIMENT_NAME" "FAIL" "$exp_start" "$(now_epoch)" "" "" ""
        return 1
    fi

    # ---- Phase 2: Snapshot pre ----
    local pre_snap
    if [ "$CHAOS_DRY_RUN" = "true" ]; then
        pre_snap="/dev/null"
    else
        pre_snap=$(snapshot_save "pre" "$exp_id")
        print_metrics_summary "$pre_snap" "pre"
    fi

    # ---- Phase 3: Inject ----
    if [ "$CHAOS_DRY_RUN" = "true" ]; then
        log_info "[DRY RUN] 跳过故障注入"
    else
        inject || {
            log_fail "故障注入失败"
            cleanup
            record_experiment_result "$exp_id" "$EXPERIMENT_NAME" "FAIL" "$exp_start" "$(now_epoch)" "$pre_snap" "" ""
            return 1
        }
    fi

    # ---- Phase 4: Wait for detection ----
    log_info "等待 eBPF 检测 (${DETECT_WAIT_SEC}s = 3x AnalysisInterval)..."
    if [ "$CHAOS_DRY_RUN" = "true" ]; then
        log_info "[DRY RUN] 跳过等待"
        sleep 1
    else
        sleep "$DETECT_WAIT_SEC"
    fi

    # ---- Phase 5: Collect metrics during fault ----
    local during_snap
    if [ "$CHAOS_DRY_RUN" = "true" ]; then
        during_snap="/dev/null"
    else
        collect_metrics
        during_snap=$(snapshot_save "during" "$exp_id")
        print_metrics_summary "$during_snap" "during"
    fi

    # ---- Phase 6: Verify ----
    local verify_result=0
    if [ "$CHAOS_DRY_RUN" = "true" ]; then
        log_info "[DRY RUN] 跳过断言验证"
    else
        verify "$pre_snap" "$during_snap" || verify_result=$?
    fi

    # ---- Phase 7: Cleanup ----
    if [ "$CHAOS_DRY_RUN" = "true" ]; then
        log_info "[DRY RUN] 跳过清理"
    else
        cleanup
    fi

    # ---- Phase 8: Wait for recovery ----
    log_info "等待系统恢复 (${RECOVER_WAIT_SEC}s)..."
    if [ "$CHAOS_DRY_RUN" = "true" ]; then
        sleep 1
    else
        sleep "$RECOVER_WAIT_SEC"
    fi

    # ---- Phase 9: Post-check ----
    local post_snap
    local post_result=0
    if [ "$CHAOS_DRY_RUN" = "true" ]; then
        post_snap="/dev/null"
    else
        post_snap=$(snapshot_save "post" "$exp_id")
        print_metrics_summary "$post_snap" "post"

        # 业务熔断检查
        if ! health_check_fuse; then
            log_fail "业务熔断触发！中断实验"
            record_experiment_result "$exp_id" "$EXPERIMENT_NAME" "FAIL" "$exp_start" "$(now_epoch)" "$pre_snap" "$during_snap" "$post_snap"
            return 1
        fi

        post_check "$pre_snap" "$post_snap" || post_result=$?
    fi

    # ---- 判定最终状态 ----
    local final_status
    exp_end=$(now_epoch)

    case "$verify_result" in
        0) final_status="PASS" ;;
        2) final_status="SKIP" ;;
        *) final_status="FAIL" ;;
    esac

    if [ "$post_result" -ne 0 ]; then
        final_status="WARN"  # 检测通过但恢复异常
    fi

    record_experiment_result "$exp_id" "$EXPERIMENT_NAME" "$final_status" "$exp_start" "$exp_end" "$pre_snap" "$during_snap" "$post_snap"

    log_info "实验 ${exp_id} 完成: ${final_status} (耗时 $(elapsed "$exp_start")s)"

    # 重置断言计数器
    ASSERTION_COUNT=0
    unset ASSERTION_RESULTS
    declare -gA ASSERTION_RESULTS

    return 0
}

# ============================================================
# 主编排
# ============================================================

set_report_start

for exp_id in "${ALL_EXPERIMENTS[@]}"; do
    if [ "${EXP_ENABLED[$exp_id]:-false}" != "true" ]; then
        continue
    fi

    run_experiment "$exp_id" || {
        run_result=$?
        if [ "$run_result" -eq 1 ]; then
            log_warn "实验 ${exp_id} 异常终止，检查是否需要中止..."
            # 业务熔断
            if ! health_check_fuse; then
                log_fail "业务熔断触发，中止全部实验"
                break
            fi
        fi
    }

    # 检查全局超时
    elapsed_so_far=$(elapsed "$START_TIME")
    if [ "$elapsed_so_far" -gt "$((GLOBAL_TIMEOUT - 300))" ]; then
        log_warn "接近全局超时 (${elapsed_so_far}s / ${GLOBAL_TIMEOUT}s)，跳过剩余实验"
        break
    fi

    echo ""  # 实验间隔空行
done

# ============================================================
# 生成报告
# ============================================================

log_step "生成报告"

generate_json_report
generate_markdown_report

echo ""
log_title "混沌实验完成"
echo "  报告目录: ${REPORT_DIR_FULL}"
echo "  JSON:     ${REPORT_DIR_FULL}/chaos-report.json"
echo "  Markdown: ${REPORT_DIR_FULL}/chaos-report.md"
echo "  快照:     ${REPORT_DIR_FULL}/snapshots/"
echo ""
echo "  通过: ${REPORT_PASS}  失败: ${REPORT_FAIL}  跳过: ${REPORT_SKIP}  警告: ${REPORT_WARN}"

# 清理超时 watcher
[ -n "${TIMEOUT_WATCHER:-}" ] && kill "$TIMEOUT_WATCHER" 2>/dev/null || true

exit 0
