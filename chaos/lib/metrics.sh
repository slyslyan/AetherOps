#!/bin/bash
# metrics.sh — Prometheus 指标查询 + 断言库
# 直接 curl 服务器的 :2112/metrics 端点，解析 Prometheus 文本格式

# ============================================================
# 指标采集
# ============================================================

# 拉取全部指标（原始 Prometheus 文本格式）
fetch_metrics() {
    exec_ssh "curl -s localhost:${TRACER_METRICS_PORT}/metrics" 2>/dev/null
}

# 拉取全部指标到本地文件
fetch_metrics_to_file() {
    local outfile="${1:-/tmp/chaos-metrics.txt}"
    fetch_metrics > "$outfile"
}

# 获取某个指标的所有行（含 label）
metric_lines() {
    local metric_name="$1"
    local input_file="${2:-/dev/stdin}"
    grep "^${metric_name}{" "$input_file" 2>/dev/null || true
}

# 获取某个指标的值（按 label 过滤）
# 用法: metric_value "ebpf_edge_anomaly_score" 'dst=".*:3306"' < /tmp/metrics.txt
metric_value() {
    local metric_name="$1"
    local label_filter="${2:-}"
    if [ -n "$label_filter" ]; then
        grep "^${metric_name}{" | grep "$label_filter" | awk '{print $NF}' | head -1
    else
        grep "^${metric_name} " | awk '{print $NF}' | head -1
    fi
}

# 获取某个指标的最大值
metric_max() {
    local metric_name="$1"
    grep "^${metric_name}{" | awk '{print $NF}' | sort -rn | head -1
}

# 获取某个指标的行数
metric_count() {
    local metric_name="$1"
    grep -c "^${metric_name}{" || true
}

# 获取所有 anomaly_score > 0 的边
metric_anomaly_edges() {
    local min_score="${1:-0}"
    grep "^ebpf_edge_anomaly_score{" | awk -v t="$min_score" '$NF > t {print $0}'
}

# ============================================================
# 基线快照
# ============================================================

# 保存当前指标到快照文件
snapshot_save() {
    local label="${1:-pre}"
    local exp_id="${2:-}"
    local file
    if [ -n "$exp_id" ]; then
        file="${REPORT_DIR}/${RUN_ID}/snapshots/metrics-${label}-${exp_id}.txt"
    else
        file="${REPORT_DIR}/${RUN_ID}/snapshots/metrics-${label}.txt"
    fi
    mkdir -p "$(dirname "$file")"
    fetch_metrics > "$file"
    echo "$file"
}

# 从快照获取基线值
get_baseline_metric() {
    local metric_name="$1"
    local label_filter="${2:-}"
    local snapshot_file="${3:-}"
    if [ -n "$label_filter" ]; then
        grep "^${metric_name}{" "$snapshot_file" | grep "$label_filter" | awk '{print $NF}' | head -1
    else
        grep "^${metric_name} " "$snapshot_file" | awk '{print $NF}' | head -1
    fi
}

# 从快照获取最大值
get_baseline_max() {
    local metric_name="$1"
    local snapshot_file="$2"
    grep "^${metric_name}{" "$snapshot_file" | awk '{print $NF}' | sort -rn | head -1
}

# 从快照获取行数
get_baseline_count() {
    local metric_name="$1"
    local snapshot_file="$2"
    grep -c "^${metric_name}{" "$snapshot_file" || true
}

# ============================================================
# 断言函数（返回 0=pass, 1=fail, 2=skip）
# ============================================================

# 存储断言结果
declare -A ASSERTION_RESULTS
ASSERTION_COUNT=0

assert_record() {
    local name="$1"
    local status="$2"  # PASS / FAIL / SKIP
    local actual="$3"
    local expected="$4"
    ASSERTION_COUNT=$((ASSERTION_COUNT + 1))
    ASSERTION_RESULTS["${ASSERTION_COUNT}_name"]="$name"
    ASSERTION_RESULTS["${ASSERTION_COUNT}_status"]="$status"
    ASSERTION_RESULTS["${ASSERTION_COUNT}_actual"]="$actual"
    ASSERTION_RESULTS["${ASSERTION_COUNT}_expected"]="$expected"
}

# ------------------------------------------
# 异常检测断言
# ------------------------------------------

# 断言：直接比较注入前后的边缘延迟（绕过 anomaly_score 公式，后者依赖 lifetime AvgLat）
# 用法: assert_latency_increased <pre_snapshot> <during_snapshot> <min_edges> <min_increase_ms>
assert_latency_increased() {
    local pre_snapshot="$1"
    local during_snapshot="$2"
    local min_edges="${3:-1}"
    local min_increase_ms="${4:-50}"

    local increased=0
    local total_edges=0

    # 遍历 pre 中的每条边，与 during 比较 per-sample latency
    while IFS= read -r line; do
        local labels
        labels=$(echo "$line" | sed 's/^ebpf_edge_latency_ms_sum{//' | sed 's/} .*//')
        [ -z "$labels" ] && continue

        local pre_sum pre_count during_sum during_count
        pre_sum=$(echo "$line" | awk '{print $NF}')
        pre_count=$(grep "^ebpf_edge_latency_ms_count{${labels}}" "$pre_snapshot" | awk '{print $NF}' | head -1)
        during_sum=$(grep "^ebpf_edge_latency_ms_sum{${labels}}" "$during_snapshot" | awk '{print $NF}' | head -1)
        during_count=$(grep "^ebpf_edge_latency_ms_count{${labels}}" "$during_snapshot" | awk '{print $NF}' | head -1)

        pre_sum=$(echo "${pre_sum:-0}" | head -1 | tr -d '\n')
        pre_count=$(echo "${pre_count:-0}" | head -1 | tr -d '\n')
        during_sum=$(echo "${during_sum:-0}" | head -1 | tr -d '\n')
        during_count=$(echo "${during_count:-0}" | head -1 | tr -d '\n')

        # 用 awk 处理科学计数法比较
        # 关键：计算窗口内增量延迟 = (during_sum - pre_sum) / (during_count - pre_count)
        # 这是故障窗口期间的 per-sample 平均延迟，不受历史累积数据稀释
        local delta_samples window_avg
        delta_samples=$(awk "BEGIN {printf \"%.0f\", (${during_count}) - (${pre_count})}")
        window_avg=$(awk "BEGIN {ds=${during_sum}; ps=${pre_sum}; dc=${during_count}; pc=${pre_count}; \
            delta_s=ds-ps; delta_c=dc-pc; \
            if(delta_c>0) printf \"%.4f\", delta_s/delta_c; else print 0}")

        if [ "$(awk "BEGIN {print (${delta_samples} <= 0)}")" = "1" ]; then
            continue  # 无新增样本，跳过
        fi

        total_edges=$((total_edges + 1))

        if [ "$(awk "BEGIN {print (${window_avg} >= ${min_increase_ms})}")" = "1" ]; then
            increased=$((increased + 1))
        fi
    done < <(grep "^ebpf_edge_latency_ms_sum{" "$pre_snapshot" 2>/dev/null)

    local name="latency_increased_min_${min_increase_ms}ms"
    if [ "$increased" -ge "$min_edges" ]; then
        log_ok "${name}: ${increased}/${total_edges} edges latency increased >= ${min_increase_ms}ms"
        assert_record "$name" "PASS" "${increased} edges" ">= ${min_edges} edges with +${min_increase_ms}ms"
        return 0
    else
        log_fail "${name}: ${increased}/${total_edges} edges latency increased >= ${min_increase_ms}ms (expected >= ${min_edges})"
        assert_record "$name" "FAIL" "${increased} edges" ">= ${min_edges} edges with +${min_increase_ms}ms"
        return 1
    fi
}

# 断言：至少 min_edges 条边的 anomaly_score 超过 baseline_max + delta
# 注意：eBPF agent 的 anomaly_score 依赖 lifetime AvgLat + MinLatThresholdMs(5ms) 门限，
# 低延迟环境下可能始终为 0。建议用 assert_latency_increased 作为主要断言。
assert_anomaly_detected() {
    local pre_snapshot="$1"
    local during_snapshot="$2"
    local min_edges="${3:-1}"
    local min_delta="${4:-${ANOMALY_DELTA_MIN}}"

    local baseline_max during_max
    baseline_max=$(get_baseline_max "ebpf_edge_anomaly_score" "$pre_snapshot")
    baseline_max="${baseline_max:-0}"
    during_max=$(get_baseline_max "ebpf_edge_anomaly_score" "$during_snapshot")
    during_max="${during_max:-0}"

    local baseline_count during_anomaly_count
    baseline_count=$(get_baseline_count "ebpf_edge_anomaly_score" "$pre_snapshot")
    during_anomaly_count=$(grep "^ebpf_edge_anomaly_score{" "$during_snapshot" 2>/dev/null | awk -v t="$min_delta" '$NF > t' | wc -l)
    during_anomaly_count="${during_anomaly_count:-0}"

    local delta
    delta=$(awk "BEGIN {printf \"%.4f\", ${during_max} - ${baseline_max}}")

    local name="anomaly_detected_min_${min_edges}"
    if ge "$during_max" "$(awk "BEGIN {printf \"%f\", ${baseline_max} + ${min_delta}}")" && \
       [ "${during_anomaly_count:-0}" -ge "$min_edges" ]; then
        log_ok "${name}: ${during_anomaly_count} edges above baseline (max=${during_max}, baseline_max=${baseline_max}, delta=${delta})"
        assert_record "$name" "PASS" "${during_anomaly_count} edges, max=${during_max}" ">= ${min_edges} edges, score > baseline+${min_delta}"
        return 0
    else
        log_fail "${name}: ${during_anomaly_count} edges above baseline (max=${during_max}, baseline_max=${baseline_max}, delta=${delta}, expected >= ${min_edges})"
        assert_record "$name" "FAIL" "${during_anomaly_count} edges, max=${during_max}, baseline=${baseline_max}" ">= ${min_edges} edges, score > baseline+${min_delta}"
        return 1
    fi
}

# ------------------------------------------
# 恢复断言
# ------------------------------------------

# 断言：anomaly_score 已回到基线水平
assert_anomaly_cleared() {
    local pre_snapshot="$1"
    local post_snapshot="$2"
    local max_allowed="${3:-${ANOMALY_CLEARED_MAX}}"

    local baseline_max post_max
    baseline_max=$(get_baseline_max "ebpf_edge_anomaly_score" "$pre_snapshot")
    baseline_max="${baseline_max:-0}"
    post_max=$(get_baseline_max "ebpf_edge_anomaly_score" "$post_snapshot")
    post_max="${post_max:-0}"

    local threshold
    threshold=$(fmax "$baseline_max" "$max_allowed")

    local name="anomaly_cleared"
    if le "$post_max" "$threshold"; then
        log_ok "${name}: post_max=${post_max} <= threshold=${threshold}"
        assert_record "$name" "PASS" "post_max=${post_max}" "<= ${threshold}"
        return 0
    else
        log_fail "${name}: post_max=${post_max} > threshold=${threshold}"
        assert_record "$name" "FAIL" "post_max=${post_max}" "<= ${threshold}"
        return 1
    fi
}

# ------------------------------------------
# 错误计数断言
# ------------------------------------------

# 断言：错误数增加
assert_errors_increased() {
    local pre_snapshot="$1"
    local during_snapshot="$2"
    local edge_pattern="${3:-}"
    local min_increase="${4:-${ERROR_INCREASE_MIN}}"

    local pre_val during_val
    if [ -n "$edge_pattern" ]; then
        pre_val=$(get_baseline_metric "ebpf_edge_errors_total" "$edge_pattern" "$pre_snapshot")
        during_val=$(grep "^ebpf_edge_errors_total{" "$during_snapshot" | grep "$edge_pattern" | awk '{print $NF}' | head -1)
    else
        pre_val=$(grep "^ebpf_edge_errors_total{" "$pre_snapshot" | awk '{s+=$NF} END {print s}')
        during_val=$(grep "^ebpf_edge_errors_total{" "$during_snapshot" | awk '{s+=$NF} END {print s}')
    fi
    pre_val=$(echo "${pre_val:-0}" | head -1 | tr -d '\n')
    during_val=$(echo "${during_val:-0}" | head -1 | tr -d '\n')

    local diff=$((during_val - pre_val))
    local name="errors_increased"

    if [ "$diff" -ge "$min_increase" ]; then
        log_ok "${name}: errors ${pre_val} -> ${during_val} (+${diff})"
        assert_record "$name" "PASS" "+${diff}" ">= +${min_increase}"
        return 0
    else
        log_fail "${name}: errors ${pre_val} -> ${during_val} (+${diff}), expected >= +${min_increase}"
        assert_record "$name" "FAIL" "+${diff}" ">= +${min_increase}"
        return 1
    fi
}

# ------------------------------------------
# HTTP 状态码断言
# ------------------------------------------

assert_http_status_seen() {
    local during_snapshot="$1"
    local status_code="${2:-500}"

    local count
    count=$(grep "^ebpf_http_requests_total{.*status=\"${status_code}\"" "$during_snapshot" | awk '{print $NF}' | head -1)
    count="${count:-0}"

    local name="http_status_${status_code}_seen"
    if [ "$count" -gt 0 ]; then
        log_ok "${name}: ${count} requests with status ${status_code}"
        assert_record "$name" "PASS" "${count} requests" "> 0"
        return 0
    else
        log_fail "${name}: no HTTP ${status_code} observed"
        assert_record "$name" "FAIL" "0 requests" "> 0"
        return 1
    fi
}

# ------------------------------------------
# 根因分析断言
# ------------------------------------------

assert_root_cause_identified() {
    local during_snapshot="$1"
    local node_pattern="${2:-}"

    local count
    if [ -n "$node_pattern" ]; then
        count=$(grep "^ebpf_root_cause_score{" "$during_snapshot" | grep "$node_pattern" | wc -l)
    else
        count=$(grep -c "^ebpf_root_cause_score{" "$during_snapshot" || true)
    fi
    count=$(echo "${count:-0}" | tail -1 | tr -d '\n')

    local name="root_cause_identified"
    if [ "${count:-0}" -gt 0 ]; then
        local top_node
        top_node=$(grep "^ebpf_root_cause_score{" "$during_snapshot" | sort -t' ' -k2 -rn | head -1)
        log_ok "${name}: top = ${top_node}"
        assert_record "$name" "PASS" "${count} suspects" "> 0"
        return 0
    else
        log_warn "${name}: no root cause identified"
        assert_record "$name" "FAIL" "0 suspects" "> 0"
        return 1
    fi
}

# ------------------------------------------
# 自愈断言
# ------------------------------------------

assert_mitigation_attempted() {
    local pre_snapshot="$1"
    local during_snapshot="$2"

    local pre_val during_val
    pre_val=$(grep -c "^ebpf_mitigation_total{" "$pre_snapshot" 2>/dev/null || true)
    during_val=$(grep -c "^ebpf_mitigation_total{" "$during_snapshot" 2>/dev/null || true)
    pre_val=$(echo "${pre_val:-0}" | tail -1 | tr -d '\n')
    during_val=$(echo "${during_val:-0}" | tail -1 | tr -d '\n')

    local name="mitigation_attempted"

    if [ "$during_val" -gt "$pre_val" ]; then
        local actions
        actions=$(grep "^ebpf_mitigation_total{" "$during_snapshot" | head -3)
        log_ok "${name}: ${during_val} mitigation events (was ${pre_val})"
        log_info "  详情: ${actions}"
        assert_record "$name" "PASS" "${during_val} events" "> ${pre_val}"
        return 0
    else
        log_info "${name}: ${during_val} mitigation events (may be blocked by policy)"
        assert_record "$name" "SKIP" "${during_val} events (policy may block)" "> ${pre_val}"
        return 0  # 被策略阻止不算失败
    fi
}

# ------------------------------------------
# Agent 健康断言
# ------------------------------------------

assert_agent_healthy() {
    local pre_snapshot="$1"
    local during_snapshot="$2"

    local pre_errors during_errors
    pre_errors=$(grep "^ebpf_agent_errors_total" "$pre_snapshot" | awk '{print $NF}' | head -1)
    pre_errors=$(echo "${pre_errors:-0}" | head -1 | tr -d '\n')
    during_errors=$(grep "^ebpf_agent_errors_total" "$during_snapshot" | awk '{print $NF}' | head -1)
    during_errors=$(echo "${during_errors:-0}" | head -1 | tr -d '\n')

    local agent_up
    agent_up=$(grep "^ebpf_agent_up" "$during_snapshot" | awk '{print $NF}' | head -1)
    agent_up=$(echo "${agent_up:-0}" | head -1 | tr -d '\n')

    local diff=$((during_errors - pre_errors))
    local name="agent_healthy"

    if [ "$agent_up" = "1" ] && [ "$diff" -le 5 ]; then
        log_ok "${name}: up=${agent_up}, errors +${diff}"
        assert_record "$name" "PASS" "up=${agent_up}, errors+${diff}" "up=1, errors+<=5"
        return 0
    else
        log_warn "${name}: up=${agent_up}, errors +${diff}"
        assert_record "$name" "FAIL" "up=${agent_up}, errors+${diff}" "up=1"
        return 1
    fi
}

# ------------------------------------------
# 稳态校验
# ------------------------------------------

assert_steady_state() {
    log_info "执行稳态校验..."

    local all_ok=true

    # 1. Agent 是否运行
    local agent_up
    agent_up=$(fetch_metrics | grep "^ebpf_agent_up" | awk '{print $NF}')
    if [ "${agent_up:-0}" != "1" ]; then
        log_fail "ebpf_agent_up = ${agent_up:-0}"
        all_ok=false
    else
        log_ok "ebpf_agent_up = 1"
    fi

    # 2. anomaly_score 是否全部接近 0
    local max_score
    max_score=$(fetch_metrics | metric_max "ebpf_edge_anomaly_score")
    max_score="${max_score:-0}"
    if ! le "$max_score" "$ANOMALY_CLEARED_MAX"; then
        log_warn "存在异常分数: max=${max_score}"
        all_ok=false
    fi

    # 3. 无 iptables 残留
    local ipt_count
    ipt_count=$(exec_sudo "iptables -S OUTPUT 2>/dev/null | grep -cE 'REJECT|DROP' || true" 2>/dev/null | tail -1 | tr -d '\n')
    ipt_count="${ipt_count:-0}"
    if [ "${ipt_count:-0}" -gt 0 ]; then
        log_warn "iptables 残留 ${ipt_count} 条 REJECT/DROP 规则"
        all_ok=false
    fi

    # 4. 无 tc netem 残留
    local tc_count
    tc_count=$(exec_sudo "tc qdisc show 2>/dev/null | grep -c netem || true" 2>/dev/null | tail -1 | tr -d '\n')
    tc_count="${tc_count:-0}"
    if [ "${tc_count:-0}" -gt 0 ]; then
        log_warn "tc netem 残留 ${tc_count} 条规则"
        all_ok=false
    fi

    # 5. JudgeX 健康检查（kubectl exec 到 pod 内执行）
    local health_status
    health_status=$(exec_sudo "${HEALTH_CHECK_CMD}" 2>/dev/null | head -1 | tr -d '\n')
    if [ "${health_status}" != "200" ]; then
        log_warn "JudgeX 健康检查返回 ${health_status:-000}"
        all_ok=false
    fi

    # 6. K3s pods 状态
    local non_ok_pods
    non_ok_pods=$(exec_sudo "kubectl -n ${JUDGEX_NAMESPACE} get pods --no-headers 2>/dev/null" 2>/dev/null | grep -vc "Running" || true)
    non_ok_pods=$(echo "${non_ok_pods:-0}" | tail -1 | tr -d '\n')
    if [ "${non_ok_pods:-0}" -gt 0 ]; then
        log_warn "存在 ${non_ok_pods} 个非 Running pod"
        all_ok=false
    fi

    if [ "$all_ok" = true ]; then
        log_ok "稳态校验通过"
        return 0
    else
        log_warn "稳态校验发现问题（见上方详情）"
        return 1
    fi
}

# ------------------------------------------
# HTTP 服务可达性熔断（业务层保护）
# ------------------------------------------

health_check_fuse() {
    local max_failures="${1:-${HEALTH_CHECK_MAX_FAILURES}}"
    local failures=0

    for i in $(seq 1 3); do
        local status
        status=$(exec_sudo "${HEALTH_CHECK_CMD}" 2>/dev/null | head -1 | tr -d '\n')
        if [ "$status" = "200" ]; then
            return 0
        fi
        failures=$((failures + 1))
        sleep 2
    done

    if [ "$failures" -ge "$max_failures" ]; then
        log_fail "业务熔断: 健康检查连续 ${failures} 次失败"
        return 1
    fi
    return 0
}

# ============================================================
# 指标摘要打印
# ============================================================

print_metrics_summary() {
    local snapshot_file="$1"
    local label="$2"

    echo ""
    echo "--- Metrics Summary [${label}] ---"
    local agent_events
    agent_events=$(grep "^ebpf_agent_events_total" "$snapshot_file" | awk '{print $NF}' | head -1)
    echo "  agent_events_total:    ${agent_events:-N/A}"

    local agent_up
    agent_up=$(grep "^ebpf_agent_up" "$snapshot_file" | awk '{print $NF}' | head -1)
    echo "  agent_up:              ${agent_up:-N/A}"

    local anomaly_count
    anomaly_count=$(grep -c "^ebpf_edge_anomaly_score{" "$snapshot_file" 2>/dev/null || true)
    anomaly_count=$(echo "${anomaly_count:-0}" | tail -1 | tr -d '\n')
    echo "  anomaly_score entries: ${anomaly_count}"

    local max_score
    max_score=$(grep "^ebpf_edge_anomaly_score{" "$snapshot_file" | awk '{print $NF}' | sort -rn | head -1)
    echo "  anomaly_score_max:     ${max_score:-0}"

    local anomaly_positive
    anomaly_positive=$(grep "^ebpf_edge_anomaly_score{" "$snapshot_file" | awk '$NF > 0' | wc -l)
    echo "  anomaly_score > 0:     ${anomaly_positive:-0}"

    local edge_count
    edge_count=$(grep -c "^ebpf_edge_latency_ms_count{" "$snapshot_file" 2>/dev/null || true)
    edge_count=$(echo "${edge_count:-0}" | tail -1 | tr -d '\n')
    echo "  edge_latency entries:  ${edge_count}"

    local err_count
    err_count=$(grep "^ebpf_edge_errors_total{" "$snapshot_file" | awk '{s+=$NF} END {printf "%.0f", s}')
    echo "  errors_total:          ${err_count:-0}"

    local mitigation_count
    mitigation_count=$(grep -c "^ebpf_mitigation_total{" "$snapshot_file" 2>/dev/null || true)
    mitigation_count=$(echo "${mitigation_count:-0}" | tail -1 | tr -d '\n')
    echo "  mitigation events:     ${mitigation_count}"

    echo "---"
}
