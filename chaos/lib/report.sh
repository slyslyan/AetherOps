#!/bin/bash
# report.sh — JSON + Markdown 混沌实验报告生成
# 用法: source chaos/lib/report.sh

# ============================================================
# 报告数据结构（内存）
# ============================================================

REPORT_DIR_FULL="${PROJECT_DIR:-/home/sly/Downloads/xm/ebpfagent}/${REPORT_DIR}/${RUN_ID}"
mkdir -p "${REPORT_DIR_FULL}/snapshots"

REPORT_START_TIME=$(now_iso)
REPORT_TOTAL=0
REPORT_PASS=0
REPORT_FAIL=0
REPORT_SKIP=0
REPORT_WARN=0
REPORT_EXPERIMENTS=(); declare -a REPORT_EXPERIMENTS
REPORT_WARNINGS=(); declare -a REPORT_WARNINGS

# ============================================================
# JSON 报告生成
# ============================================================

generate_json_report() {
    local outfile="${REPORT_DIR_FULL}/chaos-report.json"
    log_info "生成 JSON 报告: ${outfile}"

    local end_time
    end_time=$(now_iso)

    cat > "$outfile" << JSONEOF
{
  "run_id": "${RUN_ID}",
  "timestamp": "${REPORT_START_TIME}",
  "end_time": "${end_time}",
  "duration_sec": $(elapsed "${REPORT_START_EPOCH:-$(now_epoch)}"),
  "server": {
    "host": "${CHAOS_SSH_HOST}",
    "user": "${CHAOS_SSH_USER}",
    "agent_binary": "tracer",
    "metrics_port": ${TRACER_METRICS_PORT},
    "mcp_port": ${TRACER_MCP_PORT},
    "settings": {
      "p95_multiplier": ${P95_MULTIPLIER},
      "min_lat_ms": ${MIN_LAT_THRESHOLD_MS},
      "analysis_interval": ${ANALYSIS_INTERVAL},
      "detection_wait_sec": ${DETECT_WAIT_SEC},
      "recover_wait_sec": ${RECOVER_WAIT_SEC}
    }
  },
  "summary": {
    "total": ${REPORT_TOTAL},
    "passed": ${REPORT_PASS},
    "failed": ${REPORT_FAIL},
    "skipped": ${REPORT_SKIP},
    "warned": ${REPORT_WARN},
    "aborted": false
  },
  "experiments": [
JSONEOF

    local first=true
    for exp_json in "${REPORT_EXPERIMENTS[@]}"; do
        if [ "$first" = true ]; then
            first=false
        else
            echo "    ," >> "$outfile"
        fi
        echo "    ${exp_json}" >> "$outfile"
    done

    cat >> "$outfile" << JSONEOF
  ],
  "warnings": [
JSONEOF

    local first_warn=true
    for w in "${REPORT_WARNINGS[@]}"; do
        if [ "$first_warn" = true ]; then
            first_warn=false
        else
            echo "    ," >> "$outfile"
        fi
        echo "    \"${w}\"" >> "$outfile"
    done

    cat >> "$outfile" << JSONEOF
  ]
}
JSONEOF

    log_ok "JSON 报告已生成"
}

# ============================================================
# Markdown 报告生成
# ============================================================

generate_markdown_report() {
    local outfile="${REPORT_DIR_FULL}/chaos-report.md"
    log_info "生成 Markdown 报告: ${outfile}"

    cat > "$outfile" << MDEOF
# Chaos Engineering Report — ebpfagent

**Run ID**: \`${RUN_ID}\`
**Date**: ${REPORT_START_TIME}
**Server**: ${CHAOS_SSH_HOST} (Tencent Cloud CVM, K3s)
**Duration**: $(elapsed "${REPORT_START_EPOCH:-$(now_epoch)}")s

## Server State

| Item | Value |
|------|-------|
| Agent | tracer |
| Metrics Port | :${TRACER_METRICS_PORT} |
| MCP Port | :${TRACER_MCP_PORT} |
| P95 Multiplier | ${P95_MULTIPLIER} |
| Min Latency Threshold | ${MIN_LAT_THRESHOLD_MS}ms |
| Analysis Interval | ${ANALYSIS_INTERVAL}s |
| Detection Wait | ${DETECT_WAIT_SEC}s |
| Recovery Wait | ${RECOVER_WAIT_SEC}s |

## Results Summary

| # | Experiment | Status | Duration | Detection |
|---|-----------|--------|----------|-----------|
MDEOF

    # 从 REPORT_EXPERIMENTS 解析结果行
    for exp_json in "${REPORT_EXPERIMENTS[@]}"; do
        local exp_id exp_name exp_status exp_duration
        exp_id=$(echo "$exp_json" | grep -o '"id": *"[^"]*"' | cut -d'"' -f4)
        exp_name=$(echo "$exp_json" | grep -o '"name": *"[^"]*"' | cut -d'"' -f4)
        exp_status=$(echo "$exp_json" | grep -o '"status": *"[^"]*"' | cut -d'"' -f4)
        exp_duration=$(echo "$exp_json" | grep -o '"duration_sec": *[0-9]*' | awk '{print $NF}')

        local status_icon
        case "$exp_status" in
            PASS) status_icon="✅" ;;
            FAIL) status_icon="❌" ;;
            SKIP) status_icon="⏭️" ;;
            WARN) status_icon="⚠️" ;;
            *)    status_icon="❓" ;;
        esac

        echo "| ${exp_id} | ${exp_name} | ${status_icon} ${exp_status} | ${exp_duration}s | $( [ "$exp_status" = "SKIP" ] && echo 'N/A' || echo "${DETECT_WAIT_SEC}s" ) |" >> "$outfile"
    done

    echo "" >> "$outfile"
    echo "**Pass Rate**: ${REPORT_PASS}/${REPORT_TOTAL} ($(awk "BEGIN {printf \"%.1f\", ${REPORT_PASS}/${REPORT_TOTAL}*100}")%)" >> "$outfile"
    echo "" >> "$outfile"

    cat >> "$outfile" << MDEOF

## Warnings

MDEOF

    if [ "${#REPORT_WARNINGS[@]}" -ge 1 ] 2>/dev/null; then
        for w in "${REPORT_WARNINGS[@]:-}"; do
            echo "- ${w}" >> "$outfile"
        done
    else
        echo "No warnings." >> "$outfile"
    fi

    cat >> "$outfile" << MDEOF

## Known Limitations

1. **DNS UDP 不可观测**: 实验 05 DNS 失败仅能通过上层 TCP QPS 下降间接检测（callAnomaly）
2. **MySQL SSL 盲区**: 加密连接时 eBPF 无法解析应用层协议
3. **HTTP/2 HPACK**: 头部压缩后 eBPF 解析能力有限
4. **断言阈值依赖低负载环境**: 高负载时需重新标定基线
5. **Prometheus scrape_interval=15s**: 若环境变更须同步调整 DETECT_WAIT_SEC

## Artifacts

- Metrics snapshots: \`${REPORT_DIR_FULL}/snapshots/\`
- JSON report: \`${REPORT_DIR_FULL}/chaos-report.json\`

---

*Report generated at $(now_iso)*
MDEOF

    log_ok "Markdown 报告已生成"
}

# ============================================================
# 实验记录函数（供实验脚本调用）
# ============================================================

# 记录单个实验的完整结果
record_experiment_result() {
    local exp_id="$1"
    local exp_name="$2"
    local exp_status="$3"  # PASS / FAIL / SKIP
    local exp_start="$4"
    local exp_end="$5"
    local pre_snapshot="$6"
    local during_snapshot="$7"
    local post_snapshot="$8"

    local exp_duration=$((exp_end - exp_start))
    REPORT_TOTAL=$((REPORT_TOTAL + 1))

    case "$exp_status" in
        PASS) REPORT_PASS=$((REPORT_PASS + 1)) ;;
        FAIL) REPORT_FAIL=$((REPORT_FAIL + 1)) ;;
        SKIP) REPORT_SKIP=$((REPORT_SKIP + 1)) ;;
        WARN) REPORT_WARN=$((REPORT_WARN + 1)) ;;
    esac

    # 构建断言 JSON 数组
    local assertions_json="["
    local first=true
    for i in $(seq 1 "$ASSERTION_COUNT"); do
        local aname="${ASSERTION_RESULTS[${i}_name]}"
        local astatus="${ASSERTION_RESULTS[${i}_status]}"
        local aactual="${ASSERTION_RESULTS[${i}_actual]}"
        local aexpected="${ASSERTION_RESULTS[${i}_expected]}"

        if [ "$first" = true ]; then first=false; else assertions_json+=","; fi
        assertions_json+="{\"name\":\"${aname}\",\"status\":\"${astatus}\",\"actual\":\"${aactual}\",\"expected\":\"${aexpected}\"}"
    done
    assertions_json+="]"

    # 指标摘要
    local pre_max during_max post_max
    pre_max=$(get_baseline_max "ebpf_edge_anomaly_score" "$pre_snapshot")
    pre_max="${pre_max:-0}"
    during_max=$(get_baseline_max "ebpf_edge_anomaly_score" "$during_snapshot")
    during_max="${during_max:-0}"
    post_max=$(get_baseline_max "ebpf_edge_anomaly_score" "$post_snapshot")
    post_max="${post_max:-0}"

    local pre_errors during_errors
    pre_errors=$(grep "^ebpf_edge_errors_total{" "$pre_snapshot" 2>/dev/null | awk '{s+=$NF} END {printf "%.0f", s}')
    during_errors=$(grep "^ebpf_edge_errors_total{" "$during_snapshot" 2>/dev/null | awk '{s+=$NF} END {printf "%.0f", s}')

    local exp_json
    exp_json=$(cat << JSONEXP
{
  "id": "${exp_id}",
  "name": "${exp_name}",
  "status": "${exp_status}",
  "start_time": "$(date -d "@${exp_start}" -Iseconds 2>/dev/null || echo "${exp_start}")",
  "duration_sec": ${exp_duration},
  "phases": {
    "assertions": {
      "status": "${exp_status}",
      "checks": ${assertions_json}
    }
  },
  "metrics_snapshot": {
    "pre": {
      "anomaly_score_max": ${pre_max},
      "errors_total": ${pre_errors:-0}
    },
    "during": {
      "anomaly_score_max": ${during_max},
      "errors_total": ${during_errors:-0}
    },
    "post": {
      "anomaly_score_max": ${post_max}
    }
  }
}
JSONEXP
)

    REPORT_EXPERIMENTS+=("$exp_json")
}

# 添加警告信息
add_warning() {
    REPORT_WARNINGS+=("$1")
    log_warn "$1"
}

# 设置开始时间
set_report_start() {
    REPORT_START_EPOCH=$(now_epoch)
    REPORT_START_TIME=$(now_iso)
}
