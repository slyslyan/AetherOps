#!/bin/bash
# config.sh — ebpfagent 混沌工程全局配置
# 来源: chaos/lib/*.sh, chaos/runner.sh, chaos/experiments/*.sh

set -euo pipefail

# ============================================================
# SSH 目标
# ============================================================
CHAOS_SSH_HOST="${CHAOS_SSH_HOST:-150.158.113.146}"
CHAOS_SSH_USER="${CHAOS_SSH_USER:-ubuntu}"

# ============================================================
# 服务器状态（由 server-cleanup.sh 自动检测并覆盖）
# ============================================================
TRACER_SERVICE_NAME="${TRACER_SERVICE_NAME:-ebpf-tracer.service}"
TRACER_METRICS_PORT="${TRACER_METRICS_PORT:-2112}"
TRACER_MCP_PORT="${TRACER_MCP_PORT:-50052}"
OLD_AGENT_BINARY="${OLD_AGENT_BINARY:-ebpf-oj-monitor}"

# ============================================================
# 检测时间窗口（对齐服务器 eBPF agent 配置）
# ============================================================
ANALYSIS_INTERVAL="${ANALYSIS_INTERVAL:-17}"
DETECT_WAIT_SEC="${DETECT_WAIT_SEC:-51}"          # 3x AnalysisInterval + Prometheus scrape 余量
RECOVER_WAIT_SEC="${RECOVER_WAIT_SEC:-180}"        # cooldown(10s) + P95 窗口 (30 样本) 滚动 + 分析周期余量
METRICS_SCRAPE_INTERVAL="${METRICS_SCRAPE_INTERVAL:-15}"

# ============================================================
# 服务器 eBPF agent 阈值（对齐 CFG_* 环境变量）
# ============================================================
P95_MULTIPLIER="${P95_MULTIPLIER:-0.15}"           # CFG_P95_MULTIPLIER
MIN_LAT_THRESHOLD_MS="${MIN_LAT_THRESHOLD_MS:-5}"  # CFG_MIN_LAT_MS

# ============================================================
# JudgeX K3s 信息
# ============================================================
JUDGEX_NAMESPACE="${JUDGEX_NAMESPACE:-judgex}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
REDIS_PORT="${REDIS_PORT:-6379}"
BACKEND_PORT="${BACKEND_PORT:-8080}"
FRONTEND_PORT="${FRONTEND_PORT:-8081}"

# ============================================================
# 网络接口（服务器端）
# ============================================================
SERVER_IFACE="${SERVER_IFACE:-eth0}"

# ============================================================
# 安全开关
# ============================================================
CHAOS_DRY_RUN="${CHAOS_DRY_RUN:-false}"
CHAOS_ENABLE_LOW_RISK="${CHAOS_ENABLE_LOW_RISK:-true}"
CHAOS_ENABLE_HIGH_RISK="${CHAOS_ENABLE_HIGH_RISK:-true}"
CHAOS_SKIP_HIGH_RISK="${CHAOS_SKIP_HIGH_RISK:-false}"
CHAOS_MAX_RUNTIME_SEC="${CHAOS_MAX_RUNTIME_SEC:-1800}"     # 30 分钟全局超时
CHAOS_EXPERIMENT_TIMEOUT_SEC="${CHAOS_EXPERIMENT_TIMEOUT_SEC:-300}"  # 单实验超时
CHAOS_LOCK_FILE="${CHAOS_LOCK_FILE:-/tmp/chaos-runner.lock}"

# ============================================================
# 业务熔断
# ============================================================
HEALTH_CHECK_MAX_FAILURES="${HEALTH_CHECK_MAX_FAILURES:-3}"
JUDGEX_BACKEND_DEPLOYMENT="${JUDGEX_BACKEND_DEPLOYMENT:-backend}"
# 健康检查用 kubectl exec（容器内无 curl，用 wget 替代）
HEALTH_CHECK_CMD="${HEALTH_CHECK_CMD:-kubectl -n ${JUDGEX_NAMESPACE} exec deploy/${JUDGEX_BACKEND_DEPLOYMENT} -- wget -q -O /dev/null localhost:${BACKEND_PORT}/health && echo 200 || echo 000}"
READY_CHECK_CMD="${READY_CHECK_CMD:-kubectl -n ${JUDGEX_NAMESPACE} exec deploy/${JUDGEX_BACKEND_DEPLOYMENT} -- wget -q -O- localhost:${BACKEND_PORT}/ready}"
# 强制模式（跳过交互确认）
CHAOS_FORCE_YES="${CHAOS_FORCE_YES:-false}"

# ============================================================
# 断言阈值（delta over baseline）
# ============================================================
ANOMALY_DELTA_MIN="${ANOMALY_DELTA_MIN:-0.01}"      # 最小异常分数增量
ANOMALY_CLEARED_MAX="${ANOMALY_CLEARED_MAX:-5.0}"    # "恢复"判定上限 (稳态下自然抖动可能到 1-2)
ERROR_INCREASE_MIN="${ERROR_INCREASE_MIN:-1}"         # 错误计数最小增幅

# ============================================================
# 报告
# ============================================================
REPORT_DIR="${REPORT_DIR:-chaos/reports}"
RUN_ID="${RUN_ID:-chaos-$(date +%Y%m%d-%H%M%S)}"

# ============================================================
# 风险分级 — 实验到风险等级映射
# ============================================================
declare -A EXPERIMENT_RISK
EXPERIMENT_RISK["01"]="low"
EXPERIMENT_RISK["02"]="high"
EXPERIMENT_RISK["04"]="low"
EXPERIMENT_RISK["05"]="medium"
