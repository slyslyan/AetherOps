#!/bin/bash
# AetherOps — Non-K8s 单机部署脚本
#
# 适用于在 Linux 物理机/VM（如 Hadoop 节点）上直接部署，
# 无需 Kubernetes 集群。
#
# 前置条件：
#   - Linux 内核 >= 5.8（支持 BTF / CO-RE）
#   - Go >= 1.24 + clang/llvm 18+
#   - Docker 和 docker-compose
#   - Python >= 3.11 + Poetry（可选，仅认知面需要）
#
# 部署组件：
#   [systemd] aetherops-tracer    — eBPF 数据面探针
#   [docker]  aetherops-core      — Python 认知面
#   [docker]  neo4j / milvus / prometheus / grafana

set -euo pipefail

# ── 配置 ──
INSTALL_DIR="/opt/aetherops"
TRACER_BIN="/usr/local/bin/aetherops-tracer"
TRACER_ENV_FILE="/etc/default/aetherops-tracer"
CORE_ENV_FILE="/etc/default/aetherops-core"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --tracer-only         仅部署 eBPF 数据面（不启动认知面）
  --core-only           仅部署认知面及其依赖（docker-compose）
  --iface NAME          eBPF 附着网卡名（默认 ens33）
  --llm-api-key KEY     LLM API 密钥
  --llm-model MODEL     LLM 模型名（默认 deepseek-v4-flash）
  --llm-api-url URL     LLM API 地址
  -h, --help            显示帮助
EOF
    exit 0
}

# ── 参数解析 ──
TRACER_ONLY=false
CORE_ONLY=false
EBPF_IFACE="ens33"
LLM_API_KEY=""
LLM_MODEL="deepseek-v4-flash"
LLM_API_URL="https://api.openai.com/v1"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tracer-only)   TRACER_ONLY=true; shift ;;
        --core-only)     CORE_ONLY=true; shift ;;
        --iface)         EBPF_IFACE="$2"; shift 2 ;;
        --llm-api-key)   LLM_API_KEY="$2"; shift 2 ;;
        --llm-model)     LLM_MODEL="$2"; shift 2 ;;
        --llm-api-url)   LLM_API_URL="$2"; shift 2 ;;
        -h|--help)       usage ;;
        *)               error "Unknown option: $1"; usage ;;
    esac
done

# ── 前置检查 ──
check_prereqs() {
    info "Checking prerequisites..."

    if [[ "$(uname -s)" != "Linux" ]]; then
        error "This script only works on Linux (eBPF required)"
        exit 1
    fi

    kernel=$(uname -r | cut -d. -f1-2)
    if [[ "$(echo "$kernel 5.8" | awk '{print ($1 < $2)}')" == "1" ]]; then
        error "Linux kernel >= 5.8 required (current: $(uname -r))"
        exit 1
    fi

    # BTF check
    if [[ ! -f /sys/kernel/btf/vmlinux ]]; then
        warn "BTF not found — eBPF CO-RE may not work on this kernel"
    fi

    # sudo 下 PATH 可能丢失，补充常见用户路径
    export PATH="$PATH:/home/sly/software/go/bin:/usr/local/go/bin:$HOME/go/bin"

    if ! $CORE_ONLY; then
        if ! command -v go &>/dev/null; then
            error "Go >= 1.24 is required: https://go.dev/dl/"
            exit 1
        fi
        if ! command -v clang &>/dev/null; then
            error "clang/llvm >= 18 is required"
            exit 1
        fi
    fi

    if ! $TRACER_ONLY; then
        if ! command -v docker &>/dev/null; then
            error "Docker is required for cognitive plane"
            exit 1
        fi
        if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
            error "docker-compose is required for cognitive plane"
            exit 1
        fi
    fi

    info "All prerequisites satisfied"
}

# ── 编译 eBPF 探针 ──
build_tracer() {
    info "Building eBPF tracer..."

    cd "$PROJECT_ROOT"
    go generate ./cmd/tracer/...
    GOPROXY=https://goproxy.cn,direct go build -o "$TRACER_BIN" ./cmd/tracer/

    # Grant eBPF capabilities to the binary (so root is not required at runtime)
    setcap cap_bpf,cap_net_admin,cap_sys_ptrace,cap_sys_admin+ep "$TRACER_BIN" 2>/dev/null || \
        warn "setcap failed (not critical, systemd AmbientCapabilities will be used)"

    info "Tracer binary built: $TRACER_BIN"
}

# ── 安装 systemd 服务 ──
install_tracer_service() {
    info "Installing systemd service for eBPF tracer..."

    local service_src="$PROJECT_ROOT/deploy/nonk8s/aetherops-tracer.service"
    cp "$service_src" /etc/systemd/system/aetherops-tracer.service

    # Write environment file
    cat > "$TRACER_ENV_FILE" <<EOF
# AetherOps eBPF Tracer Configuration
# This file is sourced by the aetherops-tracer systemd service
EBPF_IFACE=$EBPF_IFACE
CFG_P95_MULTIPLIER=1.2
CFG_MIN_LAT_MS=10
CFG_ANALYSIS_INTERVAL=15
CFG_MITIGATION_COOLDOWN_SEC=120
CFG_PROFILE_DURATION=10
CFG_MAX_SUSPECTS=5
LOG_LEVEL=INFO
EOF

    systemctl daemon-reload
    systemctl enable aetherops-tracer
    info "Tracer service installed (start with: systemctl start aetherops-tracer)"
}

# ── 安装认知面（docker-compose）──
install_core() {
    info "Installing AetherOps cognitive plane via docker-compose..."

    mkdir -p "$INSTALL_DIR"

    # Copy compose file and config
    cp "$PROJECT_ROOT/docker-compose.aetherops.yml" "$INSTALL_DIR/"
    cp -r "$PROJECT_ROOT/config" "$INSTALL_DIR/" 2>/dev/null || true

    # Write environment file for core
    if [[ -n "$LLM_API_KEY" ]]; then
        cat > "$CORE_ENV_FILE" <<EOF
# AetherOps Core Configuration
# This file is sourced by the aetherops-core systemd service
LLM_API_KEY=$LLM_API_KEY
LLM_MODEL=$LLM_MODEL
LLM_API_URL=$LLM_API_URL
EOF
    fi

    # Install systemd service for core
    local service_src="$PROJECT_ROOT/deploy/nonk8s/aetherops-core.service"
    cp "$service_src" /etc/systemd/system/aetherops-core.service
    systemctl daemon-reload
    systemctl enable aetherops-core

    # Start docker-compose now
    info "Starting dependencies (Neo4j, Milvus, Prometheus, Grafana)..."
    local compose_cmd="docker-compose"
    if ! command -v docker-compose &>/dev/null; then
        compose_cmd="docker compose"
    fi
    $compose_cmd -f "$INSTALL_DIR/docker-compose.aetherops.yml" up -d

    info "Cognitive plane installed (manage with: systemctl start/stop aetherops-core)"
}

# ── 主流程 ──
main() {
    echo "=============================================="
    echo "  AetherOps 非 K8s 部署"
    echo "=============================================="
    echo ""

    check_prereqs

    if $TRACER_ONLY; then
        build_tracer
        install_tracer_service
    elif $CORE_ONLY; then
        install_core
    else
        build_tracer
        install_tracer_service
        install_core
    fi

    echo ""
    echo "=============================================="
    echo "  AetherOps 部署完成"
    echo "=============================================="
    echo ""
    echo "启动/停止:"
    if ! $CORE_ONLY; then
        echo "  systemctl start aetherops-tracer"
        echo "  systemctl stop aetherops-tracer"
        echo "  journalctl -u aetherops-tracer -f"
    fi
    if ! $TRACER_ONLY; then
        echo "  systemctl start aetherops-core   (docker-compose up)"
        echo "  systemctl stop aetherops-core    (docker-compose down)"
    fi
    echo ""
    echo "服务端口:"
    echo "  Neo4j Browser:   http://localhost:7474"
    echo "  Milvus:          localhost:19530"
    echo "  Prometheus:      http://localhost:9090"
    echo "  Grafana:         http://localhost:3000  (admin/aetherops)"
    if ! $CORE_ONLY; then
        echo ""
        echo "eBPF 网卡: $EBPF_IFACE"
        echo "调优配置:  $TRACER_ENV_FILE"
    fi
    if ! $TRACER_ONLY && [[ -n "$LLM_API_KEY" ]]; then
        echo "LLM 模型:  $LLM_MODEL"
    fi
}

main
