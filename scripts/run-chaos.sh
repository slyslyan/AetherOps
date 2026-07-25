#!/bin/bash
# run-chaos.sh — eBPF-AutoHeal 混沌实验批量执行脚本
#
# 用法:
#   sudo ./scripts/run-chaos.sh [experiment_id]
#   sudo ./scripts/run-chaos.sh           # 执行全部实验
#   sudo ./scripts/run-chaos.sh 1         # 仅执行实验 1 (MySQL 延迟)
#   sudo ./scripts/run-chaos.sh --dry-run # 干运行（仅打印命令）
#
# 依赖: tc, iptables, stress-ng (按需安装)

set -euo pipefail

INTERFACE="${EBPF_IFACE:-ens33}"
RECOVERY_SEC="${RECOVERY_SEC:-60}"
DRY_RUN=false
EXPERIMENT_ID="${1:-all}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

cleanup_experiment() {
    local exp="$1"
    echo -e "${YELLOW}[cleanup] experiment $exp${NC}"
    tc qdisc del dev "$INTERFACE" root 2>/dev/null || true
    iptables -t nat -F OUTPUT 2>/dev/null || true
    iptables -F OUTPUT 2>/dev/null || true
    iptables -F INPUT 2>/dev/null || true
    pkill -f "python3 -c.*HTTPServer" 2>/dev/null || true
    pkill stress-ng 2>/dev/null || true
}

run_or_dry() {
    local desc="$1"; shift
    echo -e "${GREEN}[$(date +%H:%M:%S)] $desc${NC}"
    if [ "$DRY_RUN" = true ]; then
        echo "  DRY_RUN: $*"
    else
        eval "$@"
    fi
}

# ----- 实验 1: MySQL 延迟注入 -----
experiment_1() {
    echo "=== Experiment 1: MySQL Latency Injection (200ms) ==="
    run_or_dry "Inject 200ms delay on $INTERFACE" \
        "tc qdisc add dev $INTERFACE root netem delay 200ms"
    echo "  Waiting 30s for eBPF detection..."
    sleep 30
    cleanup_experiment 1
}

# ----- 实验 2: HTTP 500 错误注入 -----
experiment_2() {
    echo "=== Experiment 2: HTTP 500 Error Injection ==="
    local mock_port=15000
    if [ "$DRY_RUN" = false ]; then
        python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self): self.send_response(500); self.end_headers()
    def do_POST(self): self.send_response(500); self.end_headers()
HTTPServer(('', $mock_port), H).serve_forever()
" &
        MOCK_PID=$!
        sleep 1
    fi
    run_or_dry "Redirect port 8080 to mock 500" \
        "iptables -t nat -A OUTPUT -p tcp --dport 8080 -j DNAT --to-destination 127.0.0.1:$mock_port"
    echo "  Waiting 30s for eBPF detection..."
    sleep 30
    cleanup_experiment 2
    [ "$DRY_RUN" = false ] && kill $MOCK_PID 2>/dev/null || true
}

# ----- 实验 3: Redis 延迟注入 -----
experiment_3() {
    echo "=== Experiment 3: Redis Latency Injection (100ms) ==="
    run_or_dry "Inject 100ms delay on $INTERFACE" \
        "tc qdisc add dev $INTERFACE root netem delay 100ms"
    sleep 30
    cleanup_experiment 3
}

# ----- 实验 4: TCP 拒绝连接 -----
experiment_4() {
    echo "=== Experiment 4: TCP Connection Rejection ==="
    run_or_dry "REJECT TCP port 3306" \
        "iptables -A OUTPUT -p tcp --dport 3306 -j REJECT --reject-with tcp-reset"
    sleep 30
    cleanup_experiment 4
}

# ----- 实验 5: CPU 打满 -----
experiment_5() {
    echo "=== Experiment 5: CPU Saturation ==="
    if command -v stress-ng &>/dev/null; then
        run_or_dry "Run stress-ng 4 CPUs for 60s" \
            "stress-ng --cpu 4 --timeout 60s &"
    else
        echo "  stress-ng not installed, using dd loop"
        run_or_dry "CPU stress via dd" \
            "for i in 1 2 3 4; do dd if=/dev/zero of=/dev/null & done; sleep 60; pkill dd"
    fi
    sleep 30
    cleanup_experiment 5
}

# ----- 实验 6: DNS 失败 -----
experiment_6() {
    echo "=== Experiment 6: DNS Failure ==="
    run_or_dry "DROP UDP port 53" \
        "iptables -A OUTPUT -p udp --dport 53 -j DROP"
    sleep 30
    cleanup_experiment 6
}

# ----- 实验 7: 网络分区 -----
experiment_7() {
    echo "=== Experiment 7: Network Partition ==="
    local target_ip="${CHAOS_TARGET_IP:-192.168.1.100}"
    run_or_dry "DROP traffic to/from $target_ip" \
        "iptables -A OUTPUT -d $target_ip -j DROP; iptables -A INPUT -s $target_ip -j DROP"
    sleep 30
    cleanup_experiment 7
}

# ===== Main =====
if [ "$EXPERIMENT_ID" = "--dry-run" ]; then
    DRY_RUN=true
    EXPERIMENT_ID="all"
fi

if [ "$EUID" -ne 0 ] && [ "$DRY_RUN" = false ]; then
    echo "请使用 sudo 运行（需要 tc/iptables 权限）"
    exit 1
fi

echo "============================================"
echo "  eBPF-AutoHeal Chaos Experiments"
echo "  Interface: $INTERFACE"
echo "  Recovery:  ${RECOVERY_SEC}s between experiments"
echo "  Dry Run:   $DRY_RUN"
echo "============================================"

run_experiment() {
    local id="$1"
    "experiment_$id"
    echo "  Recovery wait ${RECOVERY_SEC}s..."
    sleep "$RECOVERY_SEC"
}

case "$EXPERIMENT_ID" in
    all)
        for i in 1 2 3 4 5 6 7; do
            run_experiment "$i"
        done
        ;;
    [1-7])
        run_experiment "$EXPERIMENT_ID"
        ;;
    *)
        echo "Unknown experiment: $EXPERIMENT_ID (valid: 1-7, all, --dry-run)"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}All experiments complete.${NC}"
echo "Check results:"
echo "  eBPF logs:   journalctl -u ebpfagent --since '5 min ago'"
echo "  Prometheus:  curl -s localhost:2112/metrics | grep -E 'ebpf_(edge|mitigation|agent)'"
echo "  MCP status:  curl -s localhost:50052/healthz"
