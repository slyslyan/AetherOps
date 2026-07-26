#!/bin/bash
# inject.sh — 故障注入原语（幂等：先删后加）
# 使用 exec_ssh 在服务器上执行

# ============================================================
# 网络延迟注入 (tc netem)
# ============================================================

# 全局延迟 (eth0 + cni0, K3s pod 流量走 cni0 网桥)
inject_netem_delay() {
    local delay="${1:-200ms}"
    local iface="${SERVER_IFACE}"
    log_info "注入全局网络延迟: ${delay} on ${iface} + cni0"
    exec_sudo "tc qdisc del dev ${iface} root 2>/dev/null || true"
    exec_sudo "tc qdisc add dev ${iface} root netem delay ${delay}"
    exec_sudo "tc qdisc del dev cni0 root 2>/dev/null || true"
    exec_sudo "tc qdisc add dev cni0 root netem delay ${delay}"
    log_ok "网络延迟已注入"
}

# 端口过滤延迟（仅延迟特定端口的流量，K3s pod 流量走 cni0）
inject_port_delay() {
    local delay="${1:-150ms}"
    local port="${2:-6379}"
    local iface="${SERVER_IFACE}"
    log_info "注入端口延迟: ${delay} on port ${port} (${iface} + cni0)"
    for dev in "${iface}" cni0; do
        exec_sudo "tc qdisc del dev ${dev} root 2>/dev/null || true"
        exec_sudo "tc qdisc add dev ${dev} root handle 1: prio"
        exec_sudo "tc qdisc add dev ${dev} parent 1:3 handle 30: netem delay ${delay}"
        exec_sudo "tc filter add dev ${dev} protocol ip parent 1:0 prio 3 u32 match ip dport ${port} 0xffff flowid 1:3"
    done
    log_ok "端口延迟已注入"
}

# ============================================================
# TCP 拒绝连接 (iptables REJECT)
# ============================================================

inject_tcp_reject() {
    local port="${1:-3306}"
    log_info "注入 TCP 拒绝: port ${port}"
    exec_sudo "iptables -D OUTPUT -p tcp --dport ${port} -j REJECT --reject-with tcp-reset 2>/dev/null || true"
    exec_sudo "iptables -A OUTPUT -p tcp --dport ${port} -j REJECT --reject-with tcp-reset"
    log_ok "TCP 拒绝已注入 (port ${port})"
}

# ============================================================
# DNS 失败 (iptables DROP)
# ============================================================

inject_dns_drop() {
    log_info "注入 DNS 失败: DROP udp/53"
    exec_sudo "iptables -D OUTPUT -p udp --dport 53 -j DROP 2>/dev/null || true"
    exec_sudo "iptables -A OUTPUT -p udp --dport 53 -j DROP"
    log_ok "DNS 已阻断"
}

# ============================================================
# 网络分区 (iptables DROP 特定 IP)
# ============================================================

inject_network_partition() {
    local target_ip="${1:-192.168.1.100}"
    log_info "注入网络分区: DROP traffic to/from ${target_ip}"
    exec_sudo "iptables -D OUTPUT -d ${target_ip} -j DROP 2>/dev/null || true"
    exec_sudo "iptables -D INPUT -s ${target_ip} -j DROP 2>/dev/null || true"
    exec_sudo "iptables -A OUTPUT -d ${target_ip} -j DROP"
    exec_sudo "iptables -A INPUT -s ${target_ip} -j DROP"
    log_ok "网络分区已注入 (隔离 ${target_ip})"
}

# ============================================================
# HTTP 500 错误注入 (mock server + iptables DNAT)
# ============================================================

MOCK_HTTP_PID=""
MOCK_HTTP_PORT=15999

inject_http_errors() {
    local target_ip="${1}"
    local target_port="${2:-${BACKEND_PORT}}"
    log_info "注入 HTTP 500 错误: ${target_ip}:${target_port} -> localhost:${MOCK_HTTP_PORT}"

    # 启动 mock HTTP 500 服务器
    if [ "$CHAOS_DRY_RUN" != "true" ]; then
        exec_ssh "python3 -c \"
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self.send_response(500); self.end_headers()
    def do_POST(self): self.send_response(500); self.end_headers()
    def log_message(self, *args): pass
http.server.HTTPServer(('127.0.0.1', ${MOCK_HTTP_PORT}), H).serve_forever()
\" &" &
        MOCK_HTTP_PID=$(exec_ssh "echo \$!" 2>/dev/null | tail -1)
        sleep 2
        log_info "Mock HTTP 500 服务器已启动 (pid=${MOCK_HTTP_PID})"
    fi

    # DNAT 重定向
    exec_sudo "iptables -t nat -D OUTPUT -p tcp -d ${target_ip} --dport ${target_port} -j DNAT --to-destination 127.0.0.1:${MOCK_HTTP_PORT} 2>/dev/null || true"
    exec_sudo "iptables -t nat -A OUTPUT -p tcp -d ${target_ip} --dport ${target_port} -j DNAT --to-destination 127.0.0.1:${MOCK_HTTP_PORT}"

    # 验证 DNAT 规则已生效
    local nat_count
    nat_count=$(exec_sudo "iptables -t nat -L OUTPUT -n" 2>/dev/null | grep -c "15999" || echo "0")
    log_info "DNAT 规则数: ${nat_count}"
    log_ok "HTTP 500 错误已注入"
}

# ============================================================
# CPU 打满 (stress-ng)
# ============================================================

STRESS_PID=""

inject_cpu_stress() {
    local cpus="${1:-2}"
    local duration="${2:-60s}"
    log_info "注入 CPU 压力: ${cpus} 核, ${duration}"

    if [ "$CHAOS_DRY_RUN" != "true" ]; then
        if exec_ssh "command -v stress-ng" &>/dev/null; then
            exec_ssh "stress-ng --cpu ${cpus} --timeout ${duration} &" &
            STRESS_PID=$!
        else
            log_warn "stress-ng 未安装，使用 dd loop"
            exec_ssh "for i in \$(seq 1 ${cpus}); do dd if=/dev/zero of=/dev/null & done" &
            STRESS_PID=$!
        fi
        sleep 2
    fi
    log_ok "CPU 压力已注入"
}

# ============================================================
# 生成测试流量（辅助）
# ============================================================

generate_http_traffic() {
    local url="${1:-http://localhost:${BACKEND_PORT}/health}"
    local count="${2:-5}"
    log_info "生成 HTTP 流量: ${count} 次请求 ${url}"
    for i in $(seq 1 "$count"); do
        exec_ssh "curl -s -o /dev/null -w '%{http_code}' ${url} 2>/dev/null" || true
        sleep 0.5
    done
}

generate_mysql_traffic() {
    local count="${1:-5}"
    log_info "尝试生成 MySQL 连接流量: ${count} 次"
    for i in $(seq 1 "$count"); do
        exec_ssh "timeout 3 bash -c 'echo >/dev/tcp/127.0.0.1/${MYSQL_PORT}' 2>/dev/null" || true
        sleep 0.5
    done
}
