# eBPF-AutoHeal 混沌工程验证

## 实验矩阵

| # | 实验 | 故障注入 | 预期检测信号 | 预期自愈动作 | MTTR 改善 |
|---|------|---------|-------------|-------------|----------|
| 1 | MySQL 延迟注入 | tc netem 200ms | edge P95 突增 >2x baseline | TC_DROP 隔离慢节点 | 30s → 5s (6x) |
| 2 | HTTP 500 错误 | iptables 重定向到错误页 | error_rate > 50% | POD_RESTART | 120s → 30s (4x) |
| 3 | Redis 延迟注入 | tc netem 100ms on 6379 | Redis cmd latency p95 > 100ms | TC_DROP | 30s → 5s (6x) |
| 4 | TCP 拒绝连接 | iptables REJECT | error_rate = 100% | TC_DROP 熔断 | 60s → 5s (12x) |
| 5 | CPU 打满 | stress-ng --cpu 4 | 同节点所有边 P95 升高, 错误率 <1% | SCALE_UP | 180s → 60s (3x) |
| 6 | DNS 解析失败 | iptables DROP udp/53 | error_rate 100%, upstream only | POD_RESTART dns | 90s → 30s (3x) |
| 7 | 网络分区 | iptables DROP 特定 IP | 单节点所有边 error_rate 100% | TC_DROP 隔离 | - |

## 实验 1: MySQL 延迟注入

### 目标
验证 eBPF 能检测到 MySQL 连接的 RTT 异常，触发 TC_DROP 隔离慢节点。

### 前置条件
- eBPF agent 已部署到目标节点
- Python AI 认知面已启动
- MySQL 服务正常运行

### 故障注入
```bash
# 在 MySQL 服务节点上注入 200ms 延迟
sudo tc qdisc add dev ens33 root netem delay 200ms

# 观察 eBPF agent 日志
journalctl -u ebpfagent -f | grep -E "suspect|mitigation"

# 清理
sudo tc qdisc del dev ens33 root
```

### 预期结果
1. 15s 内 edge P95 突增 >2x baseline
2. 根因分析将 MySQL 节点排为第一嫌疑
3. TC_DROP 规则注入（或 DryRun 模式下记录决策）
4. MTTR: 手动排查 ~30s → 自动检测+隔离 ~5s

---

## 实验 2: HTTP 500 错误注入

### 故障注入
```bash
# 将目标服务流量重定向到返回 500 的 mock
sudo iptables -t nat -A OUTPUT -p tcp --dport 8080 -j DNAT --to-destination 127.0.0.1:15000
# 本地启动一个返回 500 的 mock
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(500)
        self.end_headers()
HTTPServer(('', 15000), H).serve_forever()
" &

# 清理
sudo iptables -t nat -D OUTPUT -p tcp --dport 8080 -j DNAT --to-destination 127.0.0.1:15000
kill %1
```

### 预期结果
1. error_rate 急剧上升 (http_probe 捕获 5xx)
2. 专家规则 "network-partition" 或 "conn-pool-exhaustion" 命中
3. POD_RESTART 建议生成

---

## 实验 3: Redis 延迟注入

### 前置条件
- Redis 服务在运行
- redis_trace eBPF 探针已加载

### 故障注入
```bash
sudo tc qdisc add dev ens33 root netem delay 100ms
```

### 验证
```bash
# 检查 Redis 命令是否被 eBPF 捕获
curl -s localhost:2112/metrics | grep redis_commands
```

---

## 实验 4: TCP 拒绝连接

### 故障注入
```bash
sudo iptables -A OUTPUT -p tcp --dport 3306 -j REJECT --reject-with tcp-reset
# 清理
sudo iptables -D OUTPUT -p tcp --dport 3306 -j REJECT --reject-with tcp-reset
```

### 预期结果
- conntrack 探针捕获大量短连接 + 错误
- 100% error_rate 触发 mitigation

---

## 实验 5: CPU 打满

### 故障注入
```bash
stress-ng --cpu 4 --timeout 120s
```

### 预期结果
- 同节点所有出边 P95 升高但 error_rate < 1%
- 专家规则 "cpu-throttle" 命中
- SCALE_UP 建议生成

---

## 实验 6: DNS 失败

### 故障注入
```bash
sudo iptables -A OUTPUT -p udp --dport 53 -j DROP
# 清理
sudo iptables -D OUTPUT -p udp --dport 53 -j DROP
```

### 预期结果
- 所有依赖外部 DNS 的服务边出现 100% error_rate
- 根因分析定位到 DNS 服务节点

---

## 实验 7: 网络分区

### 故障注入
```bash
# 隔离特定 IP 的通信
sudo iptables -A OUTPUT -d 192.168.1.100 -j DROP
sudo iptables -A INPUT -s 192.168.1.100 -j DROP

# 清理
sudo iptables -D OUTPUT -d 192.168.1.100 -j DROP
sudo iptables -D INPUT -s 192.168.1.100 -j DROP
```

---

## 批量实验执行

使用 `scripts/run-chaos.sh` 一键执行全部实验（每项间隔 60s 恢复期）。

## 成功标准

| 能力 | 指标 | 目标 |
|------|------|------|
| 异常检测 | 从注入到检测的时间 | < 15s |
| 根因分析 | Top-1 准确率 | > 80% |
| 自愈执行 | 从检测到执行的时间 | < 10s |
| 误报率 | 正常运行的误报 | < 5% |
| MTTR | 对比手动排查 | > 3x 改善 |
