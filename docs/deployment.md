# 部署指南

## 前置条件

### 内核要求
- Linux 5.8+ (BPF CO-RE 需要 BTF 支持)
- 验证：`ls /sys/kernel/btf/vmlinux` 存在
- 未开启 lockdown 模式：`cat /sys/kernel/security/lockdown` (需为空或 `none`)

### 软件依赖
- Go 1.24+
- `libbpf` ≥ 1.0
- `clang` / `llvm-strip` (编译 eBPF 需要)
- `tcpdump` (可选，抓包分析)
- `bpftool` (可选，调试 eBPF)

### K8s 部署
- K8s 1.22+
- 节点开启 `CAP_BPF`, `CAP_NET_ADMIN`
- DaemonSet 模式需要 `privileged: true` 或具体 Linux capabilities

### 非 K8s 部署
- systemd (服务管理)
- 内核参数：`kernel.unprivileged_bpf_disabled=0`

---

## 构建

```bash
# 1. 编译 eBPF C → Go bindings
make generate
# 等价于: cd cmd/tracer && go generate ./...

# 2. 编译 Go 二进制
make build
# 等价于: go build -o ebpf-local ./cmd/tracer/

# 3. 验证
file ./ebpf-local
# ./ebpf-local: ELF 64-bit LSB executable

# 4. 检查编译的 eBPF 对象
ls -la cmd/tracer/*.o
```

---

## K8s 部署

### 方式 1：直接 kubectl

```bash
# 1. 部署 Go 数据面 DaemonSet (每节点一个)
kubectl apply -f deploy/ebpf-tracer.yaml

# 2. 部署 Python 认知面 Deployment (单副本)
kubectl apply -f deploy/aetherops-core.yaml

# 3. 验证
kubectl get pods -n aetherops
kubectl logs -n aetherops daemonset/ebpf-tracer -f
```

### 方式 2：安装脚本

```bash
bash deploy/aetherops-install.sh
# 交互式：选择 full / tracer-only / core-only
```

### 方式 3：Helm

```bash
helm install aetherops deploy/helm/aetherops \
  --namespace aetherops \
  --create-namespace \
  --set tracer.image.tag=latest \
  --set core.image.tag=latest
```

### DaemonSet 安全上下文

```yaml
spec:
  template:
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: tracer
        securityContext:
          privileged: true          # 简化；生产可用 capabilities
          # capabilities:
          #   add: ["BPF", "NET_ADMIN", "SYS_ADMIN", "SYS_RESOURCE"]
        env:
        - name: EBPF_IFACE
          value: "eth0"
        - name: CFG_METRICS_ADDR
          value: ":2112"
        - name: CFG_MCP_ADDR
          value: ":50052"
```

---

## 非 K8s 部署（systemd）

```bash
# 1. 安装
sudo bash deploy/nonk8s/install.sh

# 安装脚本会：
#   - 复制 ebpf-local 到 /usr/local/bin/
#   - 创建 systemd service 文件
#   - 启用并启动服务

# 2. 管理
sudo systemctl start aetherops-tracer
sudo systemctl start aetherops-core       # 认知面（可选）
sudo systemctl status aetherops-tracer
sudo journalctl -u aetherops-tracer -f    # 查看日志

# 3. 卸载
sudo bash deploy/nonk8s/install.sh --uninstall

# systemd service 文件：
# deploy/nonk8s/aetherops-tracer.service
# deploy/nonk8s/aetherops-core.service
```

---

## Docker 部署

```bash
# 构建镜像
docker build -f docker/Dockerfile.agent -t aetherops-agent:latest .
docker build -f docker/Dockerfile.local -t aetherops-local:latest .

# 运行（需 --privileged 访问 eBPF）
docker run --rm --privileged \
  --network host \
  -e EBPF_IFACE=eth0 \
  -e CFG_METRICS_ADDR=:2112 \
  aetherops-local:latest

# Docker Compose（含 Prometheus + Grafana）
docker compose -f docker-compose.aetherops.yml up -d
# 数据面需要在容器外单独运行（需内核 eBPF 权限）
```

---

## 配置

### 环境变量

创建 `/etc/aetherops/env`：

```bash
# 分析参数
CFG_P95_MULTIPLIER=1.5
CFG_ANALYSIS_INTERVAL=30
CFG_MAX_SUSPECTS=10

# 安全
CFG_MITIGATION_COOLDOWN_SEC=300
CFG_TC_DROP_TTL=10
DRY_RUN=true                              # 先影子模式观察

# 网络
EBPF_IFACE=eth0
CFG_METRICS_ADDR=:2112
CFG_MCP_ADDR=:50052
```

### 策略文件

```bash
# 创建策略
cat > /etc/aetherops/policies.json << 'EOF'
[
  {
    "id": "protect-core",
    "effect": "deny",
    "conditions": {
      "match_pattern": "(kube-system|istio-system|aetherops)",
      "actions": ["POD_RESTART", "TC_DROP"]
    },
    "priority": 100
  }
]
EOF

export POLICY_FILE=/etc/aetherops/policies.json
```

---

## 验证

### 健康检查

```bash
# Agent 健康
curl -s http://localhost:2112/healthz | jq .
# {"status":"ok"}

# MCP 健康
curl -s http://localhost:50052/healthz | jq .
# {"status":"ok","service":"aetherops-mcp","version":"1.0.0"}

# Prometheus 指标
curl -s http://localhost:2112/metrics | grep -E 'ebpf_agent_up|ebpf_agent_health'
# ebpf_agent_up 1
# ebpf_agent_health{component="tcp_sendmsg_probe"} 1
# ebpf_agent_health{component="mcp_server"} 1
# ...
```

### eBPF 探针验证

```bash
# 检查挂载的 BPF 程序
sudo bpftool prog list | grep -A2 'tcp_sendmsg\|tcp_connect\|tcp_close'

# 检查 BPF maps
sudo bpftool map list | grep 'events\|sampling'

# 检查 TC clsact
sudo tc filter show dev eth0 egress
```

---

## 故障排查

| 问题 | 诊断 | 解决 |
|------|------|------|
| eBPF 加载失败 | `dmesg \| tail -20` | 检查内核版本和 BTF 支持 |
| Ring Buffer 无事件 | `curl localhost:2112/metrics \| grep ringbuf_events` | 检查是否有实际 TCP 流量 |
| MCP 连接失败 | `curl localhost:50052/healthz` | 检查防火墙和端口占用 |
| TC 丢包不生效 | `sudo tc qdisc show dev eth0` | 检查接口名 `EBPF_IFACE` |
| Prometheus 无数据 | 检查 `scrape_configs` | 确认 `CFG_METRICS_ADDR` 可访问 |

### 降级运行

如果 Python 认知面不可用，Go 数据面自动降级为本地专家规则引擎：

```
LLM 诊断 (MCP) ──不可用──→ 专家规则匹配 (Go 本地)
                           ──不命中──→ 启发式评分 (仅打分，无诊断)
```

日志中可见：`Expert rule matched: cpu-throttle ...`

### 日志级别

运行时日志使用 `slog`，标准输出：
- **WARN**: Ring Buffer 读取错误 (需关注，可能丢失事件)
- **INFO**: 正常事件流、自愈决策、拓扑打印
- 无 DEBUG 级别（避免 Ring Buffer 消费延迟）
