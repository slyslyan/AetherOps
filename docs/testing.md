
# 演示与测试指南

本文档将指导你从零开始验证 **AetherOps**（Go eBPF 数据面）的所有核心功能。所有测试均可在单台 Linux 机器（内核 ≥ 5.8）上完成，无需提前部署 Kubernetes 集群（K8s 功能为可选）。

---

## 0. 测试前准备

### 环境要求
- Ubuntu 24.04 Server （推荐），内核 6.8+
- Go 1.24+
- clang, llvm, libbpf-dev, bpftool 已安装（参考 README 安装步骤）
- 已下载或克隆项目源码，并位于项目根目录 `ebpfagent/`

### 编译项目
```bash
# 在项目根目录下执行
rm -f cmd/tracer/*_bpf*.go          # 清理旧的生成文件
go generate ./cmd/tracer/...        # 生成 eBPF 绑定代码
go build -o ebpf-local ./cmd/tracer/ # 编译可执行文件
```

> **已知 Bug 修复**：如果遇到 `nil map panic`（mitCooldowns），确认 `cmd/tracer/config.go` 中使用 `var mitCooldowns = make(map[string]time.Time)` 而非 `var mitCooldowns map[string]time.Time`（未初始化的 nil map 在写入时会 panic）。

### 安装 Python 依赖（可选，MCP 客户端测试需要）
```bash
cd aetherops
poetry install
# 或使用 pip 直接安装：
# pip install --break-system-packages -e .
# 或设置 PYTHONPATH：
# export PYTHONPATH=/path/to/aetherops:$PYTHONPATH
```

### 启动本地 pprof 测试服务
本项目自带了 `pprof-demo.go`，用于模拟一个开启了 pprof 的 Go 服务：
```bash
go run pprof-demo.go &
```
确认服务已启动：
```bash
curl -s http://127.0.0.1:6060/debug/pprof/
```
应返回 HTML 页面。

---

## 1. 基础监控功能测试

### 1.1 启动探针（模拟延迟模式）
```bash
sudo SIMULATE_LATENCY=1 ./ebpf-local
```

**预期输出**：
- 控制台打印 `✅ 网络探针已启动！...`
- `🔧 模拟延迟模式已启用`
- 紧接着会实时刷出系统内部 TCP 连接的日志，例如：
  ```
  🌐 PID=12003 (kube-apiserver) 192.168.49.2:8443 -> 10.244.0.2:51880 延迟=2000.00 ms
  ```

### 1.2 验证调用拓扑
等待约 10 秒，控制台会打印一次拓扑快照：
```
========== 调用拓扑 ==========
Chrome_ChildIOT -> 113.215.232.204:443 | count:3 avgLat:2000.00 ms emaLat:2000.00 ms P95:2000.00 ms score:0.00 callAnomaly:0.00 errors:3
...
==============================
```
✅ 看到形如 `源 → 目标` 的统计行，说明 eBPF 采集和拓扑构建正常。

### 1.3 验证 Prometheus 指标
保持探针运行，另开终端执行：
```bash
curl -s http://localhost:2112/metrics | grep ebpf_edge_calls_total
```
应显示非零的调用计数，例如：
```
ebpf_edge_calls_total{dst="127.0.0.1:2379",src="kube-apiserver"} 56
```
✅ Prometheus 指标暴露正常。

---

## 2. 根因分析核心算法测试

### 2.1 触发调用量骤降异常
1. 保持探针运行。
2. 打开第二个终端，制造持续访问 pprof 服务的流量：
   ```bash
   while true; do curl -s -o /dev/null http://127.0.0.1:6060/debug/pprof/; sleep 0.3; done
   ```
3. 等待 **约 30 秒**，让 EMA 基线稳定（此时拓扑中 `curl -> 127.0.0.1:6060` 的异常分数应为 0）。
4. 按 `Ctrl+C` **停止 curl 循环**。
5. 再等待 **约 30 秒**（根因分析每 15 秒执行一次）。

**预期输出**：
- 控制台拓扑快照中 `curl -> 127.0.0.1:6060` 的 `CallAnomaly` 变为大于 0，`score` 也随之大于 0。
- 随后会打印：
  ```
  ⚠️  根因分析：高延迟嫌疑节点
    嫌疑: 127.0.0.1:6060 (嫌疑分数: xxx, ...)
     🔗 故障集群分组：
      集群 1: 127.0.0.1:6060 (分数 xxx) ...
     💡 历史模式匹配：与 xx:xx:xx 的历史故障模式相似，推荐重启相关 Pod 或检查数据库
  ```
✅ 自适应阈值、多维度异常分数、故障集群、历史事件学习功能全部验证通过。

### 2.2 验证根因分数指标
```bash
curl -s http://localhost:2112/metrics | grep ebpf_root_cause_score
```
应能看到非零的嫌疑分数。

---

## 3. 自愈动作测试

### 3.1 限流与保护列表
在探针日志中，当嫌疑节点为 `127.0.0.1:6060` 时，你会看到：
```
⚠️ 自愈触发：嫌疑节点 127.0.0.1:6060 (嫌疑分数 ...)
   → 对 IP 127.0.0.1 执行 tc 限流
   → 限流跳过: 受保护 IP，拒绝限流: 127.0.0.1
```
说明保护列表生效。

### 3.2 故障现场保全
限流跳过之后，保全动作会继续：
```
   → 开始故障现场保全...
   → 正在抓取 cpu profile: http://127.0.0.1:6060/debug/pprof/profile?seconds=10
   → cpu profile 火焰图生成成功，大小 xxxx bytes
   → 正在抓取 heap profile: ...
   → 正在抓取 goroutine dump: ...
   → 正在抓取 thread dump: ...
   → 开始抓包，目标 IP 127.0.0.1，接口 ens33，时长 10s ...
   → 抓包结束，文件已保存: capture-127.0.0.1-xxxxxxxxx.pcap
```

**验证文件生成**：
```bash
ls -la cpu-*.svg heap-*.svg goroutine-*.txt thread-*.txt capture-*.pcap
```
✅ 所有文件均存在且非空。用浏览器打开 SVG 可看到火焰图。

---

## 4. 飞书/钉钉通知测试

### 4.1 配置 Webhook
去飞书群或钉钉群添加自定义机器人，复制 Webhook URL。

```bash
export FEISHU_WEBHOOK="你的webhook地址"
```

### 4.2 重新启动探针并触发自愈
```bash
sudo SIMULATE_LATENCY=1 ./ebpf-local
```
重复**2.1 节**的测试（先制造持续流量，再停止），等待自愈触发。

### 4.3 检查群消息
飞书群内应收到类似：
```
【eBPF 根因告警】
时间: 22:30:15
嫌疑节点:
- 127.0.0.1:6060 (分数: 3200.00, 平均延迟: 2000.00 ms, 调用次数: 45)
火焰图文件: cpu-127.0.0.1-1712345678.svg heap-127.0.0.1-1712345678.svg 
请及时处理。
```
✅ 通知功能正常。

---

## 5. K8s Pod 隔离功能测试（可选，需要 Minikube 环境）

### 5.1 恢复 K8s 集群连接
```bash
sudo tc qdisc del dev ens33 root 2>/dev/null
minikube status
```
确保集群正常。

### 5.2 创建测试 Deployment
```bash
kubectl create deployment test-app --image=nginx:alpine
kubectl get pod -o wide -l app=test-app
```
记下 Pod IP，例如 `10.244.0.5`。

### 5.3 用探针直接测试 Pod 重启
```bash
sudo KUBECONFIG=/home/sly/.kube/config SIMULATE_LATENCY=1 TEST_POD_IP=10.244.0.5 ./ebpf-local
```

**预期输出**：
启动日志会立即显示：
```
K8s 测试：找到 Pod default/test-app-xxxxxxxxx-xxxxx，准备重启...
K8s 测试：已成功触发 Pod default/test-app-xxxxxxxxx-xxxxx 重启！
```
同时另一个终端运行 `kubectl get pods -w` 会观察到 Pod 被 Terminate 并重新创建。
✅ K8s Pod 隔离功能正常。

### 5.4 清理
```bash
kubectl delete deployment test-app
sudo tc qdisc del dev ens33 root 2>/dev/null
```

---

## 6. 清理环境
测试结束后，执行：
```bash
pkill pprof-demo
sudo tc qdisc del dev ens33 root 2>/dev/null
```

---

## 7. MCP 客户端验证（Python 认知面）

### 7.1 安装 Python 依赖
```bash
cd aetherops
poetry install
# 或 pip install --break-system-packages -e .
```

### 7.2 直连验证（需要 Go 数据面正在运行）
确保 `ebpf-local` 已在运行（监听 :50052），然后：

```bash
cd aetherops
python3 -c "
import asyncio
from aetherops.core.mcp_client import MCPClient
async def test():
    c = MCPClient('http://localhost:50052')
    await c.connect()
    print('✅ MCP 连接成功')
    print('工具列表:', [t['name'] for t in c.list_discovered_tools()])
    topo = await c.get_topology(include_healthy=True)
    print(f'拓扑: {topo.node_count} 节点, {topo.edge_count} 边')
asyncio.run(test())
"
```

**预期输出**：
```
✅ MCP 连接成功
工具列表: ['get_topology', 'evaluate_remediation', 'execute_remediation', 'check_policy', 'list_policies']
拓扑: 1964 节点, 1980 边
```

### 7.3 SSH 隧道远程连接（Go 数据面在远程服务器）
```bash
# 终端 1：建立隧道
ssh -L 50052:localhost:50052 user@remote-server

# 终端 2：运行验证（连接本地转发的端口）
python3 -c "同上 7.2 节代码"
```

### 7.4 爆炸半径评估测试
```bash
python3 -c "
import asyncio
from aetherops.core.mcp_client import MCPClient
async def test():
    c = MCPClient('http://localhost:50052')
    await c.connect()
    report = await c.evaluate_remediation('10.42.0.90:8080', 'TC_DROP')
    print(f'风险等级: {report[\"risk_level\"]}')
    print(f'影响服务: {report[\"affected_services\"]}')
    print(f'错误预算消耗: {report[\"estimated_error_budget_consumption\"]}%')
asyncio.run(test())
"
```

### 7.5 自愈执行测试
```bash
python3 -c "
import asyncio
from aetherops.core.mcp_client import MCPClient
async def test():
    c = MCPClient('http://localhost:50052')
    await c.connect()
    result = await c.execute_remediation('10.42.0.90:8080', 'TC_DROP', force=True)
    print(f'执行状态: {result[\"status\"]}')
    print(f'执行ID: {result[\"execution_id\"]}')
asyncio.run(test())
"
```

---

**🎉 恭喜！** 你已经完整验证了 eBPF‑AutoHeal 的全部功能。如果在测试过程中遇到任何问题，请参考项目文档中的 **常见问题与解决方案** 章节。
