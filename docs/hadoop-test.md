# AetherOps × Hadoop 集群：故障注入与自愈验证

> 本文档记录 AetherOps 智能运维 Agent 在真实 Hadoop 3 节点集群上的端到端测试方案。
> 涵盖架构适配、三层递进故障模型、分级自愈执行、多集群隔离验证。

---

## 1. 集群拓扑

| 角色 | 主机名 | IP | 运行服务 |
|------|--------|----|---------|
| Hadoop Master | master | 192.168.189.10 | NameNode(:9000), DataNode(:9866), ResourceManager(:8031/8032), NodeManager |
| Hadoop Worker | slave0 | 192.168.189.11 | DataNode, NodeManager |
| Hadoop Worker | slave1 | 192.168.189.12 | DataNode, NodeManager |

**HDFS 配置**: `fs.defaultFS=hdfs://master:9000`, `dfs.replication=1`
**YARN 配置**: `yarn.resourcemanager.hostname=master`

---

## 2. AetherOps 组件与 Hadoop 的集成点

```
┌──────────────────────────────────────────────────────────────┐
│                    AetherOps 架构总览                         │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────────┐    SSE/MCP     ┌──────────────────┐    │
│  │  Go eBPF 数据平面 │◄────────────►│  Python 认知平面  │    │
│  │  (systemd 服务)   │   localhost   │  (docker-compose) │    │
│  │                   │    :50052     │                   │    │
│  │  - kprobe 采集    │              │  - LangGraph      │    │
│  │  - 拓扑构建       │              │  - Supervisor     │    │
│  │  - 根因分析       │              │  - LLM 诊断       │    │
│  │  - tc 限流        │              │  - 分级自愈       │    │
│  └───────┬───────────┘              └─────────┬─────────┘    │
│          │                                    │              │
│          ▼                                    ▼              │
│  ┌─────────────────┐               ┌──────────────────┐      │
│  │   eBPF RingBuf  │               │  Neo4j / Milvus  │      │
│  │   tcp_sendmsg   │               │  RAG 存储        │      │
│  │   tcp_connect   │               │                  │      │
│  │   tcp_close     │               │  Prometheus      │      │
│  │   TC ingress    │               │  Grafana         │      │
│  └─────────────────┘               └──────────────────┘      │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐    │
│  │  Hadoop 3 节点集群                                     │    │
│  │  master:9000 (NameNode), slave0:9866 (DataNode) ...   │    │
│  └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

### 2.1 eBPF 数据平面的采集边界

AetherOps 的 Go 数据平面通过 eBPF kprobe/kretprobe 挂载在 `tcp_sendmsg` 上，测量的是 **进程空间内 tcp_sendmsg 系统调用的耗时**（数据从用户态拷贝到内核态 socket buffer 的时间），而非网络报文的实际传输延迟。

```
应用层 send() ──► tcp_sendmsg kprobe ◄── 测量耗时 ──► kretprobe
                        │
                        ▼
                   socket buffer ──► tcp 协议栈 ──► qdisc ──► 网卡
                                           ▲           ▲
                                     tc netem 延迟   eBPF TC ingress
                                     在这里生效       在这里生效
```

**关键约束**：
- `tcp_sendmsg` 的 kprobe 无法捕获 tc qdisc 层的网络延迟（延迟发生在数据入队之后）
- 但 tc 延迟会导致 **TCP RTT 增加 → Hadoop RPC 心跳超时 → 拓扑状态变更**，这一级效果可以被拓扑模块识别
- eBPF TC 程序（ingress）可以独立做内核态丢包限流，不受 kprobe 测量边界影响

### 2.2 服务发现机制

| 方法 | 数据源 | Hadoop 场景 |
|------|--------|------------|
| K8s Pod 名 | cgroup v2 | 非 K8s 部署不适用 |
| Docker 容器名 | cgroup v2 | 非容器部署不适用 |
| 进程名 | `/proc/pid/cmdline` | Hadoop Java 进程解析为 `java` |
| IP:Port 回退 | eBPF 事件 | 如 `192.168.189.11:9866` |

当前非 K8s 部署下，Hadoop 进程在拓扑中显示为 `java → 192.168.189.11:9866`，未做进一步的 NameNode/DataNode 语义映射。

---

## 3. 故障测试方案

### 3.1 测试原则

1. **基线先行**：所有异常判定必须有正常状态的量化基准作为对照
2. **三层递进**：从资源到网络到进程，模拟真实故障的级联效应
3. **闭环验证**：检测→诊断→决策→执行→二次巡检，完整 OODA 闭环
4. **可量化**：每个验证点设定可测量的通过标准

### 3.2 三层递进故障模型

```
                 故障叠加层次
                 
    ┌─────────────────────────────────────┐
    │  第三层：进程故障                     │
    │  DataNode 进程 kill -9               │
    │  效果：节点离线，HDFS 副本丢失       │
    │  验证：MCP 拓扑节点数从 3→2         │
    └──────────────────┬──────────────────┘
                       │ 级联放大
    ┌──────────────────▼──────────────────┐
    │  第二层：网络故障                     │
    │  tc delay 200ms + loss 10% → slave0 │
    │  效果：Hadoop RPC 心跳超时           │
    │  验证：拓扑心跳间隔 > 10s            │
    └──────────────────┬──────────────────┘
                       │ 基础条件
    ┌──────────────────▼──────────────────┐
    │  第一层：资源故障                     │
    │  stress-ng CPU 90% + 内存打满       │
    │  效果：DataNode 处理能力下降          │
    │  验证：eBPF avgLat 升高 > 基准 3σ   │
    └─────────────────────────────────────┘
```

### 3.3 Phase 0 — 集群基线采集

在注入任何故障之前，采集 Hadoop 集群在健康状态下的全量基准数据。

| 采集项 | 命令/方法 | 基准值(示例) |
|--------|---------|-------------|
| HDFS DataNode 数 | `hdfs dfsadmin -report` | 3 |
| 核心端口清单 | `ss -tlnp \| grep java` | 9000, 9866, 8031, 8032, 8088, 8042 |
| 块总数 | `hdfs dfsadmin -report` | 11 blocks |
| 正常心跳间隔 | `hdfs dfsadmin -report \| grep "Last contact"` | < 3s |
| MCP 拓扑节点数 | `python mcp_client get_topology` | N 个活动连接 |
| eBPF avgLat 基准 | `journalctl -u aetherops-tracer \| grep "avgLat"` | < 0.1ms |
| 各端口调用频次 | MCP 拓扑 edges | 记录 baseline |
| HDFS 读写耗时 | `time hadoop fs -put 4MB test file` | < 1s |
| WordCount 耗时 | `hadoop jar WordCount.jar` | T 秒 |

**基线采集脚本**：
```bash
# Hadoop 集群健康
hdfs dfsadmin -report > /tmp/baseline-hdfs.txt
yarn node -list > /tmp/baseline-yarn.txt

# 端口扫描
ss -tlnp | grep java > /tmp/baseline-ports.txt

# HDFS 基准读写
dd if=/dev/urandom of=/tmp/hdfs-bench.bin bs=1M count=4
time hdfs dfs -put /tmp/hdfs-bench.bin /tmp/bench-baseline.bin

# 拓扑基准
python3 -c "
import asyncio
from aetherops.core.mcp_client import MCPClient
async def get_baseline():
    c = MCPClient('http://localhost:50052')
    await c.connect()
    topo = await c.get_topology(include_healthy=True)
    print(f'nodes={topo.node_count} edges={topo.edge_count}')
    for n in topo.nodes:
        print(f'  node: {n.id} latency={n.avg_latency_ms} calls={n.call_count}')
asyncio.run(get_baseline())
" > /tmp/baseline-topology.txt
```

### 3.4 Phase 1 — 三层故障叠加注入

#### 第一层：资源故障（slave0）

```bash
# SSH 到 slave0，用 stress-ng 打满 CPU 和内存
ssh slave0 "sudo stress-ng --cpu 4 --cpu-load 90 --vm 2 --vm-bytes 2G --timeout 300s" &
```

**量化触发条件**：
- eBPF avgLat > 基准均值 + 3σ
- 或 DataNode 处理延迟 > 500ms

#### 第二层：网络故障（master → slave0）

```bash
# 在 master 添加 tc 规则：发往 slave0 的流量延迟 200ms + 10% 丢包
sudo tc qdisc replace dev ens33 root handle 1: htb default 30
sudo tc class replace dev ens33 parent 1: classid 1:3 htb rate 10mbit
sudo tc qdisc replace dev ens33 parent 1:3 handle 30: netem delay 200ms loss 10%
sudo tc filter replace dev ens33 protocol ip parent 1:0 prio 3 u32 \
  match ip dst 192.168.189.11/32 flowid 1:3
```

**验证**：
```bash
ping -c 10 192.168.189.11  # RTT ≈ 400ms（双向延迟），loss ≈ 10%
```

**量化触发条件**：
- Hadoop NameNode 日志中出现 "heartbeat timeout"
- MCP 拓扑中 `java → 192.168.189.11:9866` 边的心跳间隔 > 10s

#### 第三层：进程故障（master DataNode）

```bash
# 停掉 master 本地的 DataNode
hdfs --daemon stop datanode
pgrep -f DataNode | xargs kill -9 2>/dev/null  # 确保完全停止
```

**量化触发条件**：
- `hdfs dfsadmin -report` 显示 Live DataNodes 从 3 → 2
- MCP 拓扑中 `192.168.189.10:9866` 节点消失或连接归零

### 3.5 Phase 2 — Agent 诊断与根因定位

启动 Python agent daemon，订阅 MCP 异常事件，运行完整 LangGraph 工作流。

```bash
cd /home/sly/Downloads/xm/ebpfagent
export LLM_API_KEY=sk-7e257937b5984736b2bf1177901fde1d
export LLM_API_URL=https://api.deepseek.com/v1/chat/completions
export LLM_MODEL=deepseek-v4-flash
export PYTHONPATH=/home/sly/Downloads/xm/ebpfagent:$PYTHONPATH
~/.cache/pypoetry/virtualenvs/aetherops-qk5YUQrL-py3.12/bin/python \
  -m aetherops.main --daemon
```

**诊断流程**：
1. **Planner**（可选，默认关闭）：LLM 根据异常事件生成诊断计划（`ENABLE_PLANNER=1` 开启）
2. **Topology Analyst**：通过 MCP 获取当前拓扑，对比基线
3. **Causal Analyst**：PC 算法构建因果图（如有 Prometheus 指标）
4. **LLM Diagnostician**：综合拓扑 + 因果图进行根因分析（含 TTL 缓存 + prompt 压缩优化）
5. **Risk Assessor**：评估自愈风险等级
6. **Remediation Executor**：执行分级自愈

> **2026-07 架构简化**：Critic Agent 已移除（评审逻辑合并入 LLM Diagnostician 的结构化输出校验），Planner 默认关闭（`ENABLE_PLANNER=0`），直接使用硬编码 5 步默认计划。

**量化验证标准**：

| 指标 | 通过标准 |
|------|---------|
| 根因定位准确率 | 准确识别 DataNode offline + 网络劣化 + 资源过载 三层根因 |
| 端到端诊断耗时 | < 5s（从异常事件入队到生成诊断报告） |
| 受影响节点范围 | 准确标注 2 个 DataNode（master 离线 + slave0 延迟） |
| 异常 RPC 调用占比 | 准确计算 slave0 相关边调用占比 |
| LLM Diagnostician | 结构化 JSON 输出校验通过（root_cause/confidence/explanation 字段完整） |

### 3.6 Phase 3 — 分级自愈执行 + 二次巡检

基于风险分级（SRE 最佳实践），执行不同策略：

| 故障等级 | 故障类型 | 自愈策略 | 风险级别 |
|---------|---------|---------|---------|
| P0 | DataNode 进程终止 | Agent 自动执行 `hdfs --daemon start datanode` | LOW（幂等操作） |
| P1 | 网络延迟/丢包 | 生成处置建议，触发告警，不自愈 | MEDIUM |
| P1 | 资源过载 | 生成处置建议，触发告警，不自愈 | MEDIUM |

```python
# Agent 自愈执行器逻辑（核心决策）
if fault_type == "PROCESS_DOWN":
    # P0: 低风险，自动执行
    execute_remediation(target="DataNode", action="RESTART_SERVICE", force=True)
elif fault_type in ("NETWORK_DEGRADED", "RESOURCE_EXHAUSTED"):
    # P1: 中风险，生成建议 + 告警
    send_alert(fault_type, recommendation)
    # 不自愈，避免误操作放大故障
```

**自愈执行后 — 二次巡检**：

```bash
# 验证 DataNode 进程已恢复
pgrep -f DataNode && echo "DataNode 进程恢复"

# 验证 HDFS 拓扑恢复
hdfs dfsadmin -report | grep "Live datanodes"

# 验证副本完整性
hdfs fsck / -files -blocks

# 对比基线指标
diff /tmp/baseline-hdfs.txt <(hdfs dfsadmin -report)
```

**量化验证标准**：

| 指标 | 通过标准 |
|------|---------|
| DataNode 自愈响应时间 | 从诊断完成到进程拉起 < 10s |
| 拓扑恢复时间 | 自愈后 MCP 拓扑节点数恢复至基准值 < 10s |
| 块完整性 | 自愈后 HDFS 块丢失数 = 0 |
| 二次巡检通过率 | 基线与恢复后指标差异 < 5% |

### 3.7 Phase 4 — 多集群隔离验证

对应之前 Helm 多集群改造，验证爆炸半径分析不会跨集群误判。

```bash
# 在 master 启动一个带其他集群标签的 Nginx 容器
docker run -d --name cross-cluster-test -l cluster=other-cluster nginx:alpine

# 验证 Nginx 端口被 MCP 拓扑收录
python3 -c "
import asyncio
from aetherops.core.mcp_client import MCPClient
async def check():
    c = MCPClient('http://localhost:50052')
    await c.connect()
    topo = await c.get_topology()
    nginx_edges = [e for e in topo.edges if 'nginx' in e.src.lower()]
    print(f'nginx 相关边数量: {len(nginx_edges)}')
    # 验证爆炸半径不会包含 nginx
    report = await c.evaluate_remediation('192.168.189.10:9866', 'TC_DROP')
    cross_cluster = any('nginx' in s.lower() for s in report.affected_services)
    print(f'跨集群误判: {cross_cluster}')  # 应为 False
asyncio.run(check())
"
```

**量化验证标准**：

| 指标 | 通过标准 |
|------|---------|
| 故障隔离 | 爆炸半径分析不会包含其他集群的服务 |
| 标签识别 | Nginx 服务被正确标记为 `cluster=other-cluster` |
| 跨集群误判率 | 0%（不把 other-cluster 的服务算入 Hadoop 集群故障影响范围） |

### 3.8 Phase 5 — 清理恢复

```bash
# 恢复 DataNode
hdfs --daemon start datanode

# 清除 tc 规则
sudo tc qdisc del dev ens33 root 2>/dev/null || true
sudo tc qdisc del dev ifb0 root 2>/dev/null || true
sudo ip link delete ifb0 2>/dev/null || true

# 停止 Nginx
docker rm -f cross-cluster-test 2>/dev/null || true

# 验证集群完全恢复
hdfs dfsadmin -report | grep "Live datanodes"
```

---

## 4. 性能基线：LangGraph 工作流端到端耗时

### 4.1 基线测试结果（2026-07-07, 优化前）

第一次在 3 节点 Hadoop 集群上运行完整工作流，注入 tc 200ms delay + 10% loss → slave0，总耗时 **85s**。

```
Agent Trace (7 spans):

  [ok   ] supervisor                0.2ms  
  [ok   ] planner                   3.1ms  
  [ok   ] topology_analyst          0.6ms  
  [ok   ] causal_analyst         5220.1ms    ← PC 算法处理 1215 节点
  [ok   ] llm_diagnostician     30465.4ms    ← Multi-turn 3 轮串行 LLM
  [ok   ] critic                  11326.9ms   ← LLM 评审诊断报告
  [ok   ] risk_assessor             63.3ms  
  [ok   ] remediation_executor   34815.1ms    ← 固定 time.sleep(10) 等待
  ─────────────────────────────────────────
  TOTAL                       85000ms (85s)
```

**瓶颈定位**：

| 瓶颈 | 耗时 | 占比 | 根因 |
|------|------|------|------|
| llm_diagnostician | 30.5s | 36% | 3 轮串行 LLM 调用，平均每轮 ~10s |
| remediation_executor | 34.8s | 41% | 固定 `time.sleep(10)` 无退避 |
| critic | 11.3s | 13% | LLM 评审 + JSON 解析，auto-approve 仅用于 API 错误 |
| causal_analyst | 5.2s | 6% | PC 算法 O(n²) 在 1215 节点上 |

### 4.2 诊断结果

```
根因:       java->192.168.189.11:9866
置信度:     0.40
执行状态:   executed
Critic 通过: True
推荐动作:   [SCALE_UP] + [CONFIG_CHANGE]
风险评估:   level=RISK_LOW budget=0.0%
```

---

## 5. 性能优化实现与对比

> **注意**：以下测试数据采集于 2026-07-07 架构简化前。当前版本已移除 Critic Agent，Planner 默认关闭，
> 并实施了 LLM Token 优化（详见 `docs/llm-token-optimization.md`）。重诊断循环问题已随 Critic 移除而消除。

### 5.1 四项优化

| # | 优化项 | 文件 | 改动 | 目标 |
|---|--------|------|------|------|
| 1 | 因果图稀疏化 | `causal_analyst` + `causal_inference.py` | 仅保留异常节点指标列 + safety cap 50 变量 | 5.2s → <1s |
| 2 | Multi-turn 2 轮 | `multi_turn_diagnosis.py` | max_turns 3→2，首轮提供数据摘要 | 30.5s → 20s |
| 3 | Critic JSON 鲁棒解析 | `langgraph_workflow.py` | `_robust_json_extract()` 4 层降级 | 消除无谓 auto-approve |
| 4 | 恢复验证指数退避 | `_verify_recovery` | `time.sleep(10)` → 2s→3s→5s 轮询 | 34.8s → 25s |

### 5.2 优化后测试结果

**第 1 轮**（124.8s，Critic 触发重诊断）：

```
Agent Trace (8 spans):

  planner                  6757.7ms  
  topology_analyst           67.7ms  
  causal_analyst           4664.4ms    ← 稀疏化后仍~4.6s（PC 算法固有开销）
  llm_diagnostician       36683.5ms    ← 第 1 轮诊断（2 轮 LLM 调用）
  critic                  12956.9ms    ← 评审拒绝，触发 re-diagnosis
  llm_diagnostician       53893.9ms    ← 第 2 轮诊断（重诊断）
  risk_assessor              42.8ms  
  remediation_executor     9740.9ms    ← 退避轮询有效
  ─────────────────────────────────────
  TOTAL                       124.8s
```

**第 2 轮**（99.3s，同样触发重诊断）：

```
Agent Trace (8 spans):

  planner                  8437.1ms  
  topology_analyst           61.2ms  
  causal_analyst           2969.1ms  
  llm_diagnostician       35220.5ms  
  critic                  10988.7ms    ← 评审拒绝，触发 re-diagnosis
  llm_diagnostician       28901.5ms  
  risk_assessor               3.4ms  
  remediation_executor    12667.0ms  
  ─────────────────────────────────────
  TOTAL                        99.3s
```

### 5.3 对比分析

| 组件 | 优化前 | 优化后(第1轮) | 优化后(第2轮) | 变化 |
|------|--------|-------------|-------------|------|
| causal_analyst | 5.2s | 4.7s | **3.0s** | -43% |
| llm_diagnostician | 30.5s | 36.7s + 53.9s | 35.2s + 28.9s | **重诊断循环抵消优化** |
| critic | 11.3s | 13.0s | 11.0s | ≈ |
| remediation_executor | 34.8s | **9.7s** | **12.7s** | **-64%** |
| **总耗时** | **85s** | **124.8s** | **99.3s** | **↑ 重诊断导致劣化** |

### 5.4 失败分析：为什么总耗时反而增加了？

两次优化后运行都触发了 **Critic → Re-Diagnosis 循环**，这是根本原因：

1. **LLM 输出方差**：两次运行的首轮诊断置信度只有 0.20-0.40（低于 Critic 默认接受阈值）。并非代码问题，而是 LLM 响应在不同调用间存在自然波动。
2. **重诊断没有增量输入**：Critic 拒绝后，第二次诊断没有携带 Critic 的具体反馈作为上下文，只是"空跑"一次，纯靠 LLM 方差期望能蒙混过关。两次的置信度同样低，白白浪费 ~30s。
3. **评审通过阈值过松**：当前 Critic 对任何诊断都做开放式 LLM 评审，没有根据故障等级分层。Hadoop 单 DataNode 离线属于低风险简单故障，走全量 LLM 评审反而挑出格式性、描述性的微小瑕疵，导致不合理打回。

**结论**：确定性优化（稀疏化、退避轮询）有效，但 Critic Re-Diagnosis 循环的系统性问题覆盖了优化收益。

---

## 6. 三层深度优化方案（架构设计，待实现）

基于上述失败的深层原因分析，诊断循环存在三个设计缺陷，需要分层优化。

### 6.1 设计缺陷分析

```
缺陷 1: 评审没有分层
  所有故障都走 LLM 全量评审
  → 低风险简单故障（单 DataNode 离线）被无意义打回
  → 实际上只需要格式校验 + 置信度阈值检查

缺陷 2: 重诊断没有增量输入
  打回重诊断时，Critic 的具体问题没有传给诊断 Agent
  → 纯重复调用，只有方差、没有质量提升
  → 反复循环，白白浪费时间

缺陷 3: 缺少硬熔断
  线上自愈系统不允许无限循环重试
  → 故障本身就在恶化，诊断循环会错过最佳修复窗口
```

### 6.2 方案一：快速止血层（1 小时可落地）

不动 Prompt，纯架构规则调整，优先保证性能稳定可复现。

**硬限制循环次数**：
- 最多重诊断 1 次（`MAX_CRITIC_LOOPS=1`），二次仍不通过直接降级走规则兜底
- 输出首诊结果 + 告警提示，绝对禁止无限循环
- 面试话术：故障自愈系统的第一原则是"快"，而不是"完美"，必须有熔断降级机制

**Critic 分层评审**：

| 故障等级 | 示例 | 评审方式 | 预期耗时 |
|---------|------|---------|---------|
| LOW（单节点离线、轻度资源过载） | DataNode 进程终止 | 规则校验：格式检查 + 置信度≥0.7 + 根因在服务列表内 | 毫秒级 |
| MEDIUM（集群级延迟抖动） | 跨机架 RPC 超时 | LLM 评审（完整） | ~10s |
| HIGH（数据删除类操作） | 误执行 rm -rf | LLM 评审 + 人工审批 | ~10s + 人工 |

当前 Hadoop 单 DataNode 故障属于 LOW 等级，改完后 Critic 耗时从 11s→接近 0，也不会触发重诊断循环。

**基线测试开关**：保留 `MAX_CRITIC_LOOPS=0` 作为性能基准测试模式，用来验证确定性优化收益。

### 6.3 方案二：质量提升层（解决首诊通过率）

从根源减少被 Critic 打回的概率，让首轮诊断就能达标。

**诊断输出强结构化约束**：
- 用 Pydantic 强制限定输出字段（根因节点、故障类型、置信度、证据列表、修复建议）
- Critic 只做字段完整性、置信度阈值、证据匹配度的客观校验
- 不做开放式主观评审，消除 90% 的"描述不规范"式打回

**规则引擎前置兜底**：
- 新增已知故障规则库，Hadoop 常见故障（DataNode 离线、RPC 超时、磁盘满）做成规则匹配模式
- 匹配成功直接输出结果，置信度设为 0.95，完全跳过 LLM 诊断 + Critic
- 常见故障场景下，诊断耗时直接从 35s 降到毫秒级

```
诊断链路（双轨制）：
               异常事件
                  │
           ┌──────┴──────┐
           ▼              ▼
       规则匹配        LLM 诊断
       毫秒级           ~35s
           │              │
           └──────┬──────┘
                  ▼
             Critic 评审
                  │
                  ▼
             执行 + 验证
```

**Prompt 少样本优化**：
- 给诊断 Agent 加入 2-3 个 Hadoop 故障的标准诊断示例（Few-Shot）
- 明确输出格式和判断标准，首诊通过率提升 60%+

### 6.4 方案三：架构进阶层（面试拔高用）

**重诊断带增量反馈**：
- 打回重诊断时，携带 Critic 的具体修改意见（"补充网络拓扑异常证据""细化故障类型为进程终止"）
- 第二次诊断有明确优化方向，而非空跑

**置信度分级直通**：

| 首诊置信度 | 后续流程 |
|-----------|---------|
| ≥0.9 | 直接跳过 Critic 自动放行 |
| 0.7-0.9 | 走 LLM 评审 |
| <0.7 | 直接触发重诊断 + 补充数据 |

### 6.5 预期效果（分层性能指标）

| 故障类型 | 诊断链路 | 预期端到端耗时 |
|---------|---------|--------------|
| 已知常见故障（DataNode 离线） | 规则匹配 → 执行 → 验证 | **<15s** |
| 低风险未知故障 | LLM 诊断 → 规则校验 → 执行 → 验证 | **<25s** |
| 中高风险未知故障 | LLM 诊断 → LLM 评审 → 执行 → 验证 | **<50s** |

---

## 7. 面试要点

### 7.1 当被问到 "tc 延迟为什么不会被 eBPF 检测到"

> eBPF kprobe 挂载在 `tcp_sendmsg` 上，测量的是进程调用 send() 到数据拷贝到内核 socket buffer 的时间。tc netem 的延迟发生在 qdisc 层（数据从 buffer 出队之后），所以 kprobe 的测量点早于 tc 生效点。
>
> 但这不代表 tc 延迟是无效故障。在网络劣化条件下，Hadoop RPC 的心跳超时、TCP 重传率上升、连接持续时间延长等二级效应，可以被拓扑模块通过 MCP 采集到。在真正的运维场景中，网络故障的排查也是通过业务层面的异常信号（延迟飙升、超时比例增加）来反向推断的，而不是靠直接测量网络延迟。

### 7.2 当被问到 "为什么用三层故障而不是单一故障"

> 单一故障（比如只 kill DataNode）虽然能触发告警，但无法体现 AIOps 在复杂故障场景下的诊断优势。三层递进故障模拟的是真实生产环境中常见的级联效应：
>
> - 资源打满 → 网络处理变慢 → 心跳超时 → 节点被标记离线
>
> 如果 agent 只能检测最后一环（DataNode 挂了）而看不出前置的资源瓶颈和网络劣化，那跟简单的 ping 检测没有区别。三层故障验证的是 agent 的因果推断能力——能否在多个异常信号中找到真正的根因链条。

### 7.3 当被问到 "为什么 DataNode 自动重启但网络故障不自愈"

> 这是 SRE 的分级运维策略。DataNode 进程重启是幂等操作，在 HDFS 架构下短时重启不影响数据完整性，风险极低（LOW），适合全自动执行。但网络延迟和资源过载的修复（如调整 tc 规则、kill stress 进程）可能涉及网络策略变更或影响其他业务，属于 MEDIUM 风险，应该生成处置建议并由值班 SRE 确认后执行，避免自动化误操作扩大故障范围。

### 7.4 当被问到 "多集群隔离为什么重要"

> 在实际生产环境中，一个 Agent 实例可能管理多个业务集群。如果没有集群标签隔离，一次故障诊断的爆炸半径分析可能错误地将其他集群的健康服务纳入影响范围，导致不必要的告警和误操作。通过给服务打标并在 blast_radius 计算中按标签过滤，我们保证故障域只限定在当前集群内。

### 7.5 当被问到 "为什么优化后总耗时反而增加了"（历史记录，当前已通过移除 Critic 解决）

> 两次优化运行都触发了 Critic → Re-Diagnosis 循环。根源不是代码问题，而是三层设计缺陷：
>
> **第一，评审没有分层**。所有故障走统一 LLM 评审，单 DataNode 离线这种低风险故障也被 LLM 主观评审找出"描述不规范"之类的细节瑕疵，导致无意义打回。
>
> **第二，重诊断没有增量输入**。Critic 发现的问题没有作为上下文传给第二次诊断，空跑一遍纯靠 LLM 方差蒙混——这本质上是测试误差，不是质量提升。
>
> **第三，缺少熔断机制**。允许无限循环浪费了 50%+ 的端到端时间，而故障本身还在恶化。
>
> 确定性优化（因果稀疏化 -43%、恢复退避 -64%）效果是明确的。解决方向是将 Critic 改为分层评审：低风险故障走规则校验（毫秒级），中高风险才走 LLM 评审，并给重诊断携带增量反馈。

### 7.6 当被问到 "Critic 的评审为什么需要分层"（历史记录，Critic 已移除）

> 用 LLM 评审每份诊断报告就像让一个资深 SRE 审查每行代码——对于数据库架构变更这是必要的，但对于一个字段重命名也拉他来过就太浪费了。
>
> 分层评审的实质是"风险匹配"：
> - **低风险故障**（单节点离线、已知模式匹配）：规则校验即可，确认格式完整、置信度达标、根因在拓扑范围内，毫秒级通过
> - **中高风险故障**（集群级异常、复杂根因链）：才需要 LLM 做完整评审，此时 LLM 的领域知识有真正价值
>
> 这种设计既保障了速度（95% 的常见故障快速通过），又保留了质量（复杂场景有 LLM 兜底）。

### 7.7 当被问到"规则引擎 + LLM 双轨制怎么设计"（前瞻设计讨论）

> 双轨制的核心是：**规则处理确定性场景，LLM 处理不确定性场景**。
>
> 规则引擎维护一张故障模式表，每条规则包含匹配条件（如 topology 中 DataNode 节点数从 3→2、对应端口无心跳）和固定输出（根因、动作、置信度 0.95）。匹配成功直接输出，完全不经过 LLM。
>
> 规则匹配失败 → 说明是未知/复杂故障 → 才走 LLM 诊断。这样做有几个好处：
> 1. 常见故障的修复时间是确定的（毫秒级），不受 LLM 方差影响
> 2. LLM 只处理规则覆盖不到的场景，降低幻觉风险
> 3. 规则库可以持续从历史故障中提取，这是一个持续收敛的过程——规则越来越多，LLM 依赖越来越少

### 7.8 当被问到 "自愈系统的熔断设计应该怎么做"

> 自愈系统的熔断跟微服务熔断思路一致：防止二次伤害。
>
> 诊断层面的熔断：最多重诊断 N 次（N=1），超时直接降级输出 best-effort 结果 + 告警。绝对不能因为诊断循环错过最佳修复窗口。
>
> 执行层面的熔断：同一节点在冷却期内（120s）不重复执行自愈。如果一次修复没生效，说明问题可能更复杂，需要人工介入而非盲目重试。
>
> 系统层面的熔断：如果连续失败达到阈值（如 5 次诊断全部被 Critic 拒绝），整个诊断链路应该降级为"只告警不自愈"，等人工确认后再恢复。
>
> 核心原则：**自愈系统的第一优先级是"快"而非"完美"。诊断可以错过，但不能让故障恶化。**

---

## 8. 下一步优化方向（按优先级）

### P0 — Quick Wins（已完成）

- [x] **移除 Critic Agent**：评审逻辑合并入 LLM Diagnostician 结构化输出校验，消除重诊断循环
- [x] **Planner 可选化**：默认关闭（`ENABLE_PLANNER=0`），使用硬编码 5 步默认计划，节省 ~500 token/工作流
- [x] **LLM Token 优化**：System prompt 压缩、用户消息截断、max_tokens 4096→1024、client 端 TTL 缓存（详见 `docs/llm-token-optimization.md`）

### P1 — 质量提升（1 周内可落地）

- [ ] **规则引擎前置兜底**：Hadoop 常见故障（DataNode 离线、RPC 超时、磁盘满）做成规则匹配模式，毫秒级输出
- [ ] **诊断输出强结构化约束**：Pydantic Model 限定字段，Critic 做客观校验
- [ ] **Prompt Few-Shot 优化**：加入 2-3 个标准诊断示例

### P2 — 架构进化（2 周+ 设计验证）

- [ ] **重诊断带增量反馈**：Critic 的具体问题作为上下文注入第二次诊断
- [ ] **置信度分级直通**：≥0.9 跳过 Critic，0.7-0.9 走评审，<0.7 直接重诊断 + 补数据
- [ ] **分层性能指标**：按故障等级报告 MTTR（已知故障 <15s，低风险 <25s，中高风险 <50s）

### 学习点总结

```
优化不是单纯的代码改动，而是系统设计问题：
  
  之前的思路：改参数（max_turns 3→2）、加缓存（sparsify）
  真正的问题：架构层面的评审分层缺失、重诊断空跑、熔断缺位
  
  教训：在没有理解系统行为模式的情况下做微优化，
        可能会被高层级的设计缺陷完全抵消。
```

---

## 9. 文档历史

| 日期 | 版本 | 变更 |
|------|------|------|
| 2026-07-07 | v1 | 初版，基于 Hadoop 3 节点集群测试方案 |
| 2026-07-07 | v2 | 新增性能基线数据 (85s Optimization v1)、优化对比分析、三层优化方案设计、面试要点扩展 |
