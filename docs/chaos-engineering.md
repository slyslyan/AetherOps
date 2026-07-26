# eBPF-AutoHeal 混沌工程文档

## 1. 方案背景

### 现存问题

1. **双 Agent 运行**：服务器（150.158.113.146）上 `ebpf-oj-monitor`（旧）和 `tracer`（新）两个 eBPF agent 同时运行，存在 kprobe 重复挂载和指标冲突风险
2. **缺少自动化验证**：旧 `scripts/run-chaos.sh` 仅注入故障 + sleep + 提示手动检查，无自动断言和报告
3. **无闭环**：故障注入后需人工通过 `journalctl`/`curl metrics | grep` 验证，依赖经验判断

### 解决方案

构建自动化混沌工程系统：**故障注入 → 指标采集 → 基线对比断言 → 幂等清理 → 稳态恢复 → 报告生成**

## 2. 总体架构

```
runner.sh (主编排器)
  ├── config.sh          # 全局配置: SSH目标、时间窗口、阈值、风险开关
  ├── server-cleanup.sh  # 一次性: 停旧 agent、校验 kprobe、导出基线
  ├── lib/
  │   ├── common.sh      # 颜色日志、浮点比较、时间工具
  │   ├── ssh-exec.sh    # exec_ssh / exec_sudo 远程执行封装
  │   ├── metrics.sh     # Prometheus 指标查询 + 断言库 (基线对比)
  │   ├── inject.sh      # 故障注入原语 (tc/iptables/stress-ng，幂等)
  │   ├── cleanup.sh     # 故障清理原语 (幂等，先删后加) + 残留校验
  │   └── report.sh      # JSON + Markdown 报告生成
  ├── experiments/       # 6 个实验脚本，每个实现统一模板
  ├── fixtures/          # 基线指标、PromQL 查询模板
  └── reports/           # 自动生成的报告 (gitignored)
```

## 3. 实验矩阵

| # | 风险 | 实验 | 注入方式 | 预期 eBPF 信号 | 关键断言 | 状态 |
|---|------|------|---------|---------------|---------|---------|
| 01 | 低 | 网络延迟 | tc netem 200ms | anomaly_score 升高 (tcp_conntrack RTT) | 3+ 边异常, root_cause 识别 | **已验证** (max=21.83, 10 边触发) |
| 02 | 高 | TCP 拒绝 | iptables REJECT tcp/3306 | 无 (netfilter 早于 kprobe) | agent 容忍 + 清理恢复 | 已验证 (已知盲点) |
| 04 | 低 | CPU 打满 | stress-ng --cpu 2 | 全局 P95 升高, 错误率 < 1% | 多边异常, 错误率不涨 | 已验证 (dd loop 强度不足) |
| 05 | 中 | DNS 失败 | iptables DROP udp/53 | QPS 下降 (callAnomaly) | 异常检测 [预期盲点] | 已验证 (UDP 盲点确认) |

### 风险等级说明

- **Low**: 仅影响网络延迟/资源使用率，不篡改业务流量，不模拟服务中断
- **Medium**: 可能阻断特定协议，但已知盲点，预期结果明确
- **High**: 涉及 iptables DNAT 劫持或服务端口拒绝，异常残留会造成业务影响

## 4. 实验执行生命周期

每个实验按以下 9 个阶段执行：

```
1. pre_check()      → 稳态校验 + 无残留规则 + 基线采集
2. snapshot(pre)    → 保存故障前指标到 reports/<run_id>/snapshots/
3. inject()         → 注入故障 (幂等: 先删后加)
4. sleep DETECT_WAIT_SEC → 等待 3x AnalysisInterval + scrape 余量
5. collect_metrics()→ 生成测试流量、采集故障期指标
6. snapshot(during) → 保存故障期指标
7. verify()         → 执行全部断言 (基线对比)
8. cleanup()        → 幂等清除故障
9. sleep RECOVER_WAIT_SEC → 等待 cooldown + 分析周期
10. snapshot(post)  → 保存恢复后指标
11. post_check()    → assert_anomaly_cleared + 稳态校验 + 业务熔断
```

### 时间窗口配置

| 参数 | 值 | 说明 |
|------|-----|------|
| ANALYSIS_INTERVAL | 17s | 对齐服务器 CFG_ANALYSIS_INTERVAL |
| DETECT_WAIT_SEC | 51s | 3x Interval + Prometheus scrape (15s) 双重余量 |
| RECOVER_WAIT_SEC | 180s | cooldown (10s) + P95 窗口 (30 样本) 滚动 + 多个分析周期 + 安全余量 |

## 5. 断言库

所有断言基于**基线对比**（`during_value vs pre_value`）而非硬编码阈值。

| 函数 | 说明 | 严重级别 |
|------|------|---------|
| `assert_anomaly_detected <n> <delta>` | 至少 n 条边 anomaly_score > baseline + delta | CRITICAL |
| `assert_errors_increased <filter>` | errors_total 高于基线 | CRITICAL |
| `assert_http_status_seen <code>` | 指定 HTTP 状态码被 uprobe 观测 | CRITICAL |
| `assert_root_cause_identified <pattern>` | root_cause_score 中有预期节点 | INFO |
| `assert_mitigation_attempted` | mitigation_total > 基线 | INFO |
| `assert_anomaly_cleared` | anomaly_score_max <= max(baseline, 0.01) | CRITICAL |
| `assert_agent_healthy` | agent_up==1, 错误增量 <= 5 | INFO |
| `assert_steady_state` | 全面稳态校验 (agent/latency/errors/iptables/tc/K3s/JudgeX) | CRITICAL |

## 6. 安全护栏

### 6.1 eBPF Agent 内置保护

| 保护层 | 机制 | 效果 |
|--------|------|------|
| 策略引擎 | `protect-critical-data-services` 规则 | 阻止对 mysql/redis 的 TC_DROP/POD_RESTART |
| 爆炸半径 | >10 服务拒绝, >20 上报人工 | 控制影响范围 |
| 锁断 | 10 分钟 3 次触发 → 锁定 30 分钟 | 防止反复触发 |
| 冷却 | 同一节点 120s 冷却 | 避免重复执行 |

### 6.2 混沌脚本保护

| 机制 | 说明 |
|------|------|
| flock 排他锁 | `/tmp/chaos-runner.lock`，防止并发执行 |
| 全局超时 30 分钟 | 超时自动触发 emergency cleanup |
| --dry-run 模式 | 只打印指令不执行，用于预校验 |
| 风险分级开关 | `--skip-high-risk` / `--enable-low-risk` 独立控制 |
| 业务熔断护栏 | 每轮实验后检查 JudgeX /health + /ready，连续 3 次失败中止 |
| trap 清理 | EXIT/INT/TERM 信号触发全局故障清除 |
| 幂等注入 | iptables: 先 `-D` 再 `-A`; tc: 先 `del` 再 `add` |

### 6.3 紧急止损

```bash
# 仅清理所有故障注入
bash chaos/runner.sh --cleanup-only
```

## 7. 执行命令

```bash
# 前置：服务器清理
bash chaos/server-cleanup.sh           # 停旧 agent + 导出基线
bash chaos/server-cleanup.sh --verify  # 仅验证不修改

# 混沌实验
bash chaos/runner.sh --dry-run         # 干运行，预校验脚本逻辑
bash chaos/runner.sh --enable-low-risk # 仅低风险实验 (01/04/06)
bash chaos/runner.sh --skip-high-risk  # 跳过高风险实验 (02/03/05)
bash chaos/runner.sh --exp 01          # 单实验
bash chaos/runner.sh --exp 01,04,06   # 多实验
bash chaos/runner.sh                   # 全部 6 个实验
bash chaos/runner.sh --cleanup-only    # 紧急清理
```

## 8. 报告格式

每次运行生成到 `chaos/reports/<run-id>/`:

- `chaos-report.json` — 结构化数据（summary, experiments[], assertions[], metrics_snapshot）
- `chaos-report.md` — 可读报告（结果表格、警告列表、已知限制）
- `snapshots/` — 每个实验的 pre/during/post 原始 Prometheus 指标

### JSON 关键字段

```json
{
  "run_id": "chaos-20260726-143022",
  "summary": { "total": 6, "passed": 5, "failed": 0, "skipped": 1 },
  "experiments": [{
    "id": "01",
    "status": "PASS",
    "metrics_snapshot": {
      "pre":  { "anomaly_score_max": 0,   "errors_total": 5 },
      "during": { "anomaly_score_max": 2.45, "errors_total": 8 },
      "post":  { "anomaly_score_max": 0 }
    }
  }]
}
```

## 9. 已知局限清单

| 局限 | 影响实验 | 说明 |
|------|---------|------|
| DNS UDP 不可观测 | 05 | eBPF 不观测 UDP DNS 应答，仅能通过上层 TCP QPS 下降间接检测 |
| MySQL SSL 盲区 | 02 | 加密连接时 eBPF 无法解析应用层协议内容 |
| Prometheus scrape 间隔 | 全部 | 默认假设 15s scrape_interval，环境变更须同步调整 DETECT_WAIT_SEC |
| tcp_sendmsg 测内核缓冲 | 全部 | kprobe 测量内核缓冲拷贝时间 (~μs)，不受网络延迟影响。已通过 tcp_conntrack+tcp_rtt 独立 RTT 统计解决 |
| iptables vs kprobe 层级 | 02 | iptables REJECT 在 netfilter 层发生，早于 TCP 栈，kprobe 无法观测 |
| tcp_rtt 需长连接 | 01, 06 | `kretprobe/tcp_recvmsg` 需请求-响应对，短连接场景用 tcp_conntrack 替代 |
| anomaly_cleared 恢复 | 全部 | P95 窗口 30 样本滚动需时间，120s 恢复等待可能不足 |

### 混沌实验实测发现 (2026-07-26 第二轮)

| 发现 | 严重度 | 说明 |
|------|--------|------|
| anomaly_score 成功触发 | **突破** | 将 tcp_conntrack (连接级 RTT) 从 tcp_sendmsg 统计中独立后，200ms tc netem 触发 10 条边 anomaly_score > 0，max=21.83 |
| 数据源选择是关键 | CRITICAL | `tcp_sendmsg` 测量内核缓冲拷贝 (~μs)，不受 tc netem 影响。`tcp_conntrack` 测量连接时长 (~ms)，包含网络延迟。分离统计后异常检测立即生效 |
| MinLatThresholdMs 降低无效 | INFO | 从 10ms 降到 0.5ms 对 anomaly_score 无影响，确认问题在测量层而非阈值层 |
| tcp_rtt 暂无数据 | INFO | `kretprobe/tcp_recvmsg` 需要长连接请求-响应对，业务流量积累后自然出现 |
| anomaly_cleared 恢复时间 | LOW | P95 窗口 (30 样本) 滚动需要时间，120s 恢复等待可能不足以让分数归零 |

## 10. 执行路线

### Stage A: 快速验证（低风险先行）

```bash
bash chaos/server-cleanup.sh              # 1. 服务器收编
bash chaos/runner.sh --dry-run            # 2. 脚本预校验
bash chaos/runner.sh --enable-low-risk    # 3. 跑低风险: 01+04
```

### Stage B: 全量上线

```bash
bash chaos/runner.sh                      # 全量 4 实验, 约 15 分钟
```

---

*最后更新: 2026-07-26 (混沌实验完成，含实测发现)*
