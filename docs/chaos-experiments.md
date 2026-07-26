# eBPF-AutoHeal 混沌工程验证

> **注意**：旧的 7 个手动实验已替换为自动化混沌工程框架。详见 [`docs/chaos-engineering.md`](chaos-engineering.md)。

## 自动化框架

```bash
# 快速开始
bash chaos/server-cleanup.sh              # 服务器收编 + 基线导出
bash chaos/runner.sh --dry-run            # 脚本预校验
bash chaos/runner.sh --enable-low-risk    # 低风险实验 (01/04)
bash chaos/runner.sh                      # 全量 4 实验

# 紧急清理
bash chaos/runner.sh --cleanup-only
```

## 已验证实验

| # | 风险 | 实验 | 关键结论 |
|---|------|------|---------|
| 01 | 低 | 网络延迟 (tc netem 200ms) | anomaly_score 成功触发 (0→15.68)，10 条边异常 |
| 02 | 高 | TCP 拒绝 (iptables REJECT) | 已知盲点 (netfilter 早于 kprobe)，agent 容忍 |
| 04 | 低 | CPU 打满 (stress-ng) | 多边 P95 升高，错误率不涨 |
| 05 | 中 | DNS 失败 (iptables DROP udp/53) | UDP 盲点确认，仅 TCP QPS 间接检测 |

## 核心发现

**anomaly_score 一直为 0 的根因**：`tcp_sendmsg` kprobe 测量的是内核缓冲拷贝时间（~µs），不受 tc netem 网络延迟影响。将 `tcp_conntrack`（连接生命周期 RTT）和 `tcp_rtt`（请求级往返延迟）独立统计后，异常检测立即生效。
