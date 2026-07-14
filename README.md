# AetherOps — eBPF + AI Multi-Agent + K8s 自愈

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go" alt="Go Version">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?logo=python" alt="Python Version">
  <img src="https://img.shields.io/badge/eBPF-Kernel%205.8+-orange?logo=linux" alt="eBPF Support">
</p>

**eBPF 采集 → AI Agent 分析 → K8s 自愈** — 基于 eBPF 内核探针的智能运维系统。Go 数据面在内核层零侵入采集 TCP 通信构建实时拓扑，Python 认知面的多 Agent 工作流（Supervisor + 5 Expert Agents）分析故障根因并执行分级自愈。

## 三句话架构

```
eBPF kprobe → Ring Buffer → ServiceGraph → 异常检测         [Go 数据面]
                                                    ↓ MCP 协议
Supervisor → Expert Agents → LLM Diagnosis → 分级自愈    [Python 认知面]
                                                    ↓
                                             K8s 自愈 + 恢复验证
```

### Go 数据面
eBPF kprobe 捕获所有 TCP 通信，构建实时服务拓扑图。滑动窗口 P95 + EMA 自适应基线计算异常评分，反向随机游走定位级联故障根因。内置 TC 丢包熔断、Pod 重启等内核级自愈能力。

### Python 认知面
Supervisor 驱动的多 Agent 工作流：Topology/Causal Analyst 准备数据 → LLM Diagnostician 根因诊断 → Risk Assessor 爆炸半径评估 → Remediation Executor 分级执行 + 恢复验证。LOW 风险自动执行，HIGH 风险等待人工审批。

## 快速启动

```bash
# Go 数据面（需 Linux 5.8+，eBPF 环境）
go generate ./cmd/tracer/...
go build -o ebpf-local ./cmd/tracer/
sudo SIMULATE_LATENCY=1 ./ebpf-local

# Python 认知面（另一终端）
cd aetherops
pip install --break-system-packages -e .
python -m aetherops.demo           # 交互式 demo
python -m aetherops.main --workflow # 单次工作流
```

## 项目结构

```
bpf/                     # eBPF C 探针（kprobe/tcp_sendmsg, TC drop, etc.）
cmd/tracer/              # Go 入口：组装 App → Start → MainLoop → Shutdown
internal/                # Go 内部包（graph/analysis/mitigation/mcp/blastradius/…）
aetherops/               # Python 认知面
├── main.py              # 守护进程：SSE 订阅异常 → 触发工作流
├── demo.py              # 3 分钟面试演示脚本
├── core/                # 核心模块
│   ├── mcp_client.py    # MCP 客户端（JSON-RPC 2.0 over SSE）
│   ├── llm_provider.py  # LLM 抽象层（DeepSeek/OpenAI/Anthropic/Ollama）
│   ├── llm_diagnosis.py # 单轮 LLM 诊断 + 启发式回退
│   ├── risk_client.py   # 风险评估客户端
│   └── feedback.py      # 审批流（LOW auto / MEDIUM confirm / HIGH pending）
└── workflows/
    └── workflow.py      # Supervisor + 5 Expert Agents 工作流引擎
```

## 分级自愈

| 风险 | 条件 | 执行 |
|------|------|------|
| LOW | 小范围、错误预算充足 | 自动执行 |
| MEDIUM | 影响有限 | 通知 SRE，60s 无拒绝则执行 |
| HIGH | 多服务影响 | 只告警，需人工审批 |

## License

GPL v3.0
