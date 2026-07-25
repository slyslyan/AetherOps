# 配置参考

## 环境变量

所有配置通过环境变量覆盖，前缀 `CFG_`。配置加载入口：`internal/config/config.go → LoadFromEnv()`。

### 分析参数

| 变量 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `CFG_P95_MULTIPLIER` | float64 | 1.2 | 异常延迟阈值 = 当前 P95 × 此倍数。值越大越不敏感 |
| `CFG_MIN_LAT_MS` | float64 | 10 | 最小延迟阈值 (ms)。低于此值的延迟不参与异常评分 |
| `CFG_CALL_QPS_THRESHOLD` | float64 | 0 (禁用) | 调用量 QPS 基线最小值。低于此值的边不触发 QPS 异常 |
| `CFG_CALL_QPS_DROP_RATIO` | float64 | 0.3 | QPS 降至当前 EMA 的此比例时触发调用量异常 |
| `CFG_CALL_ANOMALY_WEIGHT` | float64 | 2.0 | 调用量异常在综合分数中的权重 |
| `CFG_ANALYSIS_WINDOW_SEC` | float64 | 15 | QPS 计算的时间窗口 (秒) |
| `CFG_HISTORY_MIN_SIM` | float64 | 0.6 | Jaccard 相似度阈值，用于历史故障匹配 |
| `CFG_HISTORY_EXPIRE_MIN` | float64 | 10 | 历史指纹过期时间 (分钟) |

### 自愈参数

| 变量 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `CFG_MITIGATION_COOLDOWN_SEC` | float64 | 120 | 同一节点的自愈冷却时间 (秒) |
| `CFG_PROFILE_DURATION` | int | 10 | pprof 火焰图采集时长 (秒) |
| `CFG_MAX_SUSPECTS` | int | 5 | 根因分析返回的最大嫌疑节点数 |
| `CFG_TC_DROP_TTL` | int | 5 | TC drop 规则自动过期时间 (分钟) |

### 调度参数

| 变量 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `CFG_PRINT_INTERVAL` | int | 10 | 拓扑打印到标准输出的间隔 (秒) |
| `CFG_ANALYSIS_INTERVAL` | int | 15 | 异常检测 + 根因分析间隔 (秒) |

### 网络地址

| 变量 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `CFG_METRICS_ADDR` | string | :2112 | Prometheus 指标 HTTP 监听地址 |
| `AETHEROPS_METRICS_PORT` | string | (空) | 替代 `CFG_METRICS_ADDR`，仅设置端口号 |
| `CFG_MCP_ADDR` | string | :50052 | MCP JSON-RPC HTTP 监听地址 |

### eBPF 探针

| 变量 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `CFG_HTTP_PROBE_TARGET` | string | /proc/self/exe | uprobe 挂载目标二进制路径 |
| `EBPF_IFACE` | string | ens33 | 网络接口名（TC 丢包使用） |

### 自适应采样

| 变量 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `CFG_ADAPTIVE_SAMPLING_THRESHOLD` | float64 | 5.0 | 触发高频采样的异常分数阈值 |
| `CFG_NORMAL_SAMPLING_NS` | int (ns) | 100000000 (100ms) | 正常模式 eBPF 采样间隔 |
| `CFG_ADAPTIVE_SAMPLING_NS` | int (ns) | 10000000 (10ms) | 异常模式 eBPF 采样间隔 |

### 安全开关

| 变量 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `DRY_RUN` | bool | false | 影子模式：诊断+决策但不执行自愈。`1`/`true`/`yes` 开启 |

### 其他环境变量

| 变量 | 说明 |
|------|------|
| `POLICY_FILE` | OPA 风格策略 JSON 文件路径。为空则使用默认宽松策略 |
| `AETHEROPS_OUTPUT_DIR` | 火焰图/pcap 输出目录。默认 `~/.aetherops/output` |
| `FEISHU_WEBHOOK` | 飞书机器人 Webhook URL。为空则不发送告警 |
| `SIMULATE_LATENCY` | 模拟延迟模式 (仅开发用)。设置后生成随机延迟数据 |
| `LLM_PROVIDER` | LLM 提供商 (deepseek/anthropic/ollama) |
| `LLM_API_KEY` | LLM API 密钥 |

---

## 策略文件格式

策略文件是 JSON 数组，每条策略含条件和效果：

```json
[
  {
    "id": "policy-name",
    "description": "策略说明",
    "effect": "deny",
    "conditions": {
      "actions": ["TC_DROP", "POD_RESTART"],
      "match_pattern": "(prometheus|grafana)",
      "max_replicas_percent": 10,
      "block_time_ranges": ["10:00-16:00"],
      "block_days": ["Monday", "Tuesday"]
    },
    "priority": 100
  }
]
```

**字段说明**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string | 唯一标识符 |
| `description` | string | 人类可读说明 |
| `effect` | string | `deny` (拒绝) 或 `warn` (警告但允许) |
| `conditions.actions` | []string | 适用的自愈动作类型 |
| `conditions.match_pattern` | string | 目标节点名正则匹配 |
| `conditions.max_replicas_percent` | int | 最大副本变更百分比 |
| `conditions.max_replicas` | int | 最大副本数上限 |
| `conditions.block_time_ranges` | []string | 禁止执行的时间段 |
| `conditions.block_days` | []string | 禁止执行的星期 |
| `priority` | int | 优先级 (越大越优先) |

**自愈动作类型**：

| 动作 | 说明 | 可逆性 |
|------|------|--------|
| `TC_DROP` | TC 丢包熔断 | 可逆 (秒级恢复) |
| `POD_RESTART` | 重启 Pod | 不可逆 |
| `SCALE_UP` | 扩容 | 可逆 |
| `SCALE_DOWN` | 缩容 | 不可逆 |
| `CONFIG_CHANGE` | 配置变更 | 不可逆 (通常) |
| `IMAGE_ROLLBACK` | 镜像回滚 | 不可逆 |

---

## Prometheus 指标

### 业务指标

| 指标名 | 类型 | 标签 | 说明 |
|--------|------|------|------|
| `ebpf_edge_latency_ms` | Histogram | src, dst | 服务间调用延迟 |
| `ebpf_edge_calls_total` | Counter | src, dst | 服务间调用数 |
| `ebpf_edge_errors_total` | Counter | src, dst | 服务间错误调用数 |
| `ebpf_edge_anomaly_score` | Gauge | src, dst | 边的异常分数 |
| `ebpf_node_avg_latency_ms` | Gauge | node | 节点平均入向延迟 |
| `ebpf_root_cause_score` | Gauge | node | 根因嫌疑分数 |
| `ebpf_mitigation_total` | Counter | node, action | 自愈执行次数 |
| `ebpf_http_requests_total` | Counter | method, status | HTTP 请求数 |
| `ebpf_http_request_duration_ms` | Histogram | method, status | HTTP 请求耗时 |
| `ebpf_redis_commands_total` | Counter | command | Redis 命令执行数 |

### 自监控指标

| 指标名 | 类型 | 标签 | 说明 |
|--------|------|------|------|
| `ebpf_agent_events_total` | Counter | — | 处理的 eBPF 事件总数 |
| `ebpf_agent_errors_total` | Counter | — | 处理过程中的错误总数 |
| `ebpf_agent_up` | Gauge | — | Agent 运行状态 (1/0) |
| `ebpf_ringbuf_events_total` | Counter | buffer | 各 Ring Buffer 事件量 |
| `ebpf_ringbuf_dropped_total` | Counter | buffer | Ring Buffer 丢事件数 |
| `ebpf_ringbuf_read_errors_total` | Counter | buffer | Ring Buffer 读取错误数 |
| `ebpf_decision_latency_ms` | Histogram | — | 事件到决策端到端延迟 |
| `ebpf_mcp_connections` | Gauge | — | MCP 活跃连接数 |
| `ebpf_mcp_tool_calls_total` | Counter | tool | MCP 工具调用量 |
| `ebpf_events_per_second` | Gauge | — | eBPF 事件吞吐率 |
| `ebpf_agent_health` | Gauge | component | 组件健康状态 (1/0) |

**component 标签值**：`tcp_sendmsg_probe`, `tcp_connect_probe`, `tcp_rtt_probe`, `redis_probe`, `proto_classifier_probe`, `trace_context_probe`, `mcp_server`, `http_server`

### Grafana 集成

```bash
# config/prometheus.yml 已预配置抓取目标
scrape_configs:
  - job_name: 'ebpf-agent'
    static_configs:
      - targets: ['localhost:2112']
```

Grafana 数据源配置在 `config/grafana/provisioning/datasources/prometheus.yml`。
