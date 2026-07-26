# Changelog

## [1.1.0] — 2026-07-26

### 新增
- **RTT 双源异常检测**：`latRatio = max(sendmsgLatRatio, rttLatRatio)`，网络级故障由 `tcp_conntrack`/`tcp_rtt` 驱动检测
- **ServiceEdge 独立 RTT 统计**：RttCount, RttAvgLat, RttP95, RttBaselineP95，与 sendmsg 统计分离
- **latency_source 标签**：`ebpf_edge_latency_ms` 直方图新增 `tcp_sendmsg`/`tcp_rtt`/`tcp_conntrack` 标签
- **混沌工程自动化框架**：`chaos/` 目录，含 4 个实验、主编排器、断言库、安全护栏、JSON/Markdown 报告

### 修复
- **anomaly_score 始终为 0**：根因是 `tcp_sendmsg` 测量内核缓冲拷贝（~µs），不受 tc netem 影响。将 `tcp_conntrack` RTT 数据独立统计后立即生效

### 验证
- 混沌实验 01（tc netem 200ms）：anomaly_score 0→15.68（11 条边触发），latency_increased 10/75 条边

## [1.0.0] — 2026-07-25

### 新增
- **8 个 eBPF 探针**：tracer (TCP)、tcp_conntrack (连接生命周期)、tcp_rtt (请求级 RTT)、tc_drop (丢包熔断)、http_probe (HTTP uprobe)、redis_trace (Redis 协议)、proto_classifier (协议自动发现)、trace_context (W3C/Jaeger/Datadog TraceID 提取)
- **ServiceGraph**：滑动窗口 P95 + EMA 基线 + 双峰流量门控
- **三维异常检测**：延迟异常 (P95 偏离度) + 调用量异常 (QPS 突变) + 错误率
- **反向随机游走根因分析**：沿拓扑反向传播异常分数，故障聚类
- **5 条本地专家规则**：cpu-throttle, conn-pool-exhaustion, network-partition, cascading-failure, retry-storm
- **Go 本地降级链**：LLM 诊断 → 专家规则 → 启发式 → "unknown"
- **分级自愈引擎**：TC_DROP (可逆, 自动) / POD_RESTART (金丝雀) / CONFIG_CHANGE (人工审批)
- **自愈安全层**：金丝雀执行、爆炸半径门控 (影响 >20 服务拒绝)、频繁锁定 (10 分钟内 3 次)
- **策略引擎**：OPA 风格 JSON 策略文件，支持 deny/warn、时间窗口、正则匹配
- **自适应采样**：异常时自动从 100ms 降至 10ms eBPF 采样间隔
- **19 个 Prometheus 指标**：业务指标 (edge_latency, anomaly_score, root_cause_score) + 自监控 (ringbuf_events, decision_latency, component_health)
- **结构化审计日志**：AuditEntry 含动作/目标/评分/策略/专家规则/金丝雀结果/MTTR
- **MCP 服务**：5 个工具 (get_topology, evaluate_remediation, execute_remediation, check_policy, list_policies) + 3 个资源 (topology://current, topology://anomalies, policy://rules)
- **K8s 部署**：DaemonSet + Helm Chart + 安装脚本
- **非 K8s 部署**：systemd 服务 + install.sh
- **混沌工程框架**：4 个自动化实验 + 主编排器 + 断言库 + 安全护栏 + JSON/Markdown 报告
- **完整文档**：README, 架构, eBPF 探针, 配置, 部署, MCP API, 开发指南

### 技术栈
- Go 1.24 + cilium/ebpf + mark3labs/mcp-go + Prometheus client_golang
- Python 3.11 + httpx + mcp + OpenAI 协议兼容 (DeepSeek/Anthropic/Ollama)
- eBPF CO-RE + kprobe/kretprobe/uprobe/TC clsact + Ring Buffer
- Protobuf (proto/gen/)
- K8s + Helm + Docker

### 已知限制
- HTTP/2 完整帧解析因 HPACK 状态机无法通过 BPF verifier，降级为 connection preface 检测
- MySQL 协议仅做二进制包头启发式分类 (端口 3306)，不解 SQL 文本和 SSL
- uprobe HTTP 探针按需挂载 60s 后自动卸载，不持续采集
- 无 CPU profiler eBPF 集成（使用 pprof HTTP 端点替代）

### 待完成
- MySQL 完整命令解析 (可选)
- gRPC streaming 延迟测量
- HTTP/2 HPACK 解码 (需 BPF verifier 突破 或用户态辅助)
- 分布式追踪上下文关联到具体 Span (当前仅提取 TraceID/SpanID)
