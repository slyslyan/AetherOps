# MCP API 参考

## 协议概述

- **协议**: JSON-RPC 2.0 over Streamable HTTP
- **MCP 端点**: `POST/GET /mcp` — 单端点承载所有 JSON-RPC 消息;GET 建立长轮询会话,用于接收服务端通知
- **健康检查**: `GET /healthz` — 服务健康状态

### 客户端连接示例

```python
# Python (mcp 包)
from mcp import Client
from mcp.client.streamable_http import StreamableHttpTransport

transport = StreamableHttpTransport("http://127.0.0.1:50052/mcp")
client = Client(transport)
await client.initialize()

# 调用工具
result = await client.call_tool("get_topology", {"include_healthy": False})
# 读取资源
data = await client.read_resource("topology://current")
```

---

## 工具

### 1. get_topology

获取当前服务拓扑图（节点、边、异常分数）。

**参数**：

| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `include_healthy` | boolean | 否 | 是否包含零异常分数的边，默认 false |

**响应**：

```json
{
  "nodes": [
    {
      "id": "nginx-abc123",
      "avg_latency_ms": 45.2,
      "error_rate": 0.001,
      "call_count": 15234
    }
  ],
  "edges": [
    {
      "src": "nginx-abc123",
      "dst": "redis:6379",
      "call_count": 8234,
      "avg_latency_ms": 2.1,
      "ema_latency_ms": 2.3,
      "p95_latency_ms": 5.8,
      "anomaly_score": 12.5,
      "call_anomaly_score": 0.0,
      "protocol": "redis",
      "protocol_commands": {"GET": 5000, "SET": 3234},
      "recent_traces": [
        {
          "trace_id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
          "span_id": "1a2b3c4d5e6f7a8b",
          "trace_source": "w3c"
        }
      ]
    }
  ],
  "node_count": 3,
  "edge_count": 2,
  "timestamp_nano": 1720000000000000000
}
```

**边字段**：

| 字段 | 说明 |
|------|------|
| `anomaly_score` | 延迟 + 调用量 + 错误率综合分数 |
| `call_anomaly_score` | 独立的调用量异常分数 |
| `protocol` | 自动检测的协议类型 (http1/http2/mysql/redis) |
| `protocol_commands` | 协议命令计数 (如 Redis GET:100) |
| `recent_traces` | 最近 100 条关联的 TraceID/SpanID |

---

### 2. evaluate_remediation

评估自愈动作的爆炸半径和风险等级（不实际执行）。

**参数**：

| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `target_node` | string | 是 | 目标服务名或 IP:Port |
| `action` | enum | 是 | `TC_DROP`, `POD_RESTART`, `SCALE_UP`, `CONFIG_CHANGE`, `IMAGE_ROLLBACK` |

**响应**：

```json
{
  "target_node": "redis:6379",
  "action": "TC_DROP",
  "risk_level": "RISK_LOW",
  "affected_upstream": 3,
  "affected_downstream": 1,
  "affected_services": ["api-gateway", "user-svc", "order-svc"],
  "error_budget_pct": 12.5,
  "downtime_sec": 15,
  "recommendation": "Action TC_DROP on redis:6379 affects 3 upstream and 1 downstream services. Estimated error budget consumption: 12.5%. Low risk -- safe to auto-execute."
}
```

**风险等级**：

| 等级 | 条件 | 含义 |
|------|------|------|
| `RISK_LOW` | TC_DROP 且下游 ≤ 5，或 SCALE_UP | 可自动执行 |
| `RISK_MEDIUM` | TC_DROP 且下游 > 5，或 POD_RESTART 小范围 | 金丝雀执行 |
| `RISK_HIGH` | POD_RESTART 大范围，CONFIG_CHANGE, IMAGE_ROLLBACK | 需人工审批 |

---

### 3. execute_remediation

通过分级执行管线执行自愈动作。

**参数**：

| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `target_node` | string | 是 | 目标服务名或 IP:Port |
| `action` | enum | 是 | `TC_DROP`, `POD_RESTART`, `SCALE_UP`, `CONFIG_CHANGE`, `IMAGE_ROLLBACK` |
| `force` | boolean | 否 | 跳过风险检查强制执行，默认 false |

**响应**：

```json
{
  "accepted": true,
  "execution_id": "exec-redis:6379-1720000000",
  "status": "evaluated_only",
  "details": "Action TC_DROP on redis:6379 evaluated..."
}
```

**注意**：MCP 路径仅做爆炸半径评估。实际的 TC/k8s 操作需要在 Go 数据面进程内部执行（有 syscall 权限）。高风险且非强制时返回 `"status": "pending_approval"`。

---

### 4. check_policy

评估一个动作是否符合所有活跃策略规则。

**参数**：

| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `action` | enum | 是 | `TC_DROP`, `POD_RESTART`, `SCALE_UP`, `SCALE_DOWN`, `CONFIG_CHANGE`, `IMAGE_ROLLBACK` |
| `target_node` | string | 是 | 目标服务名 / IP:Port / Pod 名 |
| `target_ip` | string | 否 | 目标 IP |
| `namespace` | string | 否 | K8s namespace |

**响应**：

```json
{
  "allowed": false,
  "denied": true,
  "warned": false,
  "reasons": ["protect-monitoring: matched pattern (prometheus|grafana)"],
  "matched_by": ["protect-monitoring"]
}
```

---

### 5. list_policies

列出所有活跃策略规则。

**参数**：无

**响应**：

```json
{
  "policies": [
    {
      "id": "protect-monitoring",
      "description": "Never disrupt monitoring infrastructure",
      "effect": "deny",
      "priority": 100
    }
  ],
  "total": 4
}
```

---

## 资源

### topology://current

实时服务拓扑快照。

```python
# 读取
data = await client.read_resource("topology://current")
# content[0].text → JSON (结构与 get_topology 相同)
```

### topology://anomalies

近期异常事件（通过 Streamable HTTP GET 长轮询流推送）。

```
通知频道: notifications/events/anomaly
通知字段:
  - node_id: 异常节点 ID
  - anomaly_score: 异常分数
  - avg_latency_ms: 平均延迟
  - call_count: 调用量
  - suspect_chain: 嫌疑链 [上游, 中游, 下游]
  - timestamp_nano: Unix nano 时间戳
```

### policy://rules

活跃策略规则列表。

---

## 通知

MCP Server 通过 Streamable HTTP 的 GET 长轮询流向所有连接的客户端广播异常事件：

```json
{
  "jsonrpc": "2.0",
  "method": "notifications/events/anomaly",
  "params": {
    "node_id": "user-svc",
    "anomaly_score": 25.3,
    "avg_latency_ms": 523.1,
    "call_count": 12345,
    "suspect_chain": ["api-gateway", "user-svc", "mysql:3306"],
    "timestamp_nano": 1720000000000000000
  }
}
```

---

## 错误码

| HTTP 状态码 | 说明 |
|------------|------|
| 200 | 正常 |
| 400 | JSON-RPC 参数错误 (invalid arguments) |
| 404 | 未知工具名或资源 URI |
| 500 | 内部错误 (recovery handler 捕获) |

---

## MCP 客户端示例

```python
# 完整的工作流示例
import asyncio
from mcp import Client
from mcp.client.streamable_http import StreamableHttpTransport

async def diagnose_anomaly():
    transport = StreamableHttpTransport("http://localhost:50052/mcp")
    client = Client(transport)

    # 1. 获取拓扑
    topo = await client.call_tool("get_topology", {"include_healthy": False})
    print(f"Nodes: {topo['node_count']}, Edges: {topo['edge_count']}")

    # 2. 找到最高异常分数的边
    edges = sorted(topo["edges"], key=lambda e: e["anomaly_score"], reverse=True)
    if edges:
        suspect = edges[0]["dst"]
        print(f"Top suspect: {suspect}, score: {edges[0]['anomaly_score']}")

        # 3. 评估自愈
        eval_result = await client.call_tool("evaluate_remediation", {
            "target_node": suspect,
            "action": "TC_DROP"
        })
        print(f"Risk: {eval_result['risk_level']}")
        print(f"Recommendation: {eval_result['recommendation']}")

        # 4. 检查策略
        policy = await client.call_tool("check_policy", {
            "action": "TC_DROP",
            "target_node": suspect
        })
        if policy["allowed"]:
            # 5. 执行
            exec_result = await client.call_tool("execute_remediation", {
                "target_node": suspect,
                "action": "TC_DROP"
            })
            print(f"Result: {exec_result['status']}")

asyncio.run(diagnose_anomaly())
```
