# LLM Token 成本优化

## 问题

端到端测试期间，DeepSeek API 累计消耗 **580 万输入 token**，主要原因是每次工作流调用 LLM 时，系统 prompt 和用户消息都未加限制地膨胀，且**同一故障周期内存在大量冗余调用**。

每次工作流有 **2 次 LLM 调用**：

| 调用 | 位置 | 用途 |
|---|---|---|
| Planner | `workflows/workflow.py:_call_llm_for_plan` | 根据异常事件生成诊断计划 |
| Diagnostician | `llm_diagnosis.py:diagnose` | 分析因果图 + 拓扑，输出根因报告 |

## 根因分析

### 1. 用户消息无截断

`_build_diagnosis_prompt` 将完整的因果图和拓扑快照 dump 成 JSON 发给 LLM。测试时连到本地 312 节点的拓扑（Chrome 进程、系统服务等），全量序列化后一次消息可达 5000-8000 token。

### 2. system prompt 臃肿

`DIAGNOSIS_SYSTEM_PROMPT` 包含 5 个详细故障模式（每个 4 行症状 + 因果签名 + 推荐动作 + 指标）和完整的风险指南，~2500 字符。`PLANNER_SYSTEM_PROMPT` 也有 ~700 字符。

### 3. max_tokens 过大

三个 provider 的 `diagnose()` 都硬编码 `max_tokens=4096`，诊断报告实际只需 300-500 token。

### 4. 同一异常反复调用，无缓存

eBPF agent 每 15 秒跑一次分析。如果异常持续 5 分钟，同一个节点会触发 ~20 次工作流（= 40 次 LLM 调用）。虽然 AlertCorrelator 有 dedup，但 score/topology 的微小变化仍会产生"不同"的输入，每次都全额请求 API。

### 5. DeepSeek 不支持服务端 prompt caching

Anthropic API 的 `cache_control: {type: "ephemeral"}` 可以让 system prompt 只计费一次，但 DeepSeek 每次请求都全额处理 system prompt。唯一的缓存手段是 client 端 memoization。

## 优化措施

### 文件修改

| 文件 | 改动 |
|---|---|
| `aetherops/core/llm_diagnosis.py` | System prompt 精简、用户消息截断、紧凑 JSON |
| `aetherops/core/llm_provider.py` | `max_tokens` 4096 → 1024、client 端 TTL 缓存 |
| `aetherops/workflows/workflow.py` | Planner prompt 精简、用户消息紧凑化 |

### System prompt 压缩

```
改前: ~2500 chars / ~600 tokens (5 个详细故障模式 + 风险指南)
改后: ~976 chars / ~250 tokens (单行模式参考 + 风险缩写)
```

5 个故障模式从 36 行压成 5 行，保留了症状→动作的映射，去掉了冗余描述。

### 用户消息截断

```python
# 改前: 完整因果图 + 完整拓扑全量 dump
sections = [
    "## Causal Graph",
    json.dumps(causal_graph, indent=2),  # 全量+缩进
    "## Anomaly Context",
    json.dumps(anomaly_context, indent=2),  # 全量+缩进
]

# 改后: 截断 + 紧凑 + 只保留关键字段
MAX_USER_MSG_CHARS = 4000  # ~1000 tokens 上限
# edges 只保留 anomaly_score 最高的 20 条
# anomaly_context 只发 node/score/lat/chain
# 超过 4000 字符整体截断
```

### max_tokens 降低

```python
# 改前 (三个 provider 的 diagnose 方法)
raw = self._request(..., 4096, 0.3, timeout)

# 改后
raw = self._request(..., 1024, 0.3, timeout)
```

### Client 端 TTL 缓存

在 `OpenAICompatibleProvider._request()` 中实现 content-addressable 响应缓存，消除同一故障周期内的重复 API 调用。

```
diagnose(system_prompt, user_message):
    key = md5(system_prompt + user_message)
    if key in cache and not expired (TTL=60s):
        return cached_response  ← cache hit, 0 token
    response = _request(...)   ← cache miss, 正常调用
    cache[key] = (response, expires_at)
    return response
```

**参数**：
- TTL: 60 秒（覆盖同一次异常 4-5 个分析周期）
- max_size: 128 条（超出后淘汰最早过期的条目）
- 缓存粒度：`md5(system_prompt + user_message)` 精确匹配
- 同时覆盖 `diagnose()` 和 `chat()` 方法（planner 也受益）

**为什么只改 OpenAICompatibleProvider**：
- DeepSeek 是主要使用场景，需要 client 端缓存
- Anthropic 已有服务端 `cache_control`，不需要额外缓存
- Ollama 是本地的，不需要缓存

## 效果

| 指标 | 改前 | 改后 | 节省 |
|---|---|---|---|
| 诊断 system prompt | ~600 token | ~250 token | ~350 |
| 规划 system prompt | ~170 token | ~70 token | ~100 |
| 用户消息 JSON 格式 | `indent=2` | `separators` 紧凑 | ~30% |
| 用户消息上限 | 无限制 | 4000 字符软截断 | 上不封顶 |
| 诊断输出上限 | 4096 token | 1024 token | ~3000 |
| **大拓扑(300节点)单次诊断输入** | **~8000 token** | **~1000 token** | **8x** |
| 同一异常重复调用 | 每次全额请求 | TTL 60s 缓存命中 | **~90% 调用免请求** |
