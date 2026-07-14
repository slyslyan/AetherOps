# CLAUDE.md - ebpfagent 项目约定

## Git 提交

- 不要在任何 git commit 消息中添加 `Co-Authored-By` 行

## 项目架构（已简化）

核心叙事：**eBPF 采集 → AI Multi-Agent 分析 → K8s 自愈**

```
Go 数据面: eBPF kprobe → Ring Buffer → ServiceGraph → 异常检测 → MCP Server
Python 认知面: MCP Client → Supervisor → 5 Expert Agents → LLM Diagnosis → 分级自愈 + 恢复验证
```

## 已删除模块（面试不展开，不要重建）

以下模块已在简化中删除：chaos/、benchmark/、causal_inference.py、multi_turn_diagnosis.py、metrics_fetcher.py、hooks.py、agent_observability.py、incident_memory.py

## 核心接口（必须保持兼容）

- `workflows.workflow.build_workflow()` → Workflow
- `workflows.workflow.run_workflow(workflow, state)` → dict
- `core.llm_provider.ProviderFactory.from_env()` → LLMProvider
- `core.mcp_client.MCPClient` — MCP 客户端
