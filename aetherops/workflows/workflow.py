"""
AetherOps — Multi-Agent Cognitive Workflow.

Architecture: Planner → Supervisor → Expert Agents
  - Planner          LLM-generated dynamic execution plan based on anomaly
  - Supervisor       route to next agent per plan
  - Topology Analyst  fetch service graph from Go data plane
  - Causal Analyst    build causal graph from topology snapshot
  - LLM Diagnostician LLM-based root cause diagnosis (single-turn)
  - Risk Assessor     blast radius evaluation
  - Remediation Executor  graded remediation + recovery verification
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Literal, Optional, TypedDict

from aetherops.core.llm_diagnosis import diagnose
from aetherops.core.llm_provider import ProviderFactory
from aetherops.core.risk_client import assess_remediation, execute_remediation
from aetherops.core.mcp_client import MCPClient, run_async
from aetherops.core.feedback import (
    get_feedback_store, get_rollback_assistant,
    ApprovalStatus, RiskLevel,
)

logger = logging.getLogger(__name__)


def _fetch_topology(include_healthy: bool = False):
    """Shared helper: fetch topology via MCP, returns a snapshot."""
    mcp_addr = os.getenv("AETHEROPS_MCP_ADDR", "http://localhost:50052")
    client = MCPClient(address=mcp_addr)
    run_async(client.connect())
    snapshot = run_async(client.get_topology(include_healthy=include_healthy))
    client.close()
    return snapshot


AGENTS = Literal[
    "planner",
    "topology_analyst",
    "causal_analyst",
    "llm_diagnostician",
    "risk_assessor",
    "remediation_executor",
    "finish",
]


# ── State Definition ──

class DiagnosisState(TypedDict):
    """Shared state passed between workflow nodes."""

    # Trigger
    anomaly_event: Optional[dict]
    anomaly_detected_at: float
    topology_snapshot: Optional[dict]

    # Causal graph (derived from topology)
    causal_graph: Optional[dict]

    # LLM diagnosis
    diagnosis_report: Optional[dict]
    diagnosis_confidence: float

    # Risk assessment
    risk_report: Optional[dict]

    # Remediation
    execution_result: Optional[dict]
    recovery_report: Optional[str]

    # RAG context
    rag_context: Optional[str]

    # Plan
    plan: Optional[list]
    plan_step_index: int
    plan_rationale: Optional[str]

    # Supervisor meta-state
    next_agent: str
    supervisor_instruction: Optional[str]

    # Completion
    completed: bool
    workflow_error: Optional[str]


# ── Planner ──

PLANNER_SYSTEM_PROMPT = """You are an expert SRE operations planner. Given an anomaly event and historical context, create a step-by-step diagnosis and remediation plan.

## Available Agents
- `topology_analyst` — Fetches live service topology from eBPF data plane
- `causal_analyst` — Builds causal graph from topology data
- `llm_diagnostician` — LLM-based root cause analysis
- `risk_assessor` — Evaluates blast radius and risk level of recommended actions
- `remediation_executor` — Executes remediation, verifies recovery

## Planning Rules
1. topology_analyst and causal_analyst are always needed first (they provide data)
2. llm_diagnostician must come after data is available
3. risk_assessor and remediation_executor come last
4. If the anomaly matches a known pattern (DB, network, cache, resource, hotspot), you may suggest re-ordering or repeating certain steps

## Output Format
```json
{
  "steps": ["topology_analyst", "causal_analyst", "llm_diagnostician", "risk_assessor", "remediation_executor"],
  "reasoning": "Brief explanation of why this plan was chosen"
}
```
"""


def _robust_json_extract(text: str) -> dict:
    """Try multiple strategies to extract valid JSON from LLM response text."""
    # Strategy 1: extract from ```json code block
    if "```json" in text:
        candidate = text.split("```json")[1].split("```")[0].strip()
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    # Strategy 2: extract from any ``` code block
    if "```" in text:
        candidate = text.split("```")[1].split("```")[0].strip()
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    # Strategy 3: outermost { ... } pair
    brace_start = text.find("{")
    brace_end = text.rfind("}")
    if brace_start >= 0 and brace_end > brace_start:
        candidate = text[brace_start:brace_end + 1]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    raise ValueError("No valid JSON extracted from LLM response")


def _call_llm_for_plan(anomaly_event: dict, rag_context: str = "") -> dict:
    """Call LLM to generate a diagnosis plan."""
    provider = ProviderFactory.from_env()
    if provider is None:
        logger.info("No LLM provider for planner — using default plan")
        return {
            "steps": [
                "topology_analyst", "causal_analyst",
                "llm_diagnostician",
                "risk_assessor", "remediation_executor",
            ],
            "reasoning": "Default plan (LLM not available)",
        }

    user_msg = (
        f"## Anomaly Event\n"
        f"```json\n{json.dumps(anomaly_event, indent=2)}\n```\n"
    )
    if rag_context:
        user_msg += f"\n## Historical Context (similar past incidents)\n{rag_context[:2000]}\n"

    try:
        raw = provider.chat(PLANNER_SYSTEM_PROMPT, user_msg, max_tokens=1024, temperature=0.2, timeout=30)
        if raw is None:
            raise RuntimeError("provider.chat returned None")
        plan_data = _robust_json_extract(raw)
        steps = plan_data.get("steps", [])
        if not steps:
            raise ValueError("empty plan")
        return plan_data

    except Exception as e:
        logger.warning("Planner LLM call failed (%s) — using default plan", e)
        return {
            "steps": [
                "topology_analyst", "causal_analyst",
                "llm_diagnostician",
                "risk_assessor", "remediation_executor",
            ],
            "reasoning": f"Default plan (LLM error: {e})",
        }


def planner(state: DiagnosisState) -> dict:
    """Generate a dynamic execution plan based on anomaly + RAG context."""
    anomaly = state.get("anomaly_event", {})
    rag = state.get("rag_context", "")
    plan_data = _call_llm_for_plan(anomaly, rag)

    steps = plan_data.get("steps", [])
    logger.info("Planner: %d steps — %s", len(steps), plan_data.get("reasoning", ""))

    return {
        "plan": steps,
        "plan_step_index": 0,
        "plan_rationale": plan_data.get("reasoning", ""),
    }


# ── Expert Agents ──

def topology_analyst(state: DiagnosisState) -> dict:
    """Expert 1: Fetch current service topology from Go MCP server."""
    try:
        snapshot = _fetch_topology(include_healthy=False)
        logger.info("TopologyAnalyst: fetched %d nodes, %d edges",
                     snapshot.node_count, snapshot.edge_count)
        return {
            "topology_snapshot": {
                "nodes": [n for n in snapshot.nodes if n["avg_latency_ms"] > 0],
                "edges": [e for e in snapshot.edges if e["anomaly_score"] > 0],
                "node_count": snapshot.node_count,
                "edge_count": snapshot.edge_count,
            }
        }
    except Exception as e:
        logger.error("TopologyAnalyst failed: %s", e)
        return {"topology_snapshot": {"nodes": [], "edges": [], "error": str(e)}}


def causal_analyst(state: DiagnosisState) -> dict:
    """Expert 2: Build causal graph from topology data (no external metrics/PC)."""
    topo = state.get("topology_snapshot", {})
    anomaly_event = state.get("anomaly_event", {})

    # Build causal edges from topology anomaly edges directly
    edges = []
    for edge in topo.get("edges", []):
        edges.append({
            "src": edge.get("src", ""),
            "dst": edge.get("dst", ""),
            "anomaly_score": edge.get("anomaly_score", 0),
            "avg_latency_ms": edge.get("avg_latency_ms", 0),
        })

    # Identify suspect nodes from anomaly context
    suspect_nodes = set()
    event_node = anomaly_event.get("node_id", "")
    if event_node:
        suspect_nodes.add(event_node)
    for n in anomaly_event.get("suspect_chain", []):
        suspect_nodes.add(n)
    for edge in topo.get("edges", []):
        if edge.get("src"):
            suspect_nodes.add(edge["src"])
        if edge.get("dst"):
            suspect_nodes.add(edge["dst"])

    causal_graph = {
        "nodes": list(suspect_nodes),
        "edges": edges,
        "method": "topology_propagation",
    }
    logger.info("CausalAnalyst: built %d edges from topology propagation", len(edges))

    return {"causal_graph": causal_graph}


def llm_diagnostician(state: DiagnosisState) -> dict:
    """Expert 3: Single-turn LLM diagnosis on causal graph + anomaly context."""
    causal_graph = state.get("causal_graph", {})
    anomaly_context = {
        "topology": state.get("topology_snapshot", {}),
        "anomaly_event": state.get("anomaly_event", {}),
    }

    report = diagnose(
        causal_graph=causal_graph,
        anomaly_context=anomaly_context,
    )

    logger.info("LLMDiagnostician: root_cause=%s confidence=%.2f",
                 report.root_cause, report.confidence)

    return {
        "diagnosis_report": {
            "root_cause": report.root_cause,
            "confidence": report.confidence,
            "explanation": report.explanation,
            "affected_services": report.affected_services,
            "recommended_actions": report.recommended_actions,
        },
        "diagnosis_confidence": report.confidence,
    }


# ── Risk Assessor & Remediation Executor ──

def risk_assessor(state: DiagnosisState) -> dict:
    """Expert 4: Assess blast radius for the top recommended action."""
    report = state.get("diagnosis_report", {})
    actions = report.get("recommended_actions", [])

    if not actions:
        logger.warning("RiskAssessor: no actions to assess")
        return {"risk_report": {"error": "no actions to assess"}}

    top_action = actions[0]
    risk = assess_remediation(
        target_node=top_action.get("target", state.get("anomaly_event", {}).get("node_id", "")),
        action=top_action.get("action", "TC_DROP"),
        diagnosis=report,
    )
    logger.info("RiskAssessor: risk=%s budget=%.1f%%",
                 risk.get("risk_level"), risk.get("estimated_error_budget_consumption", 0))
    return {"risk_report": risk}


def remediation_executor(state: DiagnosisState) -> dict:
    """Expert 5: Execute remediation, verify recovery, generate fault report."""
    risk = state.get("risk_report", {})
    report = state.get("diagnosis_report", {})
    result: dict = {}

    feedback = get_feedback_store()
    rollback = get_rollback_assistant()
    trace_id = f"exec-{int(time.time())}"
    anomaly_node = state.get("anomaly_event", {}).get("node_id", "unknown")

    anomaly_score_before = state.get("anomaly_event", {}).get("anomaly_score", 0)
    anomaly_detected_at = state.get("anomaly_detected_at", 0.0)

    # 5a. Execute graded remediation
    if risk.get("error"):
        result["execution_result"] = {"status": "skipped", "details": risk.get("error"), "trace_id": trace_id}
    else:
        actions = report.get("recommended_actions", [])
        if not actions:
            result["execution_result"] = {"status": "skipped", "details": "no actions", "trace_id": trace_id}
        else:
            top_action = actions[0]
            risk_level_str = risk.get("risk_level", "RISK_LOW")
            try:
                risk_enum = RiskLevel.HIGH if "HIGH" in risk_level_str else (
                    RiskLevel.MEDIUM if "MEDIUM" in risk_level_str else RiskLevel.LOW
                )
            except Exception:
                risk_enum = RiskLevel.LOW
            force = risk_enum == RiskLevel.LOW

            if risk_enum == RiskLevel.HIGH:
                feedback.record_approval(
                    trace_id=trace_id, node_id=anomaly_node,
                    diagnosis_report=report, action=top_action,
                    status=ApprovalStatus.PENDING,
                    comment="HIGH risk action pending human approval",
                )
                result["execution_result"] = {
                    "status": "pending_approval",
                    "details": "HIGH risk requires human approval",
                    "trace_id": trace_id,
                }
            else:
                exec_result = execute_remediation(
                    target_node=top_action.get("target", ""),
                    action=top_action.get("action", "TC_DROP"),
                    force=force,
                )
                exec_result["trace_id"] = trace_id
                result["execution_result"] = exec_result

                status = ApprovalStatus.AUTO_EXECUTED_LOW_RISK if force else ApprovalStatus.APPROVED
                feedback.record_approval(
                    trace_id=trace_id, node_id=anomaly_node,
                    diagnosis_report=report, action=top_action,
                    status=status,
                )
                logger.info("RemediationExecutor: status=%s id=%s trace=%s",
                             exec_result.get("status"), exec_result.get("execution_id"), trace_id)

    # 5b. Recovery verification
    recovery_report = _verify_recovery(
        anomaly_node=anomaly_node,
        anomaly_score_before=anomaly_score_before,
        execution_result=result.get("execution_result", {}),
        diagnosis_report=report,
        anomaly_detected_at=anomaly_detected_at,
    )
    result["recovery_report"] = recovery_report
    logger.info("RemediationExecutor: recovery verification complete")

    # Check if rollback is needed
    if rollback.needs_rollback(recovery_report):
        exec_result = result.get("execution_result", {})
        rb_result = rollback.execute_rollback(
            trace_id=trace_id,
            node_id=anomaly_node,
            original_action=report.get("recommended_actions", [{}])[0] if report.get("recommended_actions") else {},
            execution_id=exec_result.get("execution_id", ""),
        )
        result["rollback_result"] = rb_result
        logger.warning("Rollback executed for trace=%s", trace_id)

    # Record outcome
    status = result.get("execution_result", {}).get("status", "unknown")
    outcome = "success" if "Resolved" in recovery_report else (
        "partial" if "Partially" in recovery_report else "failure"
    )
    mttr_value = 0.0
    if anomaly_detected_at > 0:
        mttr_value = time.time() - anomaly_detected_at
    feedback.record_outcome(trace_id=trace_id, outcome=outcome, mttr_seconds=mttr_value)

    result["completed"] = True
    return result


def _verify_recovery(
    anomaly_node: str,
    anomaly_score_before: float,
    execution_result: dict,
    diagnosis_report: dict,
    anomaly_detected_at: float = 0.0,
) -> str:
    """Re-fetch topology after remediation and generate a Markdown recovery report."""
    report_sections: list[str] = []
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    mttr_seconds = 0.0
    mttr_str = "N/A"
    if anomaly_detected_at > 0:
        mttr_seconds = time.time() - anomaly_detected_at
        if mttr_seconds < 120:
            mttr_str = f"{mttr_seconds:.0f}s"
        else:
            mins = int(mttr_seconds // 60)
            secs = int(mttr_seconds % 60)
            mttr_str = f"{mins}m {secs}s"

    exec_status = execution_result.get("status", "unknown")
    report_sections.append("# AetherOps Recovery Verification Report\n")
    report_sections.append(f"**Generated:** {ts}")
    report_sections.append(f"**Target Node:** `{anomaly_node}`")
    report_sections.append(f"**Remediation Status:** `{exec_status}`")
    report_sections.append(f"**MTTR:** `{mttr_str}`\n")

    root_cause = diagnosis_report.get("root_cause", "unknown")
    confidence = diagnosis_report.get("confidence", 0)
    report_sections.append("## Remediation Summary\n")
    report_sections.append(f"- **Root Cause:** {root_cause}")
    report_sections.append(f"- **Diagnosis Confidence:** {confidence:.1%}")
    report_sections.append(f"- **Anomaly Score (pre):** {anomaly_score_before:.2f}")
    if execution_result.get("execution_id"):
        report_sections.append(f"- **Execution ID:** `{execution_result['execution_id']}`")
    if execution_result.get("details"):
        report_sections.append(f"- **Details:** {execution_result['details']}\n")

    # Recovery verification — polling with 2 attempts
    poll_backoff = [2, 3]
    post_anomaly = 0.0
    post_latency = 0.0
    recovered = False

    for attempt, delay in enumerate(poll_backoff, 1):
        logger.info(
            "Recovery verification: polling attempt %d/%d (waiting %ds)...",
            attempt, len(poll_backoff), delay,
        )
        time.sleep(delay)

        try:
            snapshot = _fetch_topology(include_healthy=False)

            for edge in snapshot.edges:
                if edge.get("src") == anomaly_node or edge.get("dst") == anomaly_node:
                    if edge.get("anomaly_score", 0) > post_anomaly:
                        post_anomaly = edge.get("anomaly_score", 0)
                        post_latency = edge.get("avg_latency_ms", 0)

            recovered = post_anomaly < (anomaly_score_before * 0.3)
            if recovered and post_latency < 1000:
                logger.info(
                    "Recovery verification: resolved after %.1fs (score=%.2f, lat=%.1f)",
                    sum(poll_backoff[:attempt]), post_anomaly, post_latency,
                )
                break

            logger.info(
                "Recovery verification: not yet resolved (score=%.2f, lat=%.1f) — retrying...",
                post_anomaly, post_latency,
            )
        except Exception as e:
            logger.warning("Recovery verification poll attempt %d failed: %s", attempt, e)
            if attempt < len(poll_backoff):
                continue
            post_anomaly = anomaly_score_before
            post_latency = 9999

    latency_improved = post_latency < 1000
    report_sections.append("## Recovery Verification\n")
    report_sections.append("| Metric | Before | After | Status |")
    report_sections.append("|--------|--------|-------|--------|")
    report_sections.append(
        f"| Anomaly Score | {anomaly_score_before:.2f} | {post_anomaly:.2f} | "
        f"{'Resolved' if recovered else 'Still Elevated'} |"
    )
    report_sections.append(
        f"| Latency (ms) | — | {post_latency:.2f} | "
        f"{'Normal' if latency_improved else 'Elevated'} |\n"
    )

    if recovered and latency_improved:
        report_sections.append("### Verdict: Anomaly Resolved")
    elif recovered:
        report_sections.append("### Verdict: Partially Resolved")
    else:
        report_sections.append("### Verdict: Not Resolved")

    report_sections.append("\n---\n*Report auto-generated by AetherOps Remediation Executor*")

    return "\n".join(report_sections)


# ── Supervisor ──

def supervisor(state: DiagnosisState) -> dict:
    """Supervisor agent: follow the plan step by step.

    Routing priority:
      1. If plan is empty/missing → planner (first run)
      2. Follow plan step by step
      3. Plan exhausted → finish (END)
    """
    plan: list = state.get("plan") or []
    step_idx: int = state.get("plan_step_index", 0)
    next_agent: str
    instruction: Optional[str] = None

    # Case 1: No plan yet → run planner
    if not plan:
        next_agent = "planner"
        instruction = "no plan yet"

    # Case 2: Follow plan
    elif step_idx < len(plan):
        next_agent = plan[step_idx]
        instruction = f"plan step {step_idx + 1}/{len(plan)}: {next_agent}"

    # Case 3: Plan done
    else:
        next_agent = "finish"
        instruction = "all steps complete"

    logger.info("Supervisor → %s (%s)", next_agent, instruction)

    new_index = step_idx
    if next_agent in ("planner", "topology_analyst", "causal_analyst",
                       "llm_diagnostician", "risk_assessor",
                       "remediation_executor"):
        if next_agent != "planner":
            new_index = step_idx + 1
        else:
            new_index = 0

    return {
        "next_agent": next_agent,
        "supervisor_instruction": instruction,
        "plan_step_index": new_index,
    }


# ── Workflow Engine ──

class Workflow:
    """Minimal workflow engine — replaces LangGraph StateGraph.

    Holds a mapping of agent name → callable and an entry point.
    Each agent receives the current state dict and returns a dict of updates.
    The loop reads ``state["next_agent"]`` (set by the supervisor) to decide
    which agent to run next, stopping when ``next_agent == "finish"`` or the
    state sets ``completed=True``.
    """

    def __init__(self, agents: dict[str, callable], entry_point: str):
        self._agents = dict(agents)
        self._entry = entry_point

    def invoke(self, state: dict) -> dict:
        """Run the workflow loop, mutating *state* in place."""
        state = dict(state)
        agent = state.get("next_agent", self._entry)
        while agent in self._agents:
            result = self._agents[agent](state)
            state.update(result)
            if state.get("completed"):
                break
            if agent not in ("supervisor", "finish"):
                agent = "supervisor"
            else:
                agent = state.get("next_agent", "finish")
        return state


# ── Graph Builder ──

def build_workflow() -> Workflow:
    """Build and return the multi-agent workflow engine."""
    agents = {
        "supervisor": supervisor,
        "planner": planner,
        "topology_analyst": topology_analyst,
        "causal_analyst": causal_analyst,
        "llm_diagnostician": llm_diagnostician,
        "risk_assessor": risk_assessor,
        "remediation_executor": remediation_executor,
    }
    return Workflow(agents=agents, entry_point="supervisor")


def run_workflow(workflow: Workflow, initial_state: dict) -> dict:
    """Invoke a workflow (no hook wrappers)."""
    return workflow.invoke(initial_state)
