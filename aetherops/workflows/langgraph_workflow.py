"""
AetherOps — Multi-Agent LangGraph Cognitive Workflow.

Architecture: Supervisor + 5 Expert Agents
  - Supervisor         orchestrates, delegates, synthesizes
  - Topology Analyst   fetches service graph from Go data plane
  - Causal Analyst     fetches metrics + runs causal discovery
  - LLM Diagnostician  LLM-based root cause diagnosis
  - Risk Assessor      blast radius evaluation
  - Remediation Executor  graded remediation + RAG storage + prompt optimization
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict
from typing import Annotated, Any, Dict, List, Literal, Optional, TypedDict

import yaml
from langgraph.graph import END, StateGraph

from aetherops.core.causal_inference import run_causal_discovery
from aetherops.core.mcp_client import MCPClient, run_async
from aetherops.core.llm_diagnosis import diagnose
from aetherops.core.multi_turn_diagnosis import diagnose_multi_turn, DataRequest
from aetherops.core.metrics_fetcher import fetch_recent_metrics
from aetherops.core.risk_client import assess_remediation, execute_remediation
from aetherops.core.alert_correlation import AlertCorrelator, AlertEvent
from aetherops.core.feedback import (
    get_feedback_store, get_rollback_assistant,
    ApprovalStatus, AuditEntry, RiskLevel,
)

logger = logging.getLogger(__name__)


# ── State Definition ──

class DiagnosisState(TypedDict):
    """Shared state passed between LangGraph nodes."""

    # Trigger
    anomaly_event: Optional[dict]
    anomaly_detected_at: float       # time.time() when anomaly first received, for MTTR
    topology_snapshot: Optional[dict]

    # Step 1: Data fetching
    metrics_data: Optional[Any]  # pandas DataFrame

    # Step 2: Causal inference
    causal_graph: Optional[dict]
    causal_method: str

    # Step 3: LLM diagnosis
    diagnosis_report: Optional[dict]
    diagnosis_confidence: float
    diagnosis_loop_count: int

    # Step 4: Risk assessment
    risk_report: Optional[dict]

    # Step 5: Remediation
    execution_result: Optional[dict]

    # Step 6: Recovery verification (post-remediation)
    topology_before: Optional[dict]  # snapshot taken before remediation
    recovery_report: Optional[str]   # Markdown report

    # Step 7: RAG + Optimization (metadata)
    completed: bool
    workflow_error: Optional[str]

    # Supervisor meta-state
    next_agent: str          # which agent the supervisor routes to
    supervisor_instruction: Optional[str]  # routing rationale (for observability)


# ── Expert Agents ──

EXPERT_AGENTS = Literal[
    "topology_analyst",
    "causal_analyst",
    "llm_diagnostician",
    "risk_assessor",
    "remediation_executor",
    "finish",
]


def topology_analyst(state: DiagnosisState) -> Dict:
    """Expert 1: Fetch current service topology from Go MCP server."""
    try:
        transport = os.getenv("AETHEROPS_TRANSPORT", "mcp")
        if transport == "grpc":
            from aetherops.core.grpc_client import AetherOpsClient

            addr = os.getenv("AETHEROPS_GRPC_ADDR", "localhost:50051")
            client = AetherOpsClient(address=addr)
            client.connect()
            snapshot = client.get_topology(include_healthy=False)
            client.close()
        else:
            mcp_addr = os.getenv("AETHEROPS_MCP_ADDR", "http://localhost:50052")
            client = MCPClient(address=mcp_addr)
            run_async(client.connect())
            snapshot = run_async(client.get_topology(include_healthy=False))
            client.close()
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


def causal_analyst(state: DiagnosisState) -> Dict:
    """Expert 2: Fetch Prometheus metrics and run causal inference."""
    # 2a. Fetch metrics
    prom_url = os.getenv("PROMETHEUS_URL", "http://localhost:9090")
    df = fetch_recent_metrics(
        prometheus_url=prom_url,
        window_minutes=5,
        step_seconds=15,
    )

    # 2b. Run causal discovery on metrics + topology
    metrics_df = df
    topo = state.get("topology_snapshot", {})

    if metrics_df is not None and hasattr(metrics_df, "to_dict"):
        metrics_dict = metrics_df.to_dict()
    else:
        metrics_dict = {}

    context = {
        "known_topology": topo,
        "metrics_summary": metrics_dict,
    }

    try:
        result = run_causal_discovery(
            metrics_df=metrics_df,
            method=state.get("causal_method", "LPCMCI"),
            alpha=0.05,
            context=context,
        )
        logger.info("CausalAnalyst: inferred %d causal edges", len(result.edges))
        return {
            "metrics_data": df,
            "causal_graph": {
                "nodes": result.nodes,
                "edges": [(s, d, t) for s, d, t in result.edges],
            },
        }
    except Exception as e:
        logger.error("CausalAnalyst failed: %s", e)
        return {
            "metrics_data": df,
            "causal_graph": {"nodes": [], "edges": [], "error": str(e)},
        }


def llm_diagnostician(state: DiagnosisState) -> Dict:
    """Expert 3: Run multi-turn LLM diagnosis on causal graph + anomaly context."""
    causal_graph = state.get("causal_graph", {})
    anomaly_context = {
        "topology": state.get("topology_snapshot", {}),
        "anomaly_event": state.get("anomaly_event", {}),
    }

    # Use multi-turn diagnosis for iterative refinement
    result = diagnose_multi_turn(
        causal_graph=causal_graph,
        anomaly_context=anomaly_context,
        model=os.getenv("LLM_MODEL", "deepseek-v4-flash"),
        max_turns=int(os.getenv("MAX_DIAGNOSIS_TURNS", "3")),
    )

    report = result.final_report
    logger.info("LLMDiagnostician: root_cause=%s confidence=%.2f turns=%d improved=%s",
                 report.root_cause, report.confidence, result.turn_count, result.improved)

    return {
        "diagnosis_report": {
            "root_cause": report.root_cause,
            "confidence": report.confidence,
            "explanation": report.explanation,
            "affected_services": report.affected_services,
            "recommended_actions": report.recommended_actions,
            "multi_turn_data": {
                "turn_count": result.turn_count,
                "improved": result.improved,
                "data_requests": [asdict(r) for r in result.data_requests],
            },
        },
        "diagnosis_confidence": report.confidence,
        "diagnosis_loop_count": state.get("diagnosis_loop_count", 0) + 1,
    }


def risk_assessor(state: DiagnosisState) -> Dict:
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


def remediation_executor(state: DiagnosisState) -> Dict:
    """Expert 5: Execute remediation, verify recovery, generate fault report."""
    risk = state.get("risk_report", {})
    report = state.get("diagnosis_report", {})
    result: Dict[str, Any] = {}

    # Initialize feedback loop components
    feedback = get_feedback_store()
    rollback = get_rollback_assistant()
    trace_id = f"exec-{int(time.time())}"
    anomaly_node = state.get("anomaly_event", {}).get("node_id", "unknown")
    anomaly_score_before = state.get("anomaly_event", {}).get("anomaly_score", 0)
    anomaly_detected_at = state.get("anomaly_detected_at", 0.0)

    # 5a. Execute graded remediation
    if risk.get("error"):
        result["execution_result"] = {"status": "skipped", "details": risk.get("error"), "trace_id": trace_id}
        feedback.audit(AuditEntry(
            timestamp_ns=time.time_ns(), agent="remediation_executor",
            action="skip", input_summary=risk.get("error", ""),
            output_summary="skipped", duration_ms=0,
            decision="skipped", trace_id=trace_id,
        ))
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

            # HIGH risk: require human approval
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
                feedback.audit(AuditEntry(
                    timestamp_ns=time.time_ns(), agent="remediation_executor",
                    action=top_action.get("action", ""),
                    input_summary=f"{anomaly_node} via {top_action.get('action', '')}",
                    output_summary=json.dumps({k: v for k, v in exec_result.items() if k != "trace_id"}),
                    duration_ms=0, decision=exec_result.get("status", "unknown"),
                    risk_level=risk_enum, trace_id=trace_id,
                ))
                logger.info("RemediationExecutor: status=%s id=%s trace=%s",
                             exec_result.get("status"), exec_result.get("execution_id"), trace_id)

    # 5b. Recovery verification: wait, re-fetch topology, compare, generate report.
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

    # 5c. Store to RAG knowledge base
    try:
        from aetherops.rag.store import store_diagnosis

        record = {
            "anomaly_event": state.get("anomaly_event"),
            "causal_graph": state.get("causal_graph"),
            "diagnosis_report": state.get("diagnosis_report"),
            "execution_result": result.get("execution_result"),
            "recovery_report": recovery_report,
            "status": "success" if not state.get("workflow_error") else "failed",
        }
        store_diagnosis(record)
        logger.info("RemediationExecutor: diagnosis stored to RAG")
    except Exception as e:
        logger.warning("RAG store failed (non-critical): %s", e)

    # 5d. Trigger DSPy prompt optimization
    try:
        from aetherops.dspy.optimizer import async_optimize

        async_optimize()
    except Exception as e:
        logger.warning("DSPy optimize trigger failed (non-critical): %s", e)

    result["completed"] = True
    return result


def _verify_recovery(
    anomaly_node: str,
    anomaly_score_before: float,
    execution_result: dict,
    diagnosis_report: dict,
    anomaly_detected_at: float = 0.0,
) -> str:
    """Re-fetch metrics after remediation and generate a Markdown recovery report.

    Args:
        anomaly_node: The node that triggered the anomaly.
        anomaly_score_before: Anomaly score before remediation.
        execution_result: Result dict from remediation execution.
        diagnosis_report: Diagnosis report dict from LLM.
        anomaly_detected_at: time.time() when anomaly was first received (for MTTR).

    Returns:
        Markdown-formatted fault report string.
    """
    report_sections: list[str] = []
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    # Compute MTTR: time from anomaly detection to recovery verification.
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

    # ── Header ──
    exec_status = execution_result.get("status", "unknown")
    report_sections.append(f"# AetherOps Recovery Verification Report")
    report_sections.append(f"")
    report_sections.append(f"**Generated:** {ts}")
    report_sections.append(f"**Target Node:** `{anomaly_node}`")
    report_sections.append(f"**Remediation Status:** `{exec_status}`")
    report_sections.append(f"**MTTR:** `{mttr_str}`")
    report_sections.append(f"")

    # ── Remediation summary ──
    root_cause = diagnosis_report.get("root_cause", "unknown")
    confidence = diagnosis_report.get("confidence", 0)
    report_sections.append(f"## Remediation Summary")
    report_sections.append(f"")
    report_sections.append(f"- **Root Cause:** {root_cause}")
    report_sections.append(f"- **Diagnosis Confidence:** {confidence:.1%}")
    report_sections.append(f"- **Anomaly Score (pre):** {anomaly_score_before:.2f}")
    if execution_result.get("execution_id"):
        report_sections.append(f"- **Execution ID:** `{execution_result['execution_id']}`")
    if execution_result.get("details"):
        report_sections.append(f"- **Details:** {execution_result['details']}")
    report_sections.append(f"")

    # ── Recovery verification ──
    logger.info("Recovery verification: waiting 10s before re-checking metrics...")
    time.sleep(10)

    try:
        # Re-fetch topology to check if anomaly is resolved.
        transport = os.getenv("AETHEROPS_TRANSPORT", "mcp")
        if transport == "grpc":
            from aetherops.core.grpc_client import AetherOpsClient

            addr = os.getenv("AETHEROPS_GRPC_ADDR", "localhost:50051")
            client: MCPClient = AetherOpsClient(address=addr)  # type: ignore
            client.connect()
            snapshot = client.get_topology(include_healthy=False)
            client.close()
        else:
            mcp_addr = os.getenv("AETHEROPS_MCP_ADDR", "http://localhost:50052")
            client = MCPClient(address=mcp_addr)
            run_async(client.connect())
            snapshot = run_async(client.get_topology(include_healthy=False))
            client.close()

        # Find the target node in the post-remediation snapshot.
        post_anomaly = 0.0
        post_latency = 0.0
        for edge in snapshot.edges:
            if edge.get("src") == anomaly_node or edge.get("dst") == anomaly_node:
                if edge.get("anomaly_score", 0) > post_anomaly:
                    post_anomaly = edge.get("anomaly_score", 0)
                    post_latency = edge.get("avg_latency_ms", 0)

        # Determine recovery status.
        recovered = post_anomaly < (anomaly_score_before * 0.3)  # 70% reduction threshold
        latency_improved = post_latency < 1000  # below 1s threshold

        report_sections.append(f"## Recovery Verification")
        report_sections.append(f"")
        report_sections.append(f"| Metric | Before | After | Status |")
        report_sections.append(f"|--------|--------|-------|--------|")
        report_sections.append(
            f"| Anomaly Score | {anomaly_score_before:.2f} | {post_anomaly:.2f} | "
            f"{'✅ Resolved' if recovered else '⚠️ Still Elevated'} |"
        )
        report_sections.append(
            f"| Latency (ms) | — | {post_latency:.2f} | "
            f"{'✅ Normal' if latency_improved else '⚠️ Elevated'} |"
        )
        report_sections.append(f"")

        # Overall verdict
        if recovered and latency_improved:
            report_sections.append(f"### ✅ Verdict: Anomaly Resolved")
            report_sections.append(f"")
            report_sections.append(
                f"The remediation action successfully reduced the anomaly score "
                f"from **{anomaly_score_before:.2f}** to **{post_anomaly:.2f}** "
                f"and latency is within normal range (**{post_latency:.2f} ms**)."
            )
        elif recovered:
            report_sections.append(f"### ⚠️ Verdict: Partially Resolved")
            report_sections.append(f"")
            report_sections.append(
                f"The anomaly score dropped from **{anomaly_score_before:.2f}** "
                f"to **{post_anomaly:.2f}**, but latency remains elevated "
                f"(**{post_latency:.2f} ms**). Further investigation may be needed."
            )
        else:
            report_sections.append(f"### ❌ Verdict: Not Resolved")
            report_sections.append(f"")
            report_sections.append(
                f"The anomaly score remains at **{post_anomaly:.2f}** "
                f"(was **{anomaly_score_before:.2f}** before remediation). "
                f"Escalating for human review."
            )

    except Exception as e:
        logger.error("Recovery verification re-check failed: %s", e)
        report_sections.append(f"## Recovery Verification")
        report_sections.append(f"")
        report_sections.append(f"❌ **Verification check failed:** {e}")
        report_sections.append(f"Manual validation required.")
        report_sections.append(f"")

    # ── Footer ──
    report_sections.append(f"---")
    report_sections.append(f"*Report auto-generated by AetherOps Remediation Executor*")

    return "\n".join(report_sections)


# ── Supervisor ──

def supervisor(state: DiagnosisState) -> Dict:
    """Supervisor agent: inspect state and route to the next expert.

    Routing logic (priority order):
      1. No topology       → Topology Analyst
      2. No causal graph   → Causal Analyst
      3. No diagnosis      → LLM Diagnostician
      4. Low confidence    → Causal Analyst (reanalyze with fresh metrics)
      5. No risk report    → Risk Assessor
      6. No execution      → Remediation Executor
      7. All done          → finish
    """
    instruction: Optional[str] = None
    next_agent: str

    if state.get("topology_snapshot") is None:
        next_agent = "topology_analyst"
        instruction = "topology not yet fetched"

    elif state.get("causal_graph") is None:
        next_agent = "causal_analyst"
        instruction = "causal graph not yet built"

    elif state.get("diagnosis_report") is None:
        next_agent = "llm_diagnostician"
        instruction = "no LLM diagnosis yet"

    elif (
        state.get("diagnosis_confidence", 0) < 0.6
        and state.get("diagnosis_loop_count", 0) < 2
    ):
        next_agent = "causal_analyst"
        instruction = (
            f"low confidence ({state.get('diagnosis_confidence', 0):.2f}), "
            f"re-analyzing with fresh metrics (loop {state.get('diagnosis_loop_count', 0) + 1}/2)"
        )

    elif state.get("risk_report") is None:
        next_agent = "risk_assessor"
        instruction = "risk not yet assessed"

    elif state.get("execution_result") is None:
        next_agent = "remediation_executor"
        instruction = "remediation not yet executed"

    else:
        next_agent = "finish"
        instruction = "all agents complete"

    logger.info("Supervisor → %s (%s)", next_agent, instruction)
    return {
        "next_agent": next_agent,
        "supervisor_instruction": instruction,
    }


# ── Graph Builder ──

def build_workflow() -> StateGraph:
    """Build and return the multi-agent LangGraph workflow."""
    workflow = StateGraph(DiagnosisState)

    # Add nodes: supervisor + 5 expert agents
    workflow.add_node("supervisor", supervisor)
    workflow.add_node("topology_analyst", topology_analyst)
    workflow.add_node("causal_analyst", causal_analyst)
    workflow.add_node("llm_diagnostician", llm_diagnostician)
    workflow.add_node("risk_assessor", risk_assessor)
    workflow.add_node("remediation_executor", remediation_executor)

    # Set entry point
    workflow.set_entry_point("supervisor")

    # Expert agents always return to supervisor for next routing decision
    for agent in ["topology_analyst", "causal_analyst", "llm_diagnostician",
                   "risk_assessor", "remediation_executor"]:
        workflow.add_edge(agent, "supervisor")

    # Supervisor routes to the next expert based on state
    workflow.add_conditional_edges(
        "supervisor",
        lambda state: state.get("next_agent", "finish"),
        {
            "topology_analyst": "topology_analyst",
            "causal_analyst": "causal_analyst",
            "llm_diagnostician": "llm_diagnostician",
            "risk_assessor": "risk_assessor",
            "remediation_executor": "remediation_executor",
            "finish": END,
        },
    )

    return workflow.compile()


def load_workflow_from_yaml(path: str = "workflow.yaml") -> StateGraph:
    """Load workflow configuration from YAML and build the graph."""
    with open(path, "r") as f:
        config = yaml.safe_load(f)
    logger.info("Loaded workflow: %s", config.get("workflow", {}).get("name", "unknown"))
    return build_workflow()
