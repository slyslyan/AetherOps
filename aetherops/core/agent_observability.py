"""
AetherOps — Agent Observability: tracing, metrics, and span reporting.

Each agent (node in the LangGraph workflow) records a Span with timing,
input/output summary, and status. Spans are accumulated in the workflow
state and exposed via a Prometheus /metrics endpoint.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from functools import wraps
from typing import Any, Callable, Dict, List, Optional

try:
    from prometheus_client import Histogram, Counter, Gauge, generate_latest, REGISTRY

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

logger = logging.getLogger(__name__)


# ── Spans ──

@dataclass
class Span:
    """A single agent execution span."""
    agent: str
    started_at: float  # time.time()
    ended_at: Optional[float] = None
    duration_ms: float = 0.0
    status: str = "ok"  # ok | error | skipped
    input_summary: str = ""
    output_summary: str = ""
    error: str = ""

    def finish(self, status: str = "ok", error: str = ""):
        self.ended_at = time.time()
        self.duration_ms = (self.ended_at - self.started_at) * 1000
        self.status = status
        self.error = error

    def to_dict(self) -> dict:
        return {
            "agent": self.agent,
            "duration_ms": round(self.duration_ms, 1),
            "status": self.status,
            "error": self.error,
        }


def summarize(obj: Any, max_len: int = 120) -> str:
    """Produce a short text summary of a state object."""
    if obj is None:
        return "none"
    if isinstance(obj, dict):
        keys = list(obj.keys())
        return f"{{{', '.join(keys[:5])}}}" + (", ..." if len(keys) > 5 else "")
    if isinstance(obj, list):
        return f"[{len(obj)} items]"
    s = str(obj)
    return s[:max_len] + "..." if len(s) > max_len else s


# ── Prometheus Metrics ──

_agent_duration = None
_agent_total = None
_agent_errors = None
_workflow_duration = None

def _ensure_metrics():
    global _agent_duration, _agent_total, _agent_errors, _workflow_duration
    if _agent_duration is not None:
        return
    if not PROMETHEUS_AVAILABLE:
        logger.debug("prometheus_client not installed — metrics disabled")
        return
    try:
        _agent_duration = Histogram(
            "aetherops_agent_duration_ms",
            "Agent execution duration in ms",
            ["agent", "status"],
            buckets=(10, 50, 100, 500, 1000, 3000, 10_000, 30_000, 60_000),
        )
        _agent_total = Counter(
            "aetherops_agent_total",
            "Agent execution count",
            ["agent", "status"],
        )
        _agent_errors = Counter(
            "aetherops_agent_errors_total",
            "Agent error count",
            ["agent"],
        )
        _workflow_duration = Histogram(
            "aetherops_workflow_duration_ms",
            "Full workflow duration in ms",
            buckets=(1000, 5000, 10_000, 30_000, 60_000, 120_000, 300_000),
        )
        logger.info("Prometheus metrics registered")
    except Exception as e:
        logger.warning("Failed to register Prometheus metrics: %s", e)


def record_agent_metrics(agent: str, duration_ms: float, status: str):
    _ensure_metrics()
    if _agent_duration is None:
        return
    try:
        _agent_duration.labels(agent=agent, status=status).observe(duration_ms)
        _agent_total.labels(agent=agent, status=status).inc()
        if status == "error":
            _agent_errors.labels(agent=agent).inc()
    except Exception as e:
        logger.debug("Metrics recording failed: %s", e)


def record_workflow_metrics(duration_ms: float):
    _ensure_metrics()
    if _workflow_duration is None:
        return
    try:
        _workflow_duration.observe(duration_ms)
    except Exception as e:
        logger.debug("Workflow metrics recording failed: %s", e)


def metrics_text() -> str:
    """Return Prometheus metrics as text/plain (for /metrics endpoint)."""
    if PROMETHEUS_AVAILABLE:
        return generate_latest(REGISTRY).decode("utf-8")
    return "# prometheus_client not installed"


# ── Tracing decorator ──

def trace_agent(agent_name: str) -> Callable:
    """Decorator that wraps a LangGraph agent node with tracing + metrics.

    The decorated function must accept a state dict and return a state dict.
    The decorator adds/updates the ``trace_spans`` key in the returned state.
    """
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(state: dict) -> dict:
            span = Span(agent=agent_name, started_at=time.time())
            span.input_summary = _build_input_summary(state, agent_name)

            try:
                result = fn(state)
                span.finish(status="ok")
                span.output_summary = _build_output_summary(result)
                record_agent_metrics(agent_name, span.duration_ms, "ok")
            except Exception as e:
                logger.exception("Agent %s failed", agent_name)
                span.finish(status="error", error=str(e))
                record_agent_metrics(agent_name, span.duration_ms, "error")
                result = {"workflow_error": str(e)}

            # Append span to trace
            spans: list = result.get("trace_spans", state.get("trace_spans", []))
            spans = list(spans) + [span.to_dict()]
            result["trace_spans"] = spans
            return result

        return wrapper

    return decorator


def _build_input_summary(state: dict, agent_name: str) -> str:
    """Build a one-line input summary based on agent type."""
    if agent_name == "planner":
        ev = state.get("anomaly_event", {})
        return f"node={ev.get('node_id','?')} score={ev.get('anomaly_score',0)}"
    if agent_name == "topology_analyst":
        return "fetch topology"
    if agent_name == "causal_analyst":
        return f"method={state.get('causal_method','LPCMCI')}"
    if agent_name == "llm_diagnostician":
        fb = state.get("critic_feedback", "")
        return f"critic_feedback={'yes' if fb else 'no'}"
    if agent_name == "critic":
        rc = state.get("diagnosis_report", {}).get("root_cause", "?")
        return f"review diagnosis: {rc}"
    if agent_name == "risk_assessor":
        rc = state.get("diagnosis_report", {}).get("root_cause", "?")
        return f"assess risk for: {rc}"
    if agent_name == "remediation_executor":
        risk = state.get("risk_report", {}).get("risk_level", "?")
        return f"risk_level={risk}"
    return agent_name


def _build_output_summary(result: dict) -> str:
    """Build a one-line output summary."""
    if "plan" in result:
        return f"steps={result.get('plan', [])}"
    if "causal_graph" in result:
        cg = result.get("causal_graph", {})
        return f"edges={len(cg.get('edges', []))}"
    if "diagnosis_report" in result:
        dr = result.get("diagnosis_report", {})
        return f"root_cause={dr.get('root_cause','?')} conf={dr.get('confidence',0):.2f}"
    if "critic_feedback" in result:
        return f"approves={result.get('critic_approves')}"
    if "risk_report" in result:
        return f"risk={result.get('risk_report',{}).get('risk_level','?')}"
    if "execution_result" in result:
        return f"status={result.get('execution_result',{}).get('status','?')}"
    if "topology_snapshot" in result:
        ts = result.get("topology_snapshot", {})
        return f"nodes={ts.get('node_count',0)} edges={ts.get('edge_count',0)}"
    return summarize(result)
