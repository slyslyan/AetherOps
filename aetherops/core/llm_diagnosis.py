"""
AetherOps — Multi-modal LLM Diagnosis Agent.

Receives causal graph + anomaly context + optional Grafana screenshots,
and produces a structured diagnosis report with root cause explanation
and remediation recommendations.
"""

from __future__ import annotations

import json
import logging
from typing import List, Optional

from aetherops.core.llm_provider import (
    DiagnosisReport,
    LLMProvider,
    ProviderFactory,
)

logger = logging.getLogger(__name__)

# Heuristic fallback counter — incremented when LLM is unavailable or fails
_heuristic_fallback_count = 0


def _count_heuristic_fallback():
    global _heuristic_fallback_count
    _heuristic_fallback_count += 1
    logger.warning(
        "LLM unavailable, using heuristic diagnosis (fallback #%d)",
        _heuristic_fallback_count,
    )


DIAGNOSIS_SYSTEM_PROMPT = """\
You are an SRE diagnosing a microservice outage from eBPF causal graph + anomaly data.
Return ONLY ```json, no other text.

```json
{
  "root_cause": "service-name",
  "confidence": 0.85,
  "explanation": "...",
  "affected_services": ["..."],
  "recommended_actions": [
    {"action": "TC_DROP|POD_RESTART|SCALE_UP|CONFIG_CHANGE|IMAGE_ROLLBACK", "target": "...", "risk": "LOW|MEDIUM|HIGH", "rationale": "..."}
  ]
}
```

Rules: confidence 0-1, cite specific lat/err metrics, max 3 actions.

Patterns (quick reference):
- DB slow: hi P95 on db edges, normal CPU → CONFIG_CHANGE or POD_RESTART
- Cache storm: multi-svc spike, hi err rate → SCALE_UP then CONFIG_CHANGE
- Network loss: all edges from one src elevated → TC_DROP then POD_RESTART
- Resource exhaust: gradual ramp, retry storm → SCALE_UP then POD_RESTART
- Hotspot: isolated P95 spike, single node → CONFIG_CHANGE or IMAGE_ROLLBACK

Risk: TC_DROP/SCALE_UP=LOW, POD_RESTART/CONFIG_CHANGE=MEDIUM, IMAGE_ROLLBACK=HIGH
"""


def diagnose(
    causal_graph: dict,
    anomaly_context: dict,
    provider: Optional[LLMProvider] = None,
    include_screenshots: bool = False,
    screenshot_paths: Optional[List[str]] = None,
) -> DiagnosisReport:
    """
    Run LLM diagnosis on the causal graph and anomaly context.

    Uses the injected ``provider``; falls back to ``ProviderFactory.from_env()``.
    If no provider is available, runs heuristic diagnosis.

    Args:
        causal_graph: Dict with nodes, edges from causal discovery.
        anomaly_context: Dict with topology snapshot, anomaly events, metrics.
        provider: Optional LLMProvider instance. If None, auto-create from env.
        include_screenshots: If True, include base64-encoded Grafana screenshots.
        screenshot_paths: Paths to screenshot images.

    Returns:
        DiagnosisReport with root cause analysis.
    """
    if provider is None:
        provider = ProviderFactory.from_env()

    if provider is None:
        _count_heuristic_fallback()
        return _heuristic_diagnosis(causal_graph, anomaly_context)

    # Build the prompt payload.
    user_message = _build_diagnosis_prompt(causal_graph, anomaly_context)

    # If multi-modal is enabled and screenshots exist, build rich content.
    final_user_message = user_message
    if include_screenshots and screenshot_paths:
        from .screenshot_utils import encode_screenshots

        image_content = encode_screenshots(screenshot_paths)
        final_user_message = json.dumps([
            {"type": "text", "text": user_message},
            *[{"type": "image_url", "image_url": {"url": f"data:image/png;base64,{img}"}}
              for img in image_content],
        ])

    report = provider.diagnose(DIAGNOSIS_SYSTEM_PROMPT, final_user_message)
    if report is not None:
        return report

    _count_heuristic_fallback()
    return _heuristic_diagnosis(causal_graph, anomaly_context)


MAX_USER_MSG_CHARS = 4000  # ~1000 tokens, prevent topology explosion


def _build_diagnosis_prompt(causal_graph: dict, anomaly_context: dict) -> str:
    """Build a compact user message, truncating large topologies."""
    # Limit edges to the top 20 by anomaly score to avoid token explosion
    cg = dict(causal_graph)
    if len(cg.get("edges", [])) > 20:
        cg["edges"] = sorted(cg["edges"], key=lambda e: e.get("anomaly_score", 0), reverse=True)[:20]
        cg["_truncated"] = True

    # Strip verbose fields from anomaly context
    ac = {}
    evt = anomaly_context.get("anomaly_event", {})
    if evt:
        ac["node"] = evt.get("node_id", "")
        ac["score"] = evt.get("anomaly_score", 0)
        ac["lat"] = evt.get("avg_latency_ms", 0)
        ac["chain"] = evt.get("suspect_chain", [])[:10]
    topo = anomaly_context.get("topology", {})
    if topo:
        ac["nodes"] = topo.get("node_count", 0)
        ac["edges"] = topo.get("edge_count", 0)

    cg_str = json.dumps(cg, separators=(",", ":"), default=str)
    ac_str = json.dumps(ac, separators=(",", ":"), default=str)
    msg = f"causal:{cg_str}\nanomaly:{ac_str}"
    if len(msg) > MAX_USER_MSG_CHARS:
        msg = msg[:MAX_USER_MSG_CHARS] + "..."
    return msg


def _heuristic_diagnosis(causal_graph: dict, anomaly_context: dict) -> DiagnosisReport:
    """Fallback heuristic when LLM is unavailable."""
    edges = causal_graph.get("edges", [])
    nodes = causal_graph.get("nodes", [])

    # Simple heuristic: node with most outgoing edges in causal graph is root cause.
    outgoing: dict[str, int] = {}
    seen_dsts: set[str] = set()
    for edge in edges:
        src = edge.get("src", "")
        dst = edge.get("dst", "")
        if src:
            outgoing[src] = outgoing.get(src, 0) + 1
        if dst:
            seen_dsts.add(dst)

    root_cause = max(outgoing, key=outgoing.get) if outgoing else (nodes[0] if nodes else "unknown")

    return DiagnosisReport(
        root_cause=root_cause,
        confidence=0.4,
        explanation=f"Heuristic diagnosis: {root_cause} has the most causal outgoing edges ({outgoing.get(root_cause, 0)}).",
        affected_services=list(seen_dsts),
        recommended_actions=[
            {"action": "TC_DROP", "target": root_cause, "risk": "LOW", "rationale": "Automatic TC circuit break based on heuristic."}
        ],
    )
