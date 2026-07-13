# Multi-turn LLM Diagnosis — Iterative Root Cause Analysis
#
# Instead of a single LLM call, the diagnostician can request additional
# data (metrics, logs, topology details) and refine its diagnosis in
# subsequent turns — like a real SRE asking follow-up questions.

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from aetherops.core.llm_diagnosis import (
    DIAGNOSIS_SYSTEM_PROMPT,
    _build_diagnosis_prompt,
    _heuristic_diagnosis,
)
from aetherops.core.llm_provider import (
    DiagnosisReport,
    ProviderFactory,
    parse_llm_response,
)

logger = logging.getLogger(__name__)

# Max turns to prevent infinite loops (reduced from 3 to 2 for speed)
MAX_DIAGNOSIS_TURNS = 2


@dataclass
class DataRequest:
    """What the LLM asks for in a follow-up."""
    variable: str  # e.g. "mysql_query_latency_p99"
    service: str   # target service
    reason: str    # why this data helps
    metric_type: str = "prometheus"  # prometheus | topology | log


@dataclass
class MultiTurnResult:
    """Result of a multi-turn diagnosis session."""
    final_report: DiagnosisReport
    turn_count: int
    data_requests: List[DataRequest] = field(default_factory=list)
    intermediate_reports: List[DiagnosisReport] = field(default_factory=list)
    improved: bool = False  # whether multi-turn improved confidence


def diagnose_multi_turn(
    causal_graph: dict,
    anomaly_context: dict,
    model: str = "",
    metrics_fetcher=None,
    max_turns: int = MAX_DIAGNOSIS_TURNS,
) -> MultiTurnResult:
    """Run multi-turn LLM diagnosis with iterative refinement.

    Each turn:
      1. LLM produces a diagnosis + optionally requests additional data
      2. If data is requested, fetch it and inject into next turn
      3. Repeat until LLM is confident or max turns reached

    Args:
        causal_graph: Causal graph from causal discovery.
        anomaly_context: Topology + anomaly event context.
        model: Deprecated, kept for backwards compat. Provider is resolved from env.
        metrics_fetcher: Callable to fetch additional metrics.
        max_turns: Maximum diagnosis turns.

    Returns:
        MultiTurnResult with the final refined diagnosis.
    """
    provider = ProviderFactory.from_env()
    if provider is None:
        logger.warning("No LLM provider available, falling back to heuristic")
        report = _heuristic_diagnosis(causal_graph, anomaly_context)
        return MultiTurnResult(
            final_report=report,
            turn_count=0,
            improved=False,
        )

    # Build multi-turn system prompt
    system_prompt = DIAGNOSIS_SYSTEM_PROMPT + """

## Multi-Turn Protocol

You may request additional data in your response by including a `data_requests` field.

If you are NOT confident (confidence < 0.7), explain what additional data would help
and include a `data_requests` list. Each request should have:
  - "variable": what metric/data you need
  - "service": which service
  - "reason": why it helps
  - "metric_type": "prometheus" | "topology" | "log"

If you ARE confident (confidence >= 0.7), set data_requests to an empty list.

### Output Format (when requesting data)
```json
{
  "root_cause": "tentative-root-cause",
  "confidence": 0.45,
  "explanation": "Preliminary analysis...",
  "affected_services": [...],
  "recommended_actions": [...],
  "data_requests": [
    {
      "variable": "mysql_connection_pool_usage",
      "service": "mysql-0:3306",
      "reason": "To confirm connection pool exhaustion hypothesis",
      "metric_type": "prometheus"
    }
  ]
}
"""
    # Build initial user prompt — enhanced with data summary to reduce round-trips
    base_prompt = _build_diagnosis_prompt(causal_graph, anomaly_context)
    data_summary = (
        f"\n\nAvailable data: causal graph ({len(causal_graph.get('edges', []))} edges, "
        f"{len(causal_graph.get('nodes', []))} variables), "
        f"topology ({len(anomaly_context.get('topology', {}).get('nodes', []))} nodes, "
        f"{len(anomaly_context.get('topology', {}).get('edges', []))} edges)."
    )
    user_prompt = base_prompt + data_summary + """

IMPORTANT: Follow the Multi-Turn Protocol. If you need more data to be confident,
include a `data_requests` field. Only give a final diagnosis if confidence >= 0.7.
"""
    extra_context = ""
    turn = 0
    reports: List[DiagnosisReport] = []

    while turn < max_turns:
        turn += 1
        logger.info("Multi-turn diagnosis: turn %d/%d", turn, max_turns)

        # Build the full user message for this turn
        current_prompt = user_prompt
        if extra_context:
            current_prompt += f"\n\n## Additional Data (from previous turn)\n{extra_context}"
        current_prompt += f"\n\n(This is turn {turn}/{max_turns}. Be concise.)"

        try:
            raw = provider.chat(
                system_prompt=system_prompt,
                user_message=current_prompt,
                max_tokens=4096,
                temperature=0.3,
                timeout=120,
            )
            if raw is None:
                raise RuntimeError("provider.chat returned None")
        except Exception as e:
            logger.error("LLM call failed on turn %d: %s", turn, e)
            if reports:
                return MultiTurnResult(
                    final_report=reports[-1],
                    turn_count=turn,
                    intermediate_reports=reports,
                )
            report = _heuristic_diagnosis(causal_graph, anomaly_context)
            return MultiTurnResult(
                final_report=report,
                turn_count=0,
                improved=False,
            )

        # Parse response
        report = parse_llm_response(raw)
        reports.append(report)

        # Check if LLM requested more data
        data_requests = _extract_data_requests(raw)
        if not data_requests or report.confidence >= 0.7:
            # LLM is confident enough or doesn't need more data → done
            logger.info(
                "Multi-turn complete after %d turns. Confidence: %.2f",
                turn,
                report.confidence,
            )
            improved = turn > 1 and report.confidence > reports[0].confidence
            return MultiTurnResult(
                final_report=report,
                turn_count=turn,
                data_requests=data_requests,
                intermediate_reports=reports,
                improved=improved,
            )

        # LLM wants more data — fetch it
        logger.info(
            "LLM requested %d additional data points (confidence=%.2f)",
            len(data_requests),
            report.confidence,
        )
        extra_context = _fetch_requested_data(data_requests, metrics_fetcher)

    # Max turns reached — return last report
    final = reports[-1] if reports else _heuristic_diagnosis(causal_graph, anomaly_context)
    improved = len(reports) >= 2 and final.confidence > reports[0].confidence
    return MultiTurnResult(
        final_report=final,
        turn_count=turn,
        intermediate_reports=reports,
        improved=improved,
    )


def _extract_data_requests(raw: str) -> List[DataRequest]:
    """Extract data_requests from LLM response JSON."""
    try:
        if "```json" in raw:
            json_str = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            json_str = raw.split("```")[1].split("```")[0].strip()
        else:
            json_str = raw[raw.find("{") : raw.rfind("}") + 1]

        data = json.loads(json_str)
        requests_raw = data.get("data_requests", [])
        return [
            DataRequest(
                variable=r.get("variable", ""),
                service=r.get("service", ""),
                reason=r.get("reason", ""),
                metric_type=r.get("metric_type", "prometheus"),
            )
            for r in requests_raw
        ]
    except (json.JSONDecodeError, KeyError, ValueError):
        return []


def _fetch_requested_data(
    requests: List[DataRequest],
    metrics_fetcher=None,
) -> str:
    """Fetch the data requested by the LLM and format it as context text."""
    lines = ["### Requested Data\n"]
    for req in requests:
        lines.append(f"- **{req.variable}** for `{req.service}` ({req.metric_type})")

        if metrics_fetcher and req.metric_type == "prometheus":
            try:
                data = metrics_fetcher(req.variable, req.service)
                lines.append(f"  → {data[:200]}" if data else "  → (no data returned)")
            except Exception as e:
                lines.append(f"  → fetch failed: {e}")
        else:
            lines.append(f"  → (reason: {req.reason})")

    return "\n".join(lines)
