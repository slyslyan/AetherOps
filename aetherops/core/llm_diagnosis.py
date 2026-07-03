"""
AetherOps — Multi-modal LLM Diagnosis Agent.

Receives causal graph + anomaly context + optional Grafana screenshots,
and produces a structured diagnosis report with root cause explanation
and remediation recommendations.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class DiagnosisReport:
    root_cause: str
    confidence: float
    explanation: str
    affected_services: List[str]
    recommended_actions: List[dict]
    raw_llm_response: str = ""


# Default system prompt for the diagnosis agent.
# Includes known fault patterns for precise remediation recommendations.
DIAGNOSIS_SYSTEM_PROMPT = """You are an expert SRE reliability engineer diagnosing a microservice outage.

## Input Data
You will receive:
1. A causal graph showing the inferred relationships between services
2. Anomaly scores and latency metrics for affected services
3. The current service topology from eBPF kernel probes

## Your Task
1. Analyze the causal chain to identify the ROOT CAUSE service
2. Explain why this service is the root cause (what evidence supports it)
3. Rank the affected services by severity
4. Propose remediation actions (max 3), ordered by risk

## Output Format
Return a JSON object with:
```json
{
  "root_cause": "service-name",
  "confidence": 0.85,
  "explanation": "Detailed step-by-step reasoning...",
  "affected_services": ["svc-a", "svc-b"],
  "recommended_actions": [
    {"action": "POD_RESTART", "target": "svc-a", "risk": "MEDIUM", "rationale": "..."},
    ...
  ]
}
```

## Quality Checklist
- Confidence must be between 0 and 1
- Explanations must reference specific metrics (latency, error rate, QPS drops)
- Actions must map to one of: TC_DROP, POD_RESTART, SCALE_UP, CONFIG_CHANGE, IMAGE_ROLLBACK

## Known Fault Patterns (Use as Reference)

### Pattern 1: Database Slow Query
- **Symptoms**: High P95 latency on downstream db/redis edges, normal CPU, low QPS drop
- **Causal signature**: db-service appears as root cause with multiple dependents impacted
- **Recommended action**: CONFIG_CHANGE (connection pool tuning) or POD_RESTART (if connection leak)
- **Key metric to check**: p95_latency_ms >> avg_latency_ms, high spread

### Pattern 2: Cache Avalanche / Cache Miss Storm
- **Symptoms**: Sudden latency spike across multiple services simultaneously, high error rate, QPS drop
- **Causal signature**: No single root cause — many edges show co-elevated anomaly
- **Recommended action**: SCALE_UP (to handle origin load surge), then CONFIG_CHANGE (cache TTL tuning)
- **Key metric to check**: error_rate elevates before latency in time series

### Pattern 3: Network Congestion / Packet Loss
- **Symptoms**: Latency increase on ALL outgoing edges from a node, TCP retransmits, connection resets
- **Causal signature**: Upstream services show correlated elevation; no single dependent stands out
- **Recommended action**: TC_DROP (circuit break on offending upstream), then POD_RESTART (connection pool flush)
- **Key metric to check**: error_rate and latency jointly elevated across all edges of same src

### Pattern 4: Resource Exhaustion (CPU/Memory/Connection Pool)
- **Symptoms**: Latency increases gradually (ramp-up pattern), CallCount may increase (retry storm)
- **Causal signature**: Root cause node has high anomaly score but its dependents show cascading failures
- **Recommended action**: SCALE_UP (immediate capacity), followed by POD_RESTART (if memory leak)
- **Key metric to check**: call_count increasing (retries) while latency also climbing

### Pattern 5: Inefficient Algorithm / Hot Spot
- **Symptoms**: Isolated P95 spike on a single service, no downstream dependency chain
- **Causal signature**: Single node anomaly with no causal edges to others
- **Recommended action**: CONFIG_CHANGE (feature flag flip) or IMAGE_ROLLBACK
- **Key metric to check**: avg_latency_ms may be normal while P95 is very high

### Remediation Risk Guidance
- TC_DROP: LOW risk — always safe for circuit break
- SCALE_UP: LOW risk — increases replica count
- POD_RESTART: MEDIUM risk — brief connection drain, safe with retries
- CONFIG_CHANGE: MEDIUM risk — parameter tuning, monitor before/after
- IMAGE_ROLLBACK: HIGH risk — requires approval, last resort
"""


def diagnose(
    causal_graph: dict,
    anomaly_context: dict,
    model: str = "deepseek-v4-flash",
    include_screenshots: bool = False,
    screenshot_paths: Optional[List[str]] = None,
) -> DiagnosisReport:
    """
    Run LLM diagnosis on the causal graph and anomaly context.

    Args:
        causal_graph: Dict with nodes, edges from causal discovery.
        anomaly_context: Dict with topology snapshot, anomaly events, metrics.
        model: LLM model identifier.
        include_screenshots: If True, include base64-encoded Grafana screenshots.
        screenshot_paths: Paths to screenshot images.

    Returns:
        DiagnosisReport with root cause analysis.
    """
    api_key = os.environ.get("LLM_API_KEY")
    if not api_key:
        logger.warning("LLM_API_KEY not set, returning heuristic diagnosis")
        return _heuristic_diagnosis(causal_graph, anomaly_context)

    # Build the prompt payload.
    user_message = _build_diagnosis_prompt(causal_graph, anomaly_context)

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": DIAGNOSIS_SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
        "max_tokens": 4096,
        "temperature": 0.3,
    }

    # If multi-modal is enabled and screenshots exist, add image content.
    if include_screenshots and screenshot_paths:
        from .screenshot_utils import encode_screenshots

        image_content = encode_screenshots(screenshot_paths)
        user_message_with_images = [
            {"type": "text", "text": user_message},
            *[{"type": "image_url", "image_url": {"url": f"data:image/png;base64,{img}"}}
              for img in image_content],
        ]
        payload["messages"][1] = {
            "role": "user",
            "content": user_message_with_images,
        }

    try:
        resp = httpx.post(
            os.environ.get("LLM_API_URL", "https://api.deepseek.com/v1/chat/completions"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        result = resp.json()
        raw = result["choices"][0]["message"]["content"]
        return _parse_llm_response(raw)

    except httpx.TimeoutException:
        logger.error("LLM request timed out after 120s")
        return _heuristic_diagnosis(causal_graph, anomaly_context)
    except Exception as e:
        logger.error("LLM diagnosis failed: %s", e)
        return _heuristic_diagnosis(causal_graph, anomaly_context)


def _build_diagnosis_prompt(causal_graph: dict, anomaly_context: dict) -> str:
    """Build the user message for LLM diagnosis."""
    sections = [
        "## Causal Graph",
        json.dumps(causal_graph, indent=2),
        "",
        "## Anomaly Context",
        json.dumps(anomaly_context, indent=2),
        "",
        "Please analyze and return a structured diagnosis report as JSON.",
    ]
    return "\n".join(sections)


def _parse_llm_response(raw: str) -> DiagnosisReport:
    """Parse LLM response into a structured DiagnosisReport."""
    # Try to extract JSON from the response.
    try:
        # Find JSON block (between triple backticks or first { to last }).
        if "```json" in raw:
            json_str = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            json_str = raw.split("```")[1].split("```")[0].strip()
        else:
            json_str = raw[raw.find("{") : raw.rfind("}") + 1]

        data = json.loads(json_str)
        return DiagnosisReport(
            root_cause=data.get("root_cause", "unknown"),
            confidence=data.get("confidence", 0.5),
            explanation=data.get("explanation", ""),
            affected_services=data.get("affected_services", []),
            recommended_actions=data.get("recommended_actions", []),
            raw_llm_response=raw,
        )
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logger.warning("Failed to parse LLM response as JSON: %s", e)
        return DiagnosisReport(
            root_cause="unknown",
            confidence=0.0,
            explanation=raw,
            affected_services=[],
            recommended_actions=[],
            raw_llm_response=raw,
        )


def _heuristic_diagnosis(causal_graph: dict, anomaly_context: dict) -> DiagnosisReport:
    """Fallback heuristic when LLM is unavailable."""
    edges = causal_graph.get("edges", [])
    nodes = causal_graph.get("nodes", [])

    # Simple heuristic: node with most outgoing edges in causal graph is root cause.
    outgoing = {}
    for src, dst, _ in edges:
        outgoing[src] = outgoing.get(src, 0) + 1

    root_cause = max(outgoing, key=outgoing.get) if outgoing else (nodes[0] if nodes else "unknown")

    return DiagnosisReport(
        root_cause=root_cause,
        confidence=0.4,
        explanation=f"Heuristic diagnosis: {root_cause} has the most causal outgoing edges ({outgoing.get(root_cause, 0)}).",
        affected_services=[d for s, d, _ in edges],
        recommended_actions=[
            {"action": "TC_DROP", "target": root_cause, "risk": "LOW", "rationale": "Automatic TC circuit break based on heuristic."}
        ],
    )
