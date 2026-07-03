"""
AetherOps — MCP client for the Go data plane.

Communicates with the Go-side MCP server over HTTP SSE transport
using JSON-RPC 2.0. Replaces the gRPC client with the Model Context
Protocol (MCP) standard.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, AsyncIterator, Generator, List, Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class TopologySnapshot:
    nodes: List[dict]
    edges: List[dict]
    node_count: int
    edge_count: int
    timestamp_unix_nano: int


@dataclass
class AnomalyEvent:
    node_id: str
    anomaly_score: float
    avg_latency_ms: float
    call_count: int
    suspect_chain: List[str]
    timestamp_unix_nano: int


class MCPClient:
    """MCP client connecting to the ebpf-autoheal Go side via MCP protocol."""

    def __init__(self, address: str = "http://localhost:50052"):
        self.base_url = address.rstrip("/")
        self.messages_url = self.base_url + "/messages"
        self.sse_url = self.base_url + "/sse"
        self._client: Optional[httpx.Client] = None
        self._request_id = 0

    def connect(self) -> None:
        """Establish connection to MCP server via SSE endpoint discovery."""
        self._client = httpx.Client(timeout=30.0)
        # Probe SSE once to validate connectivity (non-blocking discovery)
        try:
            with self._client.stream("GET", self.sse_url) as resp:
                for line in resp.iter_lines():
                    if line.startswith("event:"):
                        break
        except Exception as e:
            logger.debug("SSE discovery: %s (proceeding with HTTP POST)", e)
        logger.info("Connected to AetherOps MCP at %s", self.base_url)

    def close(self) -> None:
        if self._client:
            self._client.close()

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _call_tool(self, name: str, arguments: dict | None = None) -> dict:
        """Call an MCP tool via JSON-RPC 2.0."""
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments or {},
            },
        }
        resp = self._client.post(self.messages_url, json=payload)
        resp.raise_for_status()
        result = resp.json()

        if "error" in result and result["error"]:
            err = result["error"]
            raise RuntimeError(f"MCP error [{err['code']}]: {err['message']}")

        # Extract text content from MCP response envelope.
        content = result.get("result", {}).get("content", [])
        for item in content:
            if item.get("type") == "text":
                return json.loads(item["text"])
        return result.get("result", {})

    def _list_tools(self) -> list:
        """List available MCP tools (used for discovery/healthcheck)."""
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/list",
        }
        resp = self._client.post(self.messages_url, json=payload)
        resp.raise_for_status()
        result = resp.json()
        if "error" in result and result["error"]:
            err = result["error"]
            raise RuntimeError(f"MCP error [{err['code']}]: {err['message']}")
        return result.get("result", {}).get("tools", [])

    # ── Topology API ──

    def get_topology(self, include_healthy: bool = False) -> TopologySnapshot:
        """Fetch current service graph via MCP."""
        result = self._call_tool("get_topology", {"include_healthy": include_healthy})

        nodes = result.get("nodes", [])
        edges = result.get("edges", [])

        return TopologySnapshot(
            nodes=nodes,
            edges=edges,
            node_count=result.get("node_count", len(nodes)),
            edge_count=result.get("edge_count", len(edges)),
            timestamp_unix_nano=result.get("timestamp_nano", 0),
        )

    # ── Remediation API ──

    def evaluate_remediation(self, target_node: str, action: str) -> dict:
        """Evaluate blast radius via MCP."""
        result = self._call_tool("evaluate_remediation", {
            "target_node": target_node,
            "action": action,
        })
        # Map MCP field names back to the expected Python dict keys.
        return {
            "target_node": result.get("target_node", ""),
            "action": result.get("action", ""),
            "risk_level": result.get("risk_level", ""),
            "affected_upstream_count": result.get("affected_up", 0),
            "affected_downstream_count": result.get("affected_down", 0),
            "affected_services": result.get("affected_services", []),
            "estimated_error_budget_consumption": result.get("error_budget_pct", 0.0),
            "estimated_downtime_seconds": result.get("downtime_sec", 0),
            "recommendation": result.get("recommendation", ""),
        }

    def execute_remediation(
        self, target_node: str, action: str, force: bool = False
    ) -> dict:
        """Execute a remediation action via MCP."""
        result = self._call_tool("execute_remediation", {
            "target_node": target_node,
            "action": action,
            "force": force,
        })
        return {
            "accepted": result.get("accepted", False),
            "execution_id": result.get("execution_id", ""),
            "status": result.get("status", ""),
            "details": result.get("details", ""),
        }

    # ── Anomaly Subscription (SSE stream) ──

    def subscribe_anomalies(
        self, min_score: float = 0.5
    ) -> Generator[AnomalyEvent, None, None]:
        """Stream anomaly events over SSE, yielding AnomalyEvent objects.

        Connects to the MCP server's SSE endpoint and filters for anomaly-type
        events. This is a blocking generator meant for daemon-mode use.
        """
        with httpx.Client(timeout=None) as sse_client:
            logger.info("Subscribing to anomaly SSE stream at %s", self.sse_url)
            with sse_client.stream("GET", self.sse_url) as resp:
                for line in resp.iter_lines():
                    line = line.strip()
                    if not line.startswith("data:"):
                        continue
                    payload = line[5:].strip()
                    try:
                        msg = json.loads(payload)
                    except json.JSONDecodeError:
                        continue

                    # Check for anomaly-type events.
                    if msg.get("type") != "anomaly":
                        continue

                    data = msg.get("data", {})
                    score = data.get("anomaly_score", 0)
                    if score < min_score:
                        continue

                    yield AnomalyEvent(
                        node_id=data.get("node_id", ""),
                        anomaly_score=score,
                        avg_latency_ms=data.get("avg_latency_ms", 0.0),
                        call_count=data.get("call_count", 0),
                        suspect_chain=data.get("suspect_chain", []),
                        timestamp_unix_nano=int(time.time() * 1e9),
                    )
