"""
AetherOps — MCP client for the Go data plane using the official MCP SDK.

Connects to the Go MCP server via SSE transport, discovers available tools
and resources dynamically, and provides typed wrappers for the cognitive plane.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, AsyncIterator, List, Optional

from mcp import ClientSession
from mcp.client.sse import sse_client

logger = logging.getLogger(__name__)

# ── Synchronous bridge for async MCP operations ──
# LangGraph workflow nodes are synchronous, but the MCP SDK is async.
# We maintain a dedicated background event loop so sync code can call
# async MCP methods via run_async().

_BG_LOOP: Optional[asyncio.AbstractEventLoop] = None
_BG_THREAD: Optional[threading.Thread] = None
_BG_LOCK = threading.Lock()


def _start_bg_loop() -> asyncio.AbstractEventLoop:
    """Start a dedicated daemon thread with its own event loop for MCP ops."""
    global _BG_LOOP, _BG_THREAD
    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_forever, daemon=True, name="mcp-bg-loop")
    t.start()
    _BG_LOOP = loop
    _BG_THREAD = t
    return loop


def get_bg_loop() -> asyncio.AbstractEventLoop:
    """Return the persistent background event loop, creating it if needed."""
    global _BG_LOOP
    if _BG_LOOP is None or not _BG_LOOP.is_running():
        with _BG_LOCK:
            if _BG_LOOP is None or not _BG_LOOP.is_running():
                return _start_bg_loop()
    return _BG_LOOP


def run_async(coro, loop: Optional[asyncio.AbstractEventLoop] = None):
    """Run an async coroutine synchronously on the background MCP event loop.

    Safe to call from any thread (including threads with their own running
    event loop).  The coroutine is dispatched to a dedicated background loop
    and the calling thread blocks until it completes.
    """
    if loop is None:
        loop = get_bg_loop()
    return asyncio.run_coroutine_threadsafe(coro, loop).result()


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
    """MCP client connecting to the AetherOps Go data plane via the official MCP SDK.

    Uses stdin/stdout or SSE transport to communicate with the MCP server.
    Tools and resources are discovered dynamically at connection time.
    """

    def __init__(self, address: str = "http://localhost:50052"):
        self.address = address.rstrip("/")
        self._sse_url = f"{self.address}/sse"
        self._session: Optional[ClientSession] = None
        self._sse_ctx = None
        self._tools: List[dict] = []
        self._resources: List[dict] = []

    async def connect(self) -> None:
        """Establish connection and discover available tools/resources."""
        self._sse_ctx = sse_client(self._sse_url)
        read, write = await self._sse_ctx.__aenter__()
        self._session = ClientSession(read, write)
        await self._session.__aenter__()
        await self._session.initialize()

        # Discover tools and resources
        tools_result = await self._session.list_tools()
        self._tools = [t.model_dump() for t in tools_result.tools] if tools_result.tools else []

        try:
            resources_result = await self._session.list_resources()
            self._resources = [r.model_dump() for r in resources_result.resources] if resources_result.resources else []
        except Exception:
            self._resources = []

        logger.info(
            "Connected to AetherOps MCP at %s — %d tools, %d resources",
            self.address,
            len(self._tools),
            len(self._resources),
        )

    def close(self) -> None:
        """Close the MCP session synchronously."""
        if self._session or self._streams:
            try:
                run_async(self._async_close())
            except Exception:
                pass

    async def _async_close(self) -> None:
        if self._session:
            try:
                await self._session.__aexit__(None, None, None)
            except Exception:
                pass
            self._session = None
        if self._sse_ctx:
            try:
                await self._sse_ctx.__aexit__(None, None, None)
            except Exception:
                pass
            self._sse_ctx = None

    def list_discovered_tools(self) -> List[dict]:
        """Return the list of tools discovered during connect()."""
        return self._tools

    def list_discovered_resources(self) -> List[dict]:
        """Return the list of resources discovered during connect()."""
        return self._resources

    async def _call_tool(self, name: str, arguments: dict | None = None) -> dict:
        """Call an MCP tool and return the parsed JSON result."""
        if not self._session:
            raise RuntimeError("MCP client not connected — call connect() first")

        result = await self._session.call_tool(name, arguments or {})
        # Result content is a list of TextContent/ImageContent/etc.
        if result.content:
            for item in result.content:
                if item.type == "text":
                    try:
                        return json.loads(item.text)
                    except (json.JSONDecodeError, TypeError):
                        return {"text": item.text}
        if result.structuredContent:
            return result.structuredContent
        return {}

    # ── Topology API ──

    async def get_topology(self, include_healthy: bool = False) -> TopologySnapshot:
        """Fetch current service graph via MCP."""
        result = await self._call_tool("get_topology", {"include_healthy": include_healthy})
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

    async def evaluate_remediation(self, target_node: str, action: str) -> dict:
        """Evaluate blast radius via MCP."""
        result = await self._call_tool("evaluate_remediation", {
            "target_node": target_node,
            "action": action,
        })
        return {
            "target_node": result.get("target_node", ""),
            "action": result.get("action", ""),
            "risk_level": result.get("risk_level", ""),
            "affected_upstream_count": result.get("affected_upstream", 0),
            "affected_downstream_count": result.get("affected_downstream", 0),
            "affected_services": result.get("affected_services", []),
            "estimated_error_budget_consumption": result.get("error_budget_pct", 0.0),
            "estimated_downtime_seconds": result.get("downtime_sec", 0),
            "recommendation": result.get("recommendation", ""),
        }

    async def execute_remediation(self, target_node: str, action: str, force: bool = False) -> dict:
        """Execute a remediation action via MCP."""
        result = await self._call_tool("execute_remediation", {
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

    # ── Policy API ──

    async def check_policy(self, action: str, target_node: str, target_ip: str = "", namespace: str = "") -> dict:
        """Evaluate a remediation action against active policies."""
        return await self._call_tool("check_policy", {
            "action": action,
            "target_node": target_node,
            "target_ip": target_ip,
            "namespace": namespace,
        })

    async def list_policies(self) -> dict:
        """List all active policy rules."""
        return await self._call_tool("list_policies", {})

    # ── Anomaly Subscription (SSE notifications) ──

    async def subscribe_anomalies(self, min_score: float = 0.5) -> AsyncIterator[AnomalyEvent]:
        """Connect to the SSE stream and yield anomaly notifications as they arrive.

        This is an async generator — use ``async for event in client.subscribe_anomalies():``.

        MCP notifications follow JSON-RPC 2.0 with the ``notifications/events/anomaly``
        method, matching the events published by PublishAnomalyNotification in the Go
        data plane.
        """
        import httpx

        sse_url = f"{self.address}/sse"
        logger.info("Subscribing to anomaly SSE stream at %s", sse_url)

        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream("GET", sse_url) as resp:
                async for line in resp.aiter_lines():
                    line = line.strip()
                    if not line.startswith("data:"):
                        continue
                    payload = line[5:].strip()
                    try:
                        msg = json.loads(payload)
                    except json.JSONDecodeError:
                        continue

                    if not isinstance(msg, dict):
                        continue
                    if msg.get("method") == "notifications/events/anomaly":
                        params = msg.get("params", {})
                        score = params.get("anomaly_score", 0)
                        if score < min_score:
                            continue
                        yield AnomalyEvent(
                            node_id=params.get("node_id", ""),
                            anomaly_score=score,
                            avg_latency_ms=params.get("avg_latency_ms", 0.0),
                            call_count=params.get("call_count", 0),
                            suspect_chain=params.get("suspect_chain", []),
                            timestamp_unix_nano=params.get("timestamp_nano", int(time.time() * 1e9)),
                        )
