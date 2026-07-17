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

from anyio.streams.memory import MemoryObjectReceiveStream
from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCNotification

logger = logging.getLogger(__name__)

# ── Synchronous bridge for async MCP operations ──
# LangGraph workflow nodes are synchronous, but the MCP SDK is async.
# We maintain a dedicated background event loop so sync code can call
# async MCP methods via run_async().

_BG_LOOP: Optional[asyncio.AbstractEventLoop] = None
_BG_THREAD: Optional[threading.Thread] = None
_BG_LOCK = threading.Lock()

# The event loop on which the MCP session was created.
# run_async must dispatch coroutines to THIS loop (not the background loop)
# because the session's _receive_loop and SSE tasks run here, and anyio memory
# streams are bound to a single event loop.
_SESSION_LOOP: Optional[asyncio.AbstractEventLoop] = None


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


def stop_bg_loop():
    """Stop the background event loop and wait for the thread to finish."""
    global _BG_LOOP, _BG_THREAD
    loop = _BG_LOOP
    thread = _BG_THREAD
    _BG_LOOP = None
    _BG_THREAD = None
    if loop is not None and loop.is_running():
        loop.call_soon_threadsafe(loop.stop)
    if thread is not None and thread.is_alive():
        thread.join(timeout=5)


def run_async(coro, loop: Optional[asyncio.AbstractEventLoop] = None):
    """Run an async coroutine synchronously, blocking the calling thread.

    Dispatches to *loop* if given, otherwise to the session's event loop
    (``_SESSION_LOOP``), falling back to a dedicated background loop.  Using the
    session loop is critical because anyio memory streams are bound to a single
    event loop — cross-loop usage causes a deadlock.
    """
    if loop is None:
        loop = _SESSION_LOOP or get_bg_loop()
    return asyncio.run_coroutine_threadsafe(coro, loop).result()


# ── Anomaly notification interceptor ──
# The Python MCP SDK uses a strict RootModel union for ServerNotification
# (CancelledNotification | ProgressNotification | LoggingMessageNotification |
#  ResourceUpdatedNotification | ...).  Any custom notification method like
# "notifications/events/anomaly" fails model_validate in _receive_loop and is
# silently dropped with a warning before ClientSession._received_notification
# is ever called.
#
# We intercept at the stream level: before the session's _receive_loop sees
# each message, we check if it is an anomaly JSON-RPC notification and, if so,
# hand it to the callback and skip forwarding it to the session.


class _AnomalyFilter:
    """Wraps a read stream to intercept anomaly notifications.

    Messages whose JSON-RPC method is ``notifications/events/anomaly`` are
    routed to *on_anomaly* instead of being forwarded to the session (which
    would drop them during ServerNotification validation).

    Implements the anyio MemoryObjectReceiveStream protocol so the session's
    ``_receive_loop`` can iterate over it with ``async for`` and enter it as
    an async context manager.
    """

    def __init__(self, inner: MemoryObjectReceiveStream, on_anomaly):
        self._inner = inner
        self._on_anomaly = on_anomaly

    # ── ObjectReceiveStream protocol ──

    async def receive(self):
        while True:
            msg = await self._inner.receive()
            if isinstance(msg, SessionMessage):
                root = msg.message.root
                if isinstance(root, JSONRPCNotification):
                    if root.method == "notifications/events/anomaly":
                        self._on_anomaly(root.params or {})
                        continue
            return msg

    def receive_nowait(self):
        return self._inner.receive_nowait()

    def clone(self):
        return _AnomalyFilter(self._inner.clone(), self._on_anomaly)

    def statistics(self):
        return self._inner.statistics()

    # ── AsyncResource protocol (required by async with) ──

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass  # owned by the SSE context; close is handled at the SSE level

    async def aclose(self):
        await self._inner.aclose()

    def close(self):
        self._inner.close()

    # ── Extended attributes (TypedAttributeProvider) ──

    def extra(self, key, default=None):
        return getattr(self._inner, 'extra', lambda k, d: d)(key, default)

    def extra_attributes(self):
        return getattr(self._inner, 'extra_attributes', lambda: {})()

    # ── Async iteration ──

    def __aiter__(self):
        return self

    async def __anext__(self):
        return await self.receive()


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

    Uses SSE transport to communicate with the MCP server.
    Tools and resources are discovered dynamically at connection time.
    """

    def __init__(self, address: str = "http://localhost:50052"):
        self.address = address.rstrip("/")
        self._sse_url = f"{self.address}/sse"
        self._session: Optional[ClientSession] = None
        self._sse_ctx = None
        self._tools: List[dict] = []
        self._resources: List[dict] = []
        self._anomaly_queue = asyncio.Queue()

    async def connect(self) -> None:
        """Establish connection and discover available tools/resources."""
        global _SESSION_LOOP
        _SESSION_LOOP = asyncio.get_running_loop()
        self._sse_ctx = sse_client(self._sse_url)
        read, write = await self._sse_ctx.__aenter__()
        # Wrap read stream to intercept anomaly notifications before the
        # session's strict ServerNotification validation drops them.
        read = _AnomalyFilter(read, self._on_anomaly)
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
        if self._session or self._sse_ctx:
            try:
                run_async(self._async_close())
            except Exception:
                pass

    async def _async_close(self) -> None:
        global _SESSION_LOOP
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
        _SESSION_LOOP = None

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

    # ── Anomaly Subscription (SSE notification interceptor) ──

    def _on_anomaly(self, params: dict) -> None:
        """Called by _AnomalyFilter when an anomaly notification is intercepted."""
        self._anomaly_queue.put_nowait(params)

    async def subscribe_anomalies(self, min_score: float = 0.5) -> AsyncIterator[AnomalyEvent]:
        """Subscribe to anomaly notifications via the MCP session.

        Anomaly notifications are intercepted at the stream level by
        _AnomalyFilter, which catches them before the MCP SDK's strict
        ServerNotification validation would drop them.
        """
        logger.info("Subscribing to anomaly events (min_score=%.2f)", min_score)

        while True:
            try:
                params = await self._anomaly_queue.get()
            except Exception as e:
                logger.error("Anomaly queue error: %s", e)
                break

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
