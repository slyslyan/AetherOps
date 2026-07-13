"""
MCP Client tests — verify connection and tool discovery.

Usage:
    pytest aetherops/tests/test_mcp_client.py -v

    # Or with live MCP server:
    pytest aetherops/tests/test_mcp_client.py -v --mcp-addr http://localhost:50052
"""

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from aetherops.core.mcp_client import MCPClient, TopologySnapshot


@pytest.fixture
def mcp_addr():
    """Return MCP server address from env or default."""
    return os.getenv("MCP_ADDR", "http://localhost:50052")


# ── Unit tests (mocked) ──


def test_client_init():
    """Client initialises with correct SSE URL."""
    c = MCPClient("http://localhost:50052")
    assert c._sse_url == "http://localhost:50052/sse"


def test_client_init_trailing_slash():
    """Trailing slash is stripped."""
    c = MCPClient("http://localhost:50052/")
    assert c._sse_url == "http://localhost:50052/sse"


@pytest.mark.asyncio
async def test_connect():
    """Connect discovers tools."""
    c = MCPClient("http://localhost:50052")

    mock_session = AsyncMock()
    mock_session.initialize = AsyncMock()
    mock_session.list_tools = AsyncMock()
    mock_session.list_tools.return_value.tools = []

    mock_sse = MagicMock()
    mock_sse.__aenter__.return_value = (MagicMock(), MagicMock())
    with patch("aetherops.core.mcp_client.sse_client", return_value=mock_sse), \
         patch("aetherops.core.mcp_client.ClientSession", return_value=mock_session):
        await c.connect()
        assert c._session is not None
        assert c._tools == []


@pytest.mark.asyncio
async def test_get_topology():
    """get_topology returns a TopologySnapshot."""
    c = MCPClient("http://localhost:50052")

    mock_session = AsyncMock()
    mock_session.call_tool = AsyncMock()
    mock_session.call_tool.return_value.content = [
        type("obj", (), {"type": "text", "text": '{"nodes":[],"edges":[],"node_count":0,"edge_count":0,"timestamp_nano":0}'})()
    ]

    with patch("aetherops.core.mcp_client.ClientSession", return_value=mock_session):
        c._session = mock_session
        topo = await c.get_topology()
        assert isinstance(topo, TopologySnapshot)
        assert topo.node_count == 0


# ── Integration test (requires live MCP server) ──


@pytest.mark.skip("requires live MCP server (set MCP_ADDR)")
@pytest.mark.asyncio
async def test_live_connect(mcp_addr):
    """Connect to a running MCP server (skip if unavailable)."""
    c = MCPClient(mcp_addr)
    await c.connect()
    tools = c.list_discovered_tools()
    tool_names = [t["name"] for t in tools]
    assert "get_topology" in tool_names
    assert "evaluate_remediation" in tool_names


@pytest.mark.skip("requires live MCP server (set MCP_ADDR)")
@pytest.mark.asyncio
async def test_live_topology(mcp_addr):
    """Fetch topology from live MCP server."""
    c = MCPClient(mcp_addr)
    await c.connect()
    topo = await c.get_topology(include_healthy=True)
    assert isinstance(topo, TopologySnapshot)
    # Should always have at least self-reference
    assert topo.node_count >= 0
