"""
Risk client tests — verify remediation assessment and execution.

Usage:
    pytest aetherops/tests/test_risk_client.py -v
"""

import os
from unittest.mock import patch

import pytest

from aetherops.core.risk_client import assess_remediation, execute_remediation


def test_assess_remediation_fallback():
    """When MCP is unavailable, returns a fallback report."""
    report = assess_remediation("test-node:8080", "TC_DROP")
    assert report["target_node"] == "test-node:8080"
    assert report["action"] == "TC_DROP"
    assert report["risk_level"] == 1  # RISK_LOW fallback
    assert "error" in report


def test_execute_remediation_fallback():
    """When MCP is unavailable, returns a failed execution."""
    result = execute_remediation("test-node:8080", "TC_DROP")
    assert result["accepted"] is False
    assert result["status"] == "failed"


@pytest.mark.asyncio
async def test_assess_live():
    """Assess remediation against live MCP server (skip if unavailable)."""
    addr = os.getenv("MCP_ADDR", "http://localhost:50052")
    # Force MCP transport
    with patch.dict(os.environ, {"AETHEROPS_TRANSPORT": "mcp",
                                  "AETHEROPS_MCP_ADDR": addr}):
        report = assess_remediation("10.42.0.1:8080", "TC_DROP")
        if "error" in report and "refused" in str(report.get("error", "")).lower():
            pytest.skip(f"MCP server not available at {addr}")
        assert "risk_level" in report
