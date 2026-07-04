"""
AetherOps — Risk assessment and remediation client.

Calls the Go blast_radius tools via MCP protocol (default) or gRPC (fallback).
Controlled by AETHEROPS_TRANSPORT env var: "mcp" (default) or "grpc".

All MCP operations use a sync→async bridge (run_async) since LangGraph workflow
nodes are synchronous but the MCP SDK is fully async.  The bridge dispatches
coroutines to a dedicated background event loop and blocks the calling thread.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from aetherops.core.mcp_client import MCPClient, run_async

logger = logging.getLogger(__name__)

_client: Optional[MCPClient] = None


def _get_client() -> MCPClient:
    global _client
    if _client is None:
        transport = os.getenv("AETHEROPS_TRANSPORT", "mcp")
        if transport == "grpc":
            from aetherops.core.grpc_client import AetherOpsClient

            addr = os.getenv("AETHEROPS_GRPC_ADDR", "localhost:50051")
            client: MCPClient = AetherOpsClient(address=addr)  # type: ignore
            client.connect()
            _client = client  # type: ignore
        else:
            mcp_addr = os.getenv("AETHEROPS_MCP_ADDR", "http://localhost:50052")
            client = MCPClient(address=mcp_addr)
            run_async(client.connect())
            _client = client
    return _client


def assess_remediation(
    target_node: str,
    action: str = "TC_DROP",
    diagnosis: Optional[dict] = None,
) -> dict:
    """
    Assess the blast radius of a proposed remediation action.

    Args:
        target_node: Service name or IP:Port to act on.
        action: Remediation action type (TC_DROP, POD_RESTART, etc.).
        diagnosis: Optional LLM diagnosis context.

    Returns:
        RemediationReport dict with risk level and impact analysis.
    """
    try:
        client = _get_client()
        report = run_async(client.evaluate_remediation(target_node, action))
        logger.info(
            "Risk assessment: action=%s target=%s risk=%s budget=%.1f%%",
            action,
            target_node,
            report["risk_level"],
            report["estimated_error_budget_consumption"],
        )
        report["diagnosis_context"] = diagnosis or {}
        return report
    except Exception as e:
        logger.error("Risk assessment failed: %s", e)
        return {
            "target_node": target_node,
            "action": action,
            "risk_level": 1,  # RISK_LOW fallback
            "affected_services": [],
            "estimated_error_budget_consumption": 0.0,
            "recommendation": f"Fallback: {e}",
            "error": str(e),
        }


def execute_remediation(
    target_node: str,
    action: str,
    force: bool = False,
    execution_id: Optional[str] = None,
) -> dict:
    """
    Execute a remediation action through the Go graded execution layer.

    Args:
        target_node: Service name or IP:Port.
        action: Remediation action type.
        force: Skip risk check if True.
        execution_id: Optional trace ID.

    Returns:
        Execution result dict.
    """
    try:
        client = _get_client()
        result = run_async(client.execute_remediation(target_node, action, force=force))
        logger.info(
            "Remediation execution: action=%s target=%s status=%s id=%s",
            action,
            target_node,
            result["status"],
            result["execution_id"],
        )
        return result
    except Exception as e:
        logger.error("Remediation execution failed: %s", e)
        return {
            "accepted": False,
            "execution_id": execution_id or "unknown",
            "status": "failed",
            "details": str(e),
        }
