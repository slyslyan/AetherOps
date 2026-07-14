"""
AetherOps — AI-Driven Intelligent Operations Agent.

Entry point for the Python cognitive plane.

Usage:
    python -m aetherops.main                   # Start anomaly listener
    python -m aetherops.main --workflow        # Run workflow once with sample data
    python -m aetherops.main --daemon          # Daemon mode: listen for anomalies
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
import time
from threading import Thread
from typing import Optional

from aetherops.core.mcp_client import MCPClient, AnomalyEvent, stop_bg_loop
from aetherops.core.alert_correlation import AlertCorrelator, AlertEvent
from aetherops.core.feedback import get_feedback_store
from aetherops.workflows.workflow import build_workflow, run_workflow

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("aetherops")


class AetherOpsDaemon:
    """Daemon that listens for anomaly events and triggers the diagnosis workflow."""

    def __init__(self):
        self.workflow = build_workflow()
        self.client: Optional[MCPClient] = None
        self.running = False
        self.correlator = AlertCorrelator(
            window_seconds=int(os.getenv("ALERT_WINDOW_SECONDS", "60")),
            storm_threshold=int(os.getenv("ALERT_STORM_THRESHOLD", "20")),
        )
        self.feedback = get_feedback_store()
        self._metrics_server = None

    def _start_metrics_server(self):
        """Start a lightweight HTTP server for Prometheus metrics scraping."""
        port = int(os.getenv("AETHEROPS_METRICS_PORT", "9093"))
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler

            class MetricsHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    body = b"AetherOps agent running"
                    if self.path == "/metrics":
                        self.send_response(200)
                        self.send_header("Content-Type", "text/plain")
                        self.end_headers()
                        self.wfile.write(body)
                    else:
                        self.send_response(200)
                        self.send_header("Content-Type", "text/plain")
                        self.end_headers()
                        self.wfile.write(body)

                def log_message(self, fmt, *args):
                    pass  # silence HTTP log

            server = HTTPServer(("127.0.0.1", port), MetricsHandler)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self._metrics_server = server
            logger.info("Metrics server started on :%d/metrics", port)
        except Exception as e:
            logger.warning("Metrics server failed to start (%s) — continuing", e)

    async def start(self):
        """Start listening for anomaly events via MCP SSE stream."""
        # MCP path — subscribe via SSE
        mcp_addr = os.getenv("AETHEROPS_MCP_ADDR", "http://localhost:50052")
        self.client = MCPClient(address=mcp_addr)
        await self.client.connect()
        self.running = True

        min_score = float(os.getenv("ANOMALY_MIN_SCORE", "0.5"))
        self._start_metrics_server()
        logger.info("AetherOps daemon started (MCP/SSE). Watching for anomalies (min_score=%.2f)...", min_score)

        try:
            async for event in self.client.subscribe_anomalies(min_score=min_score):
                if not self.running:
                    break
                logger.info(
                    "Anomaly detected: %s (score=%.2f)",
                    event.node_id,
                    event.anomaly_score,
                )
                # Run the sync handler in a thread to avoid blocking the event loop
                await asyncio.to_thread(self._handle_anomaly, event)
        except asyncio.CancelledError:
            logger.info("Daemon cancelled")
        except Exception:
            logger.exception("Unexpected error in anomaly listener")
        finally:
            self.stop()

    def stop(self):
        """Stop the daemon and close the client connection."""
        self.running = False
        if self.client:
            self.client.close()
        stop_bg_loop()

    def _handle_anomaly(self, event: AnomalyEvent):
        """Handle a single anomaly event through the diagnosis workflow."""
        logger.info("Starting diagnosis pipeline for anomaly: %s", event.node_id)

        # Alert correlation: dedup + grouping + storm suppression
        alert = AlertEvent(
            node_id=event.node_id,
            alert_type="anomaly",
            severity=min(event.anomaly_score / 100.0, 1.0),
            message=f"Anomaly score {event.anomaly_score:.1f} on {event.node_id}",
            score=event.anomaly_score,
            timestamp_ns=event.timestamp_unix_nano or time.time_ns(),
        )
        correlated = self.correlator.feed(alert)

        # Skip if deduped or suppressed during storm
        if correlated.is_deduped:
            logger.debug("Deduped alert for %s (score=%.1f)", event.node_id, event.anomaly_score)
            return
        if correlated.is_suppressed:
            logger.info("Suppressed alert during storm: %s", event.node_id)
            return

        # Build initial state
        initial_state = default_diagnosis_state(event)

        # Run the workflow
        try:
            result = run_workflow(self.workflow, initial_state)
            logger.info(
                "Diagnosis pipeline complete. Root cause: %s, Status: %s",
                result.get("diagnosis_report", {}).get("root_cause", "unknown"),
                result.get("execution_result", {}).get("status", "unknown"),
            )
        except Exception as e:
            logger.error("Workflow execution failed: %s", e)


def default_diagnosis_state(event: AnomalyEvent) -> dict:
    """Build the initial LangGraph state for an anomaly event."""
    return {
        "anomaly_event": {
            "node_id": event.node_id,
            "anomaly_score": event.anomaly_score,
            "avg_latency_ms": event.avg_latency_ms,
            "call_count": event.call_count,
            "suspect_chain": event.suspect_chain,
            "timestamp_unix_nano": event.timestamp_unix_nano,
        },
        "anomaly_detected_at": time.time(),
        "topology_snapshot": None,
        "causal_graph": None,
        "diagnosis_report": None,
        "diagnosis_confidence": 0.0,
        "risk_report": None,
        "execution_result": None,
        "completed": False,
        "workflow_error": None,
        "plan": None,
        "plan_step_index": 0,
        "plan_rationale": None,
        "next_agent": "supervisor",
        "recovery_report": None,
        "rag_context": None,
    }


def run_single_workflow():
    """Run a single diagnosis workflow with sample data for testing."""
    logger.info("Running single diagnosis workflow (demo mode)...")

    if not os.getenv("LLM_API_KEY"):
        logger.warning("LLM_API_KEY not set — LLM diagnosis will fall back to heuristic")

    workflow = build_workflow()

    demo_event = AnomalyEvent(
        node_id="demo-service:8080",
        anomaly_score=85.0,
        avg_latency_ms=2500.0,
        call_count=150,
        suspect_chain=["svc-a", "svc-b", "demo-service:8080"],
        timestamp_unix_nano=int(time.time() * 1e9),
    )
    initial_state = default_diagnosis_state(demo_event)
    initial_state["causal_method"] = "PC"

    _t0 = time.time()
    result = run_workflow(workflow, initial_state)
    _duration_ms = (time.time() - _t0) * 1000

    print("\n=== WORKFLOW RESULT ===")
    print(f"Root cause: {result.get('diagnosis_report', {}).get('root_cause', 'N/A')}")
    print(f"Confidence: {result.get('diagnosis_confidence', 0):.2f}")
    print(f"Execution: {result.get('execution_result', {}).get('status', 'N/A')}")
    print(f"Duration: {_duration_ms:.0f}ms")
    print(f"Plan: {result.get('plan', [])}")
    print(f"Plan rationale: {result.get('plan_rationale', 'N/A')}")
    print("=======================\n")


async def _run_daemon():
    """Async entry point for daemon mode."""
    daemon = AetherOpsDaemon()

    def shutdown():
        daemon.stop()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown)
        except NotImplementedError:
            # Windows or non-main-thread — fall back to KeyboardInterrupt
            pass

    await daemon.start()


def main():
    parser = argparse.ArgumentParser(description="AetherOps — Intelligent Operations Agent")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon, listen for anomalies")
    parser.add_argument("--workflow", action="store_true", help="Run workflow once with demo data")
    args = parser.parse_args()

    if args.daemon:
        try:
            asyncio.run(_run_daemon())
        except KeyboardInterrupt:
            logger.info("Shutdown by user")
    elif args.workflow:
        run_single_workflow()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
