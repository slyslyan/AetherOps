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
from typing import Optional

import yaml

from aetherops.core.mcp_client import MCPClient, AnomalyEvent
from aetherops.core.alert_correlation import AlertCorrelator, AlertEvent
from aetherops.core.feedback import AuditEntry, get_feedback_store
from aetherops.rag.retriever import build_diagnosis_context, retrieve_similar
from aetherops.workflows.langgraph_workflow import build_workflow

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("aetherops")


class AetherOpsDaemon:
    """Daemon that listens for anomaly events and triggers the diagnosis workflow."""

    def __init__(self, config_path: str = "workflow.yaml"):
        self.config = self._load_config(config_path)
        self.workflow = build_workflow()
        self.client: Optional[MCPClient] = None
        self.running = False
        self.correlator = AlertCorrelator(
            window_seconds=int(os.getenv("ALERT_WINDOW_SECONDS", "60")),
            storm_threshold=int(os.getenv("ALERT_STORM_THRESHOLD", "20")),
        )
        self.feedback = get_feedback_store()

    def _load_config(self, path: str) -> dict:
        with open(path) as f:
            return yaml.safe_load(f)

    def start(self):
        """Start listening for anomaly events via MCP SSE stream."""
        transport = os.getenv("AETHEROPS_TRANSPORT", "mcp")
        if transport == "grpc":
            # gRPC fallback path
            from aetherops.core.grpc_client import AetherOpsClient

            grpc_addr = os.getenv("AETHEROPS_GRPC_ADDR", "localhost:50051")
            self.client = AetherOpsClient(address=grpc_addr)
            self.client.connect()
            min_score = float(os.getenv("ANOMALY_MIN_SCORE", "0.5"))
            logger.info("AetherOps daemon started (gRPC). Watching for anomalies (min_score=%.2f)...", min_score)
            try:
                for event in self.client.subscribe_anomalies(min_score=min_score):
                    if not self.running:
                        break
                    self._handle_anomaly(event)
            except KeyboardInterrupt:
                pass
            finally:
                self.stop()
            return

        # MCP path — subscribe via SSE
        mcp_addr = os.getenv("AETHEROPS_MCP_ADDR", "http://localhost:50052")
        self.client = MCPClient(address=mcp_addr)
        self.client.connect()
        self.running = True

        min_score = float(os.getenv("ANOMALY_MIN_SCORE", "0.5"))
        logger.info("AetherOps daemon started (MCP/SSE). Watching for anomalies (min_score=%.2f)...", min_score)

        try:
            for event in self.client.subscribe_anomalies(min_score=min_score):
                if not self.running:
                    break
                logger.info(
                    "Anomaly detected: %s (score=%.2f)",
                    event.node_id,
                    event.anomaly_score,
                )
                self._handle_anomaly(event)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            self.stop()

    def stop(self):
        self.running = False
        if self.client:
            self.client.close()

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

        # Audit the incoming anomaly
        self.feedback.audit(AuditEntry(
            timestamp_ns=time.time_ns(), agent="supervisor",
            action="anomaly_received",
            input_summary=f"node={event.node_id} score={event.anomaly_score:.1f}",
            output_summary="", duration_ms=0,
            decision="start_diagnosis", trace_id=f"anomaly-{int(time.time())}",
        ))

        # Build initial state
        initial_state = {
            "anomaly_event": {
                "node_id": event.node_id,
                "anomaly_score": event.anomaly_score,
                "avg_latency_ms": event.avg_latency_ms,
                "call_count": event.call_count,
                "suspect_chain": event.suspect_chain,
                "timestamp_unix_nano": event.timestamp_unix_nano,
            },
            "topology_snapshot": None,
            "metrics_data": None,
            "causal_graph": None,
            "causal_method": "LPCMCI",
            "diagnosis_report": None,
            "diagnosis_confidence": 0.0,
            "diagnosis_loop_count": 0,
            "risk_report": None,
            "execution_result": None,
            "completed": False,
            "workflow_error": None,
            "next_agent": "topology_analyst",
            "topology_before": None,
            "recovery_report": None,
            "anomaly_detected_at": time.time(),
        }

        # Inject RAG context
        try:
            fingerprint = f"anomaly_{event.node_id}_score_{event.anomaly_score:.2f}"
            similar = retrieve_similar(fingerprint, top_k=3)
            context = build_diagnosis_context(fingerprint, similar)
            if context:
                initial_state["rag_context"] = context
                logger.info("Injected %d similar historical cases into context", len(similar))
        except Exception as e:
            logger.warning("RAG retrieval failed (non-critical): %s", e)

        # Run the workflow
        try:
            result = self.workflow.invoke(initial_state)
            logger.info(
                "Diagnosis pipeline complete. Root cause: %s, Status: %s",
                result.get("diagnosis_report", {}).get("root_cause", "unknown"),
                result.get("execution_result", {}).get("status", "unknown"),
            )
        except Exception as e:
            logger.error("Workflow execution failed: %s", e)


def run_single_workflow():
    """Run a single diagnosis workflow with sample data for testing."""
    logger.info("Running single diagnosis workflow (demo mode)...")
    workflow = build_workflow()

    initial_state = {
        "anomaly_event": {
            "node_id": "demo-service:8080",
            "anomaly_score": 85.0,
            "avg_latency_ms": 2500.0,
            "call_count": 150,
            "suspect_chain": ["svc-a", "svc-b", "demo-service:8080"],
            "timestamp_unix_nano": int(time.time() * 1e9),
        },
        "topology_snapshot": None,
        "metrics_data": None,
        "causal_graph": None,
        "causal_method": "PC",
        "diagnosis_report": None,
        "diagnosis_confidence": 0.0,
        "diagnosis_loop_count": 0,
        "risk_report": None,
        "execution_result": None,
        "completed": False,
        "workflow_error": None,
        "next_agent": "topology_analyst",
        "topology_before": None,
        "recovery_report": None,
        "anomaly_detected_at": time.time(),
    }

    result = workflow.invoke(initial_state)
    print("\n=== WORKFLOW RESULT ===")
    print(f"Root cause: {result.get('diagnosis_report', {}).get('root_cause', 'N/A')}")
    print(f"Confidence: {result.get('diagnosis_confidence', 0):.2f}")
    print(f"Execution: {result.get('execution_result', {}).get('status', 'N/A')}")
    print("=======================\n")


def main():
    parser = argparse.ArgumentParser(description="AetherOps — Intelligent Operations Agent")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon, listen for anomalies")
    parser.add_argument("--workflow", action="store_true", help="Run workflow once with demo data")
    args = parser.parse_args()

    if args.daemon:
        daemon = AetherOpsDaemon()
        daemon.start()
    elif args.workflow:
        run_single_workflow()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
