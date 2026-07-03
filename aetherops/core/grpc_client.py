"""
AetherOps — gRPC client for the Go data plane.

Communicates with the Go-side TopologyService and RemediationService
to fetch topology snapshots, subscribe to anomaly events, and
evaluate/execute remediation actions.
"""

from __future__ import annotations

import json
import logging
from concurrent import futures
from dataclasses import dataclass
from typing import AsyncIterator, List, Optional

import grpc

from aetherops.proto import aetherops_pb2 as pb
from aetherops.proto import aetherops_pb2_grpc as pb_grpc

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


class AetherOpsClient:
    """gRPC client connecting to the ebpf-autoheal Go side."""

    def __init__(self, address: str = "localhost:50051"):
        self.address = address
        self.channel: Optional[grpc.Channel] = None
        self.topology_stub: Optional[pb_grpc.TopologyServiceStub] = None
        self.remediation_stub: Optional[pb_grpc.RemediationServiceStub] = None

    def connect(self) -> None:
        self.channel = grpc.insecure_channel(
            self.address,
            options=[
                ("grpc.max_send_message_length", 50 * 1024 * 1024),
                ("grpc.max_receive_message_length", 50 * 1024 * 1024),
            ],
        )
        self.topology_stub = pb_grpc.TopologyServiceStub(self.channel)
        self.remediation_stub = pb_grpc.RemediationServiceStub(self.channel)
        logger.info("Connected to AetherOps Go gRPC at %s", self.address)

    def close(self) -> None:
        if self.channel:
            self.channel.close()

    # ── Topology ──

    def get_topology(self, include_healthy: bool = False) -> TopologySnapshot:
        """Fetch current service graph from Go side."""
        req = pb.GetTopologyRequest(include_healthy=include_healthy)
        resp = self.topology_stub.GetTopology(req)

        nodes = [
            {
                "id": n.id,
                "avg_latency_ms": n.avg_latency_ms,
                "error_rate": n.error_rate,
                "call_count": n.call_count,
            }
            for n in resp.nodes
        ]
        edges = [
            {
                "src": e.src,
                "dst": e.dst,
                "call_count": e.call_count,
                "avg_latency_ms": e.avg_latency_ms,
                "ema_latency_ms": e.ema_latency_ms,
                "p95_latency_ms": e.p95_latency_ms,
                "anomaly_score": e.anomaly_score,
            }
            for e in resp.edges
        ]
        return TopologySnapshot(
            nodes=nodes,
            edges=edges,
            node_count=resp.node_count,
            edge_count=resp.edge_count,
            timestamp_unix_nano=resp.timestamp_unix_nano,
        )

    def subscribe_anomalies(
        self, min_score: float = 0.5
    ) -> AsyncIterator[AnomalyEvent]:
        """Stream anomaly events from Go side."""
        req = pb.AnomalySubscription(min_score_threshold=min_score)
        for event in self.topology_stub.SubscribeAnomalyEvents(req):
            yield AnomalyEvent(
                node_id=event.node_id,
                anomaly_score=event.anomaly_score,
                avg_latency_ms=event.avg_latency_ms,
                call_count=event.call_count,
                suspect_chain=list(event.suspect_chain),
                timestamp_unix_nano=event.timestamp_unix_nano,
            )

    # ── Remediation ──

    def evaluate_remediation(
        self, target_node: str, action: str
    ) -> dict:
        """Evaluate blast radius for a proposed action."""
        action_enum = pb.RemediationAction.Value(action)
        req = pb.RemediationRequest(
            target_node=target_node,
            action=action_enum,
        )
        resp = self.remediation_stub.EvaluateRemediation(req)
        return {
            "target_node": resp.target_node,
            "action": resp.action,
            "risk_level": resp.risk_level,
            "affected_upstream_count": resp.affected_upstream_count,
            "affected_downstream_count": resp.affected_downstream_count,
            "affected_services": list(resp.affected_services),
            "estimated_error_budget_consumption": resp.estimated_error_budget_consumption,
            "estimated_downtime_seconds": resp.estimated_downtime_seconds,
            "recommendation": resp.recommendation,
        }

    def execute_remediation(
        self, target_node: str, action: str, force: bool = False
    ) -> dict:
        """Execute a remediation action through the Go graded execution layer."""
        action_enum = pb.RemediationAction.Value(action)
        req = pb.ExecuteRequest(
            target_node=target_node,
            action=action_enum,
            force=force,
        )
        resp = self.remediation_stub.ExecuteRemediation(req)
        return {
            "accepted": resp.accepted,
            "execution_id": resp.execution_id,
            "status": resp.status,
            "details": resp.details,
        }
