# AetherOps — Feedback Loop (simplified)
#
# Keeps: approval flow (LOW auto / MEDIUM confirm / HIGH pending),
# rollback check, and singleton store.
# Removed: JSONL persistence, weekly stats, audit trail.

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    AUTO_EXECUTED_LOW_RISK = "auto_executed"
    ROLLED_BACK = "rolled_back"
    ESCALATED = "escalated"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class AuditEntry:
    timestamp_ns: int
    agent: str
    action: str
    input_summary: str
    output_summary: str
    duration_ms: float
    decision: str
    risk_level: RiskLevel = RiskLevel.LOW
    error: Optional[str] = None
    trace_id: str = ""


@dataclass
class FeedbackEntry:
    trace_id: str
    node_id: str
    diagnosis_report: Dict
    recommended_action: Dict
    approval: ApprovalStatus
    human_comment: str = ""
    actual_outcome: str = ""
    mttr_seconds: float = 0.0
    created_at: float = 0.0
    updated_at: float = 0.0

    def __post_init__(self):
        now = time.time()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now


class FeedbackStore:
    """In-memory feedback store with approval tracking."""

    def __init__(self):
        self._entries: Dict[str, FeedbackEntry] = {}

    def record_approval(self, trace_id: str, node_id: str, diagnosis_report: Dict,
                        action: Dict, status: ApprovalStatus, comment: str = "") -> FeedbackEntry:
        entry = FeedbackEntry(trace_id=trace_id, node_id=node_id,
                              diagnosis_report=diagnosis_report, recommended_action=action,
                              approval=status, human_comment=comment)
        self._entries[trace_id] = entry
        return entry

    def record_outcome(self, trace_id: str, outcome: str, mttr_seconds: float = 0.0) -> Optional[FeedbackEntry]:
        entry = self._entries.get(trace_id)
        if not entry:
            return None
        entry.actual_outcome = outcome
        entry.mttr_seconds = mttr_seconds
        entry.updated_at = time.time()
        return entry

    def audit(self, entry: AuditEntry):
        pass  # audit persistence removed


class RollbackAssistant:
    """Minimal rollback check — verifies recovery report keywords."""

    def __init__(self, feedback_store: FeedbackStore):
        self.feedback = feedback_store

    def needs_rollback(self, recovery_report: str) -> bool:
        return any(kw in recovery_report for kw in ["Not Resolved", "Still Elevated", "failed"])

    def execute_rollback(self, trace_id: str, node_id: str, original_action: Dict, execution_id: str) -> Dict:
        logger.warning("Rollback triggered: trace=%s node=%s", trace_id, node_id)
        self.feedback.record_approval(trace_id=trace_id, node_id=node_id, diagnosis_report={},
                                      action=original_action, status=ApprovalStatus.ROLLED_BACK,
                                      comment=f"Auto-rollback: {original_action.get('action')} failed")
        return {"rollback_executed": True, "original_action": original_action.get("action"),
                "node_id": node_id, "trace_id": trace_id, "execution_id": execution_id,
                "timestamp": time.time(), "status": "rollback_initiated"}


_store: Optional[FeedbackStore] = None


def get_feedback_store() -> FeedbackStore:
    global _store
    if _store is None:
        _store = FeedbackStore()
    return _store


def get_rollback_assistant() -> RollbackAssistant:
    return RollbackAssistant(get_feedback_store())
