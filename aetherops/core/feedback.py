# AetherOps — Feedback Loop & Audit Log
#
# Records every agent decision, human approval/rejection, and outcome.
# Enables: accuracy tracking, rollback, continuous improvement.

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

FEEDBACK_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "feedback")


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
    decision: str  # what the agent decided
    risk_level: RiskLevel = RiskLevel.LOW
    error: Optional[str] = None
    trace_id: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict) -> "AuditEntry":
        return cls(**d)


@dataclass
class FeedbackEntry:
    trace_id: str
    node_id: str
    diagnosis_report: Dict
    recommended_action: Dict
    approval: ApprovalStatus
    human_comment: str = ""
    actual_outcome: str = ""  # success / partial / failure
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
    """Stores feedback entries and audit logs, with weekly stats."""

    def __init__(self, store_dir: str = FEEDBACK_DIR):
        self.store_dir = store_dir
        os.makedirs(store_dir, exist_ok=True)
        self._entries: Dict[str, FeedbackEntry] = {}
        self._audit_log: List[AuditEntry] = []
        self._load()

    # ── Persistence ──

    def _load(self):
        """Load existing feedback entries from disk."""
        feedback_file = os.path.join(self.store_dir, "feedback.jsonl")
        if os.path.exists(feedback_file):
            try:
                with open(feedback_file) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            data = json.loads(line)
                            entry = FeedbackEntry(**data)
                            self._entries[entry.trace_id] = entry
                logger.info("Loaded %d feedback entries", len(self._entries))
            except Exception as e:
                logger.warning("Failed to load feedback: %s", e)

    def _save(self):
        """Write all entries to disk."""
        feedback_file = os.path.join(self.store_dir, "feedback.jsonl")
        try:
            with open(feedback_file, "w") as f:
                for entry in self._entries.values():
                    f.write(json.dumps(asdict(entry), default=str) + "\n")
        except Exception as e:
            logger.error("Failed to save feedback: %s", e)

    def _flush_audit(self):
        """Append audit log to disk."""
        if not self._audit_log:
            return
        audit_file = os.path.join(
            self.store_dir,
            f"audit_{datetime.now(timezone.utc).strftime('%Y%m')}.jsonl",
        )
        try:
            with open(audit_file, "a") as f:
                for entry in self._audit_log:
                    f.write(json.dumps(entry.to_dict(), default=str) + "\n")
            self._audit_log.clear()
        except Exception as e:
            logger.error("Failed to flush audit log: %s", e)

    # ── Audit ──

    def audit(self, entry: AuditEntry):
        """Record an audit entry."""
        self._audit_log.append(entry)
        if len(self._audit_log) >= 10:
            self._flush_audit()
        logger.debug("Audit: %s → %s (%.0fms)", entry.agent, entry.decision, entry.duration_ms)

    # ── Feedback ──

    def record_approval(
        self,
        trace_id: str,
        node_id: str,
        diagnosis_report: Dict,
        action: Dict,
        status: ApprovalStatus,
        comment: str = "",
    ) -> FeedbackEntry:
        """Record a human approval or rejection decision."""
        entry = FeedbackEntry(
            trace_id=trace_id,
            node_id=node_id,
            diagnosis_report=diagnosis_report,
            recommended_action=action,
            approval=status,
            human_comment=comment,
        )
        self._entries[trace_id] = entry
        self._save()
        logger.info("Feedback recorded: trace=%s action=%s status=%s", trace_id, action.get("action"), status.value)
        return entry

    def record_outcome(
        self,
        trace_id: str,
        outcome: str,
        mttr_seconds: float = 0.0,
    ) -> Optional[FeedbackEntry]:
        """Record the actual outcome of a remediation action."""
        entry = self._entries.get(trace_id)
        if not entry:
            logger.warning("No feedback entry found for trace %s", trace_id)
            return None
        entry.actual_outcome = outcome
        entry.mttr_seconds = mttr_seconds
        entry.updated_at = time.time()
        self._save()
        logger.info("Outcome recorded: trace=%s outcome=%s MTTR=%.0fs", trace_id, outcome, mttr_seconds)
        return entry

    # ── Statistics ──

    def get_stats(self, days: int = 7) -> Dict:
        """Get feedback statistics for the last N days."""
        cutoff = time.time() - days * 86400
        recent = [
            e for e in self._entries.values()
            if e.created_at >= cutoff
        ]

        total = len(recent)
        if total == 0:
            return {
                "total": 0,
                "period_days": days,
                "approval_rate": 0,
                "success_rate": 0,
                "avg_mttr": 0,
            }

        approved = sum(1 for e in recent if e.approval in (
            ApprovalStatus.APPROVED, ApprovalStatus.AUTO_EXECUTED_LOW_RISK
        ))
        successful = sum(1 for e in recent if e.actual_outcome == "success")
        mttrs = [e.mttr_seconds for e in recent if e.mttr_seconds > 0]

        return {
            "total": total,
            "period_days": days,
            "approval_rate": approved / total if total else 0,
            "auto_executed": sum(1 for e in recent if e.approval == ApprovalStatus.AUTO_EXECUTED_LOW_RISK),
            "rejected": sum(1 for e in recent if e.approval == ApprovalStatus.REJECTED),
            "rollback_count": sum(1 for e in recent if e.approval == ApprovalStatus.ROLLED_BACK),
            "success_rate": successful / total if total else 0,
            "avg_mttr": sum(mttrs) / len(mttrs) if mttrs else 0,
            "recent_rejections": [
                {"node": e.node_id, "action": e.recommended_action.get("action", ""),
                 "comment": e.human_comment}
                for e in recent if e.approval == ApprovalStatus.REJECTED
            ][-5:],
        }

    def get_stats_report(self, days: int = 7) -> str:
        """Generate a Markdown stats report."""
        stats = self.get_stats(days)
        if stats["total"] == 0:
            return "No feedback data available for the last {} days.".format(days)

        return f"""# AetherOps Feedback Statistics ({days}-day)

## Overview
- **Total Incidents:** {stats['total']}
- **Approval Rate:** {stats['approval_rate']:.1%}
- **Success Rate:** {stats['success_rate']:.1%}
- **Average MTTR:** {stats['avg_mttr']:.0f}s

## Breakdown
| Metric | Value |
|--------|-------|
| Auto-executed (LOW risk) | {stats['auto_executed']} |
| Rejected | {stats['rejected']} |
| Rolled back | {stats['rollback_count']} |

## Recent Rejections
""" + "\n".join(
    f"- `{r['node']}` — {r['action']}: {r['comment']}"
    for r in stats.get("recent_rejections", [])
) if stats.get("recent_rejections") else "\n*(none)*"

    def get_audit_trail(self, trace_id: str) -> List[AuditEntry]:
        """Get the full audit trail for a specific trace."""
        # Flush first to ensure we have everything on disk
        self._flush_audit()

        results = []
        audit_file = os.path.join(
            self.store_dir,
            f"audit_{datetime.now(timezone.utc).strftime('%Y%m')}.jsonl",
        )
        if os.path.exists(audit_file):
            with open(audit_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entry = AuditEntry.from_dict(json.loads(line))
                        if entry.trace_id == trace_id:
                            results.append(entry)
        return results


# ── Rollback Assistant ──

class RollbackAssistant:
    """Handles remediation rollback when verification fails."""

    def __init__(self, feedback_store: FeedbackStore):
        self.feedback = feedback_store

    def needs_rollback(self, recovery_report: str) -> bool:
        """Check if a recovery report indicates rollback is needed."""
        keywords = ["Not Resolved", "Still Elevated", "escalating", "failed"]
        return any(kw in recovery_report for kw in keywords)

    def execute_rollback(
        self,
        trace_id: str,
        node_id: str,
        original_action: Dict,
        execution_id: str,
    ) -> Dict:
        """Execute a rollback for a failed remediation."""
        logger.warning("Rollback triggered: trace=%s node=%s action=%s",
                       trace_id, node_id, original_action.get("action"))

        # Determine inverse action
        inverse_action = self._inverse_action(original_action.get("action", ""))

        rollback_result = {
            "rollback_executed": True,
            "original_action": original_action.get("action"),
            "rollback_action": inverse_action,
            "node_id": node_id,
            "trace_id": trace_id,
            "execution_id": execution_id,
            "timestamp": time.time(),
            "status": "rollback_initiated",
        }

        # Record rollback in feedback
        self.feedback.record_approval(
            trace_id=trace_id,
            node_id=node_id,
            diagnosis_report={},
            action=original_action,
            status=ApprovalStatus.ROLLED_BACK,
            comment=f"Auto-rollback: {original_action.get('action')} failed verification",
        )

        return rollback_result

    def _inverse_action(self, action: str) -> str:
        """Map an action to its inverse."""
        inverse_map = {
            "SCALE_UP": "SCALE_DOWN",
            "POD_RESTART": "POD_RESTART",  # restart twice won't hurt
            "TC_DROP": "TC_REMOVE",
            "CONFIG_CHANGE": "CONFIG_ROLLBACK",
            "IMAGE_ROLLBACK": "IMAGE_ROLLBACK",  # already a rollback
        }
        return inverse_map.get(action, f"REVERSE_{action}")


# Global singleton
_store: Optional[FeedbackStore] = None


def get_feedback_store() -> FeedbackStore:
    global _store
    if _store is None:
        _store = FeedbackStore()
    return _store


def get_rollback_assistant() -> RollbackAssistant:
    return RollbackAssistant(get_feedback_store())
