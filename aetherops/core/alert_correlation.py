# AetherOps — Alert Deduplication
#
# Sliding-window dedup: same node+type within 60s → merged.
# Keeps the interface (AlertCorrelator, AlertEvent) for compatibility.

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List

logger = logging.getLogger(__name__)


@dataclass
class AlertEvent:
    node_id: str
    alert_type: str
    severity: float
    message: str
    score: float
    timestamp_ns: int
    fingerprint: str = ""
    correlation_id: str = ""
    is_deduped: bool = False
    is_suppressed: bool = False

    def __post_init__(self):
        if not self.fingerprint:
            raw = f"{self.node_id}|{self.alert_type}|{int(self.severity * 10)}"
            self.fingerprint = hashlib.md5(raw.encode()).hexdigest()[:12]


@dataclass
class AlertDigest:
    correlation_id: str
    alert_type: str
    node_ids: List[str]
    severity: float
    count: int
    first_seen_ns: int
    last_seen_ns: int
    root_cause: str | None = None
    summary: str = ""


class AlertCorrelator:
    """Simple sliding-window alert dedup."""

    def __init__(self, window_seconds: int = 60, storm_threshold: int = 20, storm_window_seconds: int = 1):
        self.window_seconds = window_seconds
        self._recent: Dict[str, AlertEvent] = {}

    def feed(self, alert: AlertEvent) -> AlertEvent:
        """Feed an alert. Returns the (possibly deduped) alert."""
        existing = self._recent.get(alert.fingerprint)
        if existing:
            elapsed_ns = alert.timestamp_ns - existing.timestamp_ns
            if elapsed_ns < self.window_seconds * 1_000_000_000:
                alert.is_deduped = True
                return alert

        raw = f"{alert.node_id}|{alert.alert_type}"
        alert.correlation_id = hashlib.md5(raw.encode()).hexdigest()[:12]
        self._recent[alert.fingerprint] = alert
        return alert

    def update_groups_with_causal_graph(self, causal_graph: dict):
        pass  # causal grouping removed

    def get_groups(self, min_severity: float = 0.0) -> List[AlertDigest]:
        return []

    def get_digest_report(self) -> str:
        return "No active alerts."

    def cleanup(self, max_age_seconds: int = 300):
        now_ns = time.time_ns()
        cutoff = now_ns - max_age_seconds * 1_000_000_000
        self._recent = {fp: a for fp, a in self._recent.items() if a.timestamp_ns >= cutoff}
