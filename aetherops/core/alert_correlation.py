# AetherOps — Alert Correlation & Deduplication Engine
#
# Three-tier alert processing:
#   Tier 1 — Time-window dedup: same node+type within 60s → merged
#   Tier 2 — Causal grouping: alerts with shared causal root → grouped
#   Tier 3 — Storm suppression: >20 alerts/sec → batched digest

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class AlertEvent:
    node_id: str
    alert_type: str  # latency, error_rate, call_drop, anomaly
    severity: float  # 0.0 - 1.0
    message: str
    score: float
    timestamp_ns: int
    fingerprint: str = ""
    correlation_id: str = ""  # set by correlation engine
    is_deduped: bool = False
    is_suppressed: bool = False

    def __post_init__(self):
        if not self.fingerprint:
            raw = f"{self.node_id}|{self.alert_type}|{int(self.severity * 10)}"
            self.fingerprint = hashlib.md5(raw.encode()).hexdigest()[:12]


@dataclass
class AlertDigest:
    """A grouped digest of multiple alerts, used during storm suppression."""
    correlation_id: str
    alert_type: str
    node_ids: List[str]
    severity: float  # max severity of grouped alerts
    count: int
    first_seen_ns: int
    last_seen_ns: int
    root_cause: Optional[str] = None
    summary: str = ""


class AlertCorrelator:
    """Three-tier alert correlation engine.

    Usage:
        correlator = AlertCorrelator(window_seconds=60)
        correlator.feed(alert)
        correlator.feed(alert2)
        grouped = correlator.get_groups()
    """

    def __init__(
        self,
        window_seconds: int = 60,
        storm_threshold: int = 20,
        storm_window_seconds: int = 1,
    ):
        self.window_seconds = window_seconds
        self.storm_threshold = storm_threshold
        self.storm_window_seconds = storm_window_seconds
        self._recent: Dict[str, AlertEvent] = {}  # fingerprint -> latest alert
        self._timeline: List[AlertEvent] = []
        self._correlation_groups: Dict[str, AlertDigest] = {}
        self._storm_counters: Dict[int, int] = defaultdict(int)  # epoch_second -> count

    # ── Tier 1: Time-window dedup ──

    def feed(self, alert: AlertEvent) -> AlertEvent:
        """Feed an alert into the correlator. Returns the (possibly deduped) alert."""
        now_s = int(time.time())

        # Update storm counter
        self._storm_counters[now_s] += 1

        # Tier 1: Check dedup window
        existing = self._recent.get(alert.fingerprint)
        if existing:
            elapsed_ns = alert.timestamp_ns - existing.timestamp_ns
            if elapsed_ns < self.window_seconds * 1_000_000_000:
                alert.is_deduped = True
                alert.correlation_id = existing.correlation_id
                logger.debug("Deduped alert: %s (%.1fs since last)", alert.fingerprint, elapsed_ns / 1e9)
                return alert

        # Tier 2: Assign correlation group
        correlation_id = self._assign_group(alert)
        alert.correlation_id = correlation_id

        # Tier 3: Check storm suppression
        storm_count = sum(
            self._storm_counters.get(s, 0)
            for s in range(now_s - self.storm_window_seconds, now_s + 1)
        )
        if storm_count > self.storm_threshold:
            alert.is_suppressed = True
            logger.debug("Suppressed alert: %s (storm: %d/s)", alert.fingerprint, storm_count)
            # Update digest instead
            if correlation_id in self._correlation_groups:
                d = self._correlation_groups[correlation_id]
                d.count += 1
                d.last_seen_ns = alert.timestamp_ns
                if alert.node_id not in d.node_ids:
                    d.node_ids.append(alert.node_id)
                d.severity = max(d.severity, alert.severity)
            return alert

        # Fresh alert — record it
        self._recent[alert.fingerprint] = alert
        self._timeline.append(alert)

        # Update digest
        if correlation_id in self._correlation_groups:
            d = self._correlation_groups[correlation_id]
            d.count += 1
            d.last_seen_ns = alert.timestamp_ns
            if alert.node_id not in d.node_ids:
                d.node_ids.append(alert.node_id)
            d.severity = max(d.severity, alert.severity)
        else:
            self._correlation_groups[correlation_id] = AlertDigest(
                correlation_id=correlation_id,
                alert_type=alert.alert_type,
                node_ids=[alert.node_id],
                severity=alert.severity,
                count=1,
                first_seen_ns=alert.timestamp_ns,
                last_seen_ns=alert.timestamp_ns,
            )

        return alert

    def _assign_group(self, alert: AlertEvent) -> str:
        """Assign a correlation group ID based on causal proximity."""
        # Same node + same type = same group
        # Different nodes but same causal parent = same group (requires causal graph context)
        raw = f"{alert.node_id}|{alert.alert_type}"
        return hashlib.md5(raw.encode()).hexdigest()[:12]

    def update_groups_with_causal_graph(self, causal_graph: Dict):
        """Re-assign correlation groups using the causal graph.

        If alerts A and B have a shared causal ancestor C, they get the same group.
        """
        edges = causal_graph.get("edges", [])

        # Build reverse adjacency: child -> [parents]
        reverse_adj: Dict[str, List[str]] = defaultdict(list)
        for src, dst, _typ in edges:
            if isinstance(dst, str) and isinstance(src, str):
                reverse_adj[dst].append(src)

        # For each recent alert, find the root cause in the causal graph
        for fp, alert in self._recent.items():
            if alert.is_deduped:
                continue
            # Walk up the causal chain to find the root
            visited: Set[str] = set()
            queue = [alert.node_id]
            root_cause = alert.node_id
            while queue:
                node = queue.pop(0)
                if node in visited:
                    continue
                visited.add(node)
                parents = reverse_adj.get(node, [])
                if parents:
                    root_cause = parents[0]  # first parent = most direct cause
                    queue.extend(parents)

            # Re-group by root cause
            new_group = hashlib.md5(f"causal:{root_cause}".encode()).hexdigest()[:12]
            old_group = alert.correlation_id
            alert.correlation_id = new_group

            # Migrate digest
            if old_group in self._correlation_groups:
                old_d = self._correlation_groups.pop(old_group)
                if new_group in self._correlation_groups:
                    d = self._correlation_groups[new_group]
                    d.count += old_d.count
                    d.node_ids = list(set(d.node_ids + old_d.node_ids))
                    d.severity = max(d.severity, old_d.severity)
                    d.last_seen_ns = max(d.last_seen_ns, old_d.last_seen_ns)
                else:
                    old_d.correlation_id = new_group
                    old_d.root_cause = root_cause
                    self._correlation_groups[new_group] = old_d

        logger.info("Re-grouped alerts by causal graph: %d groups", len(self._correlation_groups))

    # ── Digest generation ──

    def get_groups(self, min_severity: float = 0.0) -> List[AlertDigest]:
        """Get all correlation groups, optionally filtered by min severity."""
        return [
            d for d in self._correlation_groups.values()
            if d.severity >= min_severity
        ]

    def get_digest_report(self) -> str:
        """Generate a Markdown digest report of all active alert groups."""
        if not self._correlation_groups:
            return "No active alerts."

        lines = [
            "# AetherOps Alert Correlation Digest",
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Active groups: {len(self._correlation_groups)}",
            f"Total raw alerts in window: {len(self._timeline)}",
            f"Deduped: {sum(1 for a in self._timeline if a.is_deduped)}",
            f"Suppressed (storm): {sum(1 for a in self._timeline if a.is_suppressed)}",
            "",
            "## Alert Groups",
            "| Group ID | Type | Nodes | Severity | Count | Root Cause |",
            "|----------|------|-------|----------|-------|------------|",
        ]

        for gid, d in sorted(
            self._correlation_groups.items(),
            key=lambda x: x[1].severity,
            reverse=True,
        ):
            nodes = ", ".join(d.node_ids[:5])
            if len(d.node_ids) > 5:
                nodes += f" (+{len(d.node_ids) - 5})"
            lines.append(
                f"| {gid[:8]} | {d.alert_type} | {nodes} | {d.severity:.2f} | "
                f"{d.count} | {d.root_cause or 'N/A'} |"
            )

        lines.append("")
        return "\n".join(lines)

    def cleanup(self, max_age_seconds: int = 300):
        """Remove stale alerts older than max_age_seconds."""
        now_ns = time.time_ns()
        cutoff = now_ns - max_age_seconds * 1_000_000_000

        # Clean recent fingerprints
        stale_fps = [
            fp for fp, alert in self._recent.items()
            if alert.timestamp_ns < cutoff
        ]
        for fp in stale_fps:
            del self._recent[fp]

        # Clean timeline
        self._timeline = [a for a in self._timeline if a.timestamp_ns >= cutoff]

        # Clean groups with no recent alerts
        active_fps = {a.fingerprint for a in self._timeline if not a.is_deduped}
        stale_groups = [
            gid for gid, d in self._correlation_groups.items()
            if d.last_seen_ns < cutoff
        ]
        for gid in stale_groups:
            del self._correlation_groups[gid]

        # Clean old storm counters
        now_s = int(time.time())
        stale_seconds = [s for s in self._storm_counters if s < now_s - 60]
        for s in stale_seconds:
            del self._storm_counters[s]

        if stale_fps or stale_groups:
            logger.debug("Cleaned %d stale alerts, %d stale groups", len(stale_fps), len(stale_groups))


