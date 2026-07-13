"""
AetherOps — Incident Memory (File-based KV).

Persists incident data across restarts using flat JSON files.
Each incident is one file, keyed by a unique incident ID.

Thread-safe within a single process since each file is atomically
written and read independently.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class IncidentMemory:
    """File-based KV store for incident tracking.

    Args:
        base_dir: Directory for incident JSON files.
            Created on first write if it doesn't exist.
    """

    def __init__(self, base_dir: str | None = None) -> None:
        self.base_dir = Path(base_dir or os.getenv(
            "AETHEROPS_INCIDENT_DIR",
            str(Path.home() / ".aetherops" / "incidents"),
        ))

    def _ensure_dir(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, incident_id: str) -> Path:
        # Sanitize: only alphanumeric, hyphens, underscores, dots
        safe = "".join(c for c in incident_id if c.isalnum() or c in "-_.")
        return self.base_dir / f"{safe}.json"

    def save(self, incident_id: str, data: Dict[str, Any]) -> None:
        """Save or update an incident record."""
        self._ensure_dir()
        data["_id"] = incident_id
        data["_updated_at"] = time.time()
        path = self._path(incident_id)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        logger.debug("Incident saved: %s (%d bytes)", incident_id, path.stat().st_size)

    def load(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Load an incident record, or None if it doesn't exist."""
        path = self._path(incident_id)
        if not path.exists():
            return None
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load incident %s: %s", incident_id, e)
            return None

    def list(
        self,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """List incidents, newest first, with optional status filter."""
        if not self.base_dir.exists():
            return []
        incidents: List[Dict[str, Any]] = []
        for path in sorted(self.base_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                with open(path) as f:
                    data = json.load(f)
                if status is None or data.get("status") == status:
                    incidents.append(data)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Skipping corrupt incident file %s: %s", path.name, e)
        return incidents[offset:offset + limit]

    def delete(self, incident_id: str) -> bool:
        """Delete an incident record. Returns True if existed."""
        path = self._path(incident_id)
        if path.exists():
            path.unlink()
            logger.info("Incident deleted: %s", incident_id)
            return True
        return False

    def cleanup(self, max_age_seconds: int = 30 * 86400) -> int:
        """Remove incidents older than max_age_seconds. Returns count removed."""
        if not self.base_dir.exists():
            return 0
        now = time.time()
        removed = 0
        for path in self.base_dir.glob("*.json"):
            try:
                if now - path.stat().st_mtime > max_age_seconds:
                    path.unlink()
                    removed += 1
            except OSError:
                pass
        if removed:
            logger.info("Cleaned up %d expired incident files", removed)
        return removed

    def count(self, status: Optional[str] = None) -> int:
        """Count incidents, optionally filtered by status."""
        return len(self.list(status=status, limit=10_000_000))
