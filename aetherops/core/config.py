"""
AetherOps — Centralized Configuration.

Single source of truth for all environment variables.
Eliminates scattered os.getenv() calls across 15+ files.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class AetherOpsConfig:
    """Centralized configuration loaded from environment variables.

    All defaults match the original per-file os.getenv() calls so this is
    a transparent replacement.
    """

    # ── Transport ──
    transport: str = "mcp"  # mcp | grpc
    mcp_addr: str = "http://localhost:50052"
    grpc_addr: str = "localhost:50051"

    # ── LLM Provider ──
    llm_provider: str = "deepseek"
    llm_api_key: str = ""
    llm_model: str = ""
    llm_base_url: str = ""

    # ── Analysis ──
    prometheus_url: str = "http://localhost:9090"
    max_diagnosis_turns: int = 2
    anomaly_min_score: float = 0.5

    # ── Alert Correlation ──
    alert_window_seconds: int = 60
    alert_storm_threshold: int = 20

    # ── Metrics ──
    metrics_port: int = 9093

    # ── Storage paths ──
    feedback_dir: str = ""
    incident_dir: str = ""

    # ── Policy ──
    policy_file: str = ""

    # ── Probe ──
    http_probe_target: str = "/proc/self/exe"

    @classmethod
    def from_env(cls) -> AetherOpsConfig:
        """Load configuration from environment variables."""
        return cls(
            transport=os.getenv("AETHEROPS_TRANSPORT", "mcp"),
            mcp_addr=os.getenv("AETHEROPS_MCP_ADDR", "http://localhost:50052"),
            grpc_addr=os.getenv("AETHEROPS_GRPC_ADDR", "localhost:50051"),
            llm_provider=os.getenv("LLM_PROVIDER", "deepseek"),
            llm_api_key=os.getenv("LLM_API_KEY", ""),
            llm_model=os.getenv("LLM_MODEL", ""),
            llm_base_url=os.getenv("LLM_BASE_URL", ""),
            prometheus_url=os.getenv("PROMETHEUS_URL", "http://localhost:9090"),
            max_diagnosis_turns=int(os.getenv("MAX_DIAGNOSIS_TURNS", "2")),
            anomaly_min_score=float(os.getenv("ANOMALY_MIN_SCORE", "0.5")),
            alert_window_seconds=int(os.getenv("ALERT_WINDOW_SECONDS", "60")),
            alert_storm_threshold=int(os.getenv("ALERT_STORM_THRESHOLD", "20")),
            metrics_port=int(os.getenv("AETHEROPS_METRICS_PORT", "9093")),
            feedback_dir=os.getenv("AETHEROPS_FEEDBACK_DIR", ""),
            incident_dir=os.getenv("AETHEROPS_INCIDENT_DIR", ""),
            policy_file=os.getenv("POLICY_FILE", ""),
            http_probe_target=os.getenv("HTTP_PROBE_TARGET", "/proc/self/exe"),
        )

    @property
    def resolved_feedback_dir(self) -> str:
        return self.feedback_dir or str(Path.home() / ".aetherops" / "feedback")

    @property
    def resolved_incident_dir(self) -> str:
        return self.incident_dir or str(Path.home() / ".aetherops" / "incidents")
