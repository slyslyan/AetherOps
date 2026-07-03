"""
AetherOps — Prometheus metrics fetcher.

Pulls recent metrics from Prometheus for the causal inference engine.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import pandas as pd
import requests

logger = logging.getLogger(__name__)


def fetch_recent_metrics(
    prometheus_url: str = "http://localhost:9090",
    window_minutes: int = 5,
    step_seconds: int = 15,
) -> pd.DataFrame:
    """
    Fetch recent Prometheus metrics for all known services.

    Returns a DataFrame with columns like:
        latency_{service}, error_rate_{service}, qps_{service}

    Args:
        prometheus_url: Prometheus server URL.
        window_minutes: How far back to query.
        step_seconds: Resolution of data points.

    Returns:
        DataFrame with time-series metrics.
    """
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=window_minutes)
    params = {
        "query": "ebpf_edge_latency_ms",
        "start": start.timestamp(),
        "end": end.timestamp(),
        "step": step_seconds,
    }

    try:
        resp = requests.get(
            f"{prometheus_url}/api/v1/query_range",
            params=params,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        return _prometheus_to_dataframe(data)
    except Exception as e:
        logger.warning("Failed to fetch Prometheus metrics: %s", e)
        return _empty_metrics_dataframe()


def _prometheus_to_dataframe(data: dict) -> pd.DataFrame:
    """Convert Prometheus range query response to a DataFrame."""
    records = {}
    for result in data.get("data", {}).get("result", []):
        metric = result.get("metric", {})
        src = metric.get("src", "unknown")
        dst = metric.get("dst", "unknown")
        label = f"latency_{src}_to_{dst}"

        values = []
        timestamps = []
        for ts_str, val_str in result.get("values", []):
            timestamps.append(datetime.fromtimestamp(ts_str, tz=timezone.utc))
            values.append(float(val_str))

        if values:
            records[label] = pd.Series(values, index=timestamps)

    if not records:
        return _empty_metrics_dataframe()

    df = pd.DataFrame(records)
    df = df.fillna(method="ffill").fillna(method="bfill").fillna(0)
    return df


def _empty_metrics_dataframe() -> pd.DataFrame:
    """Return an empty DataFrame with expected structure."""
    return pd.DataFrame({"time": []})
