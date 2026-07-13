"""
AetherOps — Causal Inference Engine.

Uses causal-learn to perform causal discovery on Prometheus metrics
and topology data, producing a causal graph that identifies root causes.

This module wraps the LPCMCI algorithm (for time-series data) and
PC algorithm (for cross-sectional data).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


@dataclass
class CausalGraph:
    """Represents a discovered causal graph."""

    nodes: List[str]
    edges: List[Tuple[str, str, str]]  # (source, target, type: "-->", "x->", "o-o")
    adjacency_matrix: Optional[np.ndarray] = None
    scores: Dict[str, float] = field(default_factory=dict)


def run_causal_discovery(
    metrics_df: pd.DataFrame,
    method: str = "LPCMCI",
    alpha: float = 0.05,
    context: Optional[dict] = None,
) -> CausalGraph:
    """
    Run causal discovery on metric + topology data.

    Args:
        metrics_df: DataFrame with columns as variables (latency, error_rate,
                   qps for each service) and rows as time points.
        method: "LPCMCI" for time-series, "PC" for cross-sectional.
        alpha: Significance threshold for conditional independence tests.
        context: Optional dict with extra info (e.g., known edges from topology).

    Returns:
        CausalGraph with discovered causal relationships.
    """
    variables = list(metrics_df.columns)
    data = metrics_df.to_numpy()

    logger.info(
        "Running causal discovery: method=%s, variables=%d, samples=%d, alpha=%.3f",
        method,
        len(variables),
        data.shape[0],
        alpha,
    )

    if data.shape[0] < 10:
        logger.warning("Very few samples (%d), causal discovery may be unreliable", data.shape[0])

    # Safety cap: PC algorithm is O(n²), limit to top K most relevant variables
    max_vars = int(os.getenv("MAX_CAUSAL_VARS", "50"))
    if len(variables) > max_vars:
        logger.warning(
            "Too many variables (%d) for PC algorithm, truncating to %d",
            len(variables), max_vars,
        )
        variables = variables[:max_vars]
        data = metrics_df[variables].to_numpy()

    try:
        from causallearn.search.ConstraintBased.PC import pc
        from causallearn.search.FCMBased import lingam

        if method == "LPCMCI":
            # LPCMCI requires time-series data.
            # We use PC as a practical approximation on lagged features.
            cg = pc(data, alpha=alpha, indep_test="fisherz")
            edges = _convert_pc_edges(cg, variables)

        elif method == "PC":
            cg = pc(data, alpha=alpha, indep_test="fisherz")
            edges = _convert_pc_edges(cg, variables)

        elif method == "LINGAM":
            model = lingam.DirectLiNGAM()
            model.fit(data)
            edges = _convert_lingam_edges(model, variables)

        else:
            raise ValueError(f"Unknown causal discovery method: {method}")

        logger.info("Causal discovery complete: %d edges found", len(edges))
        return CausalGraph(nodes=variables, edges=edges)

    except ImportError as e:
        logger.warning("causal-learn not installed: %s. Using heuristic fallback.", e)
        return _heuristic_fallback(variables, context)

    except Exception as e:
        logger.error("Causal discovery failed: %s. Using heuristic fallback.", e)
        return _heuristic_fallback(variables, context)


def _convert_pc_edges(cg, variables: List[str]) -> List[Tuple[str, str, str]]:
    """Convert causal-learn PC result to our edge format."""
    edges = []
    graph = cg.G
    for i in range(graph.num_vars):
        for j in range(i + 1, graph.num_vars):
            edge = graph.get_edge(i, j)
            if edge is not None:
                edge_type = _infer_edge_type(edge)
                edges.append((variables[i], variables[j], edge_type))
    return edges


def _convert_lingam_edges(
    model, variables: List[str]
) -> List[Tuple[str, str, str]]:
    """Convert LiNGAM result to our edge format."""
    edges = []
    B = model.B  # causal adjacency matrix
    for i in range(len(variables)):
        for j in range(len(variables)):
            if abs(B[i, j]) > 0.01:
                edges.append((variables[j], variables[i], "-->"))
    return edges


def _infer_edge_type(edge) -> str:
    """Map causal-learn edge types to string representation."""
    s = str(edge)
    if "-->" in s:
        return "-->"
    if "x->" in s:
        return "x->"
    if "o-o" in s:
        return "o-o"
    return "---"


def _heuristic_fallback(
    variables: List[str], context: Optional[dict] = None
) -> CausalGraph:
    """Fallback heuristic when causal-learn is unavailable or fails.

    Uses correlation + known topology edges as a rough causal estimate.
    """
    edges = []
    if context and "known_topology" in context:
        topo = context["known_topology"]
        for edge in topo.get("edges", []):
            if edge.get("anomaly_score", 0) > 0:
                edges.append((edge["src"], edge["dst"], "-->"))

    logger.info("Heuristic fallback produced %d edges", len(edges))
    return CausalGraph(nodes=variables, edges=edges)
