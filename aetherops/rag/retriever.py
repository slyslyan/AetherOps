"""
AetherOps — RAG Retriever.

Given a new anomaly fingerprint, retrieves the most similar
historical diagnosis records from Milvus to provide context
for the LLM diagnosis.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def retrieve_similar(
    anomaly_fingerprint: str,
    top_k: int = 3,
    min_score: float = 0.0,
) -> List[Dict]:
    """
    Retrieve similar historical diagnoses from Milvus.

    Args:
        anomaly_fingerprint: Text description of the current anomaly.
        top_k: Number of similar records to return.
        min_score: Minimum similarity score threshold.

    Returns:
        List of diagnosis records sorted by similarity (highest first).
    """
    try:
        from pymilvus import Collection, connections

        from aetherops.rag.store import _compute_embedding

        uri = os.getenv("MILVUS_URI", "http://localhost:19530")
        connections.connect("aetherops", uri=uri)

        if not Collection.has_collection("aetheops_diagnoses", using="aetherops"):
            logger.info("No diagnoses collection yet in Milvus")
            return []

        collection = Collection("aetheops_diagnoses", using="aetherops")
        collection.load()

        query_embedding = _compute_embedding(anomaly_fingerprint)
        results = collection.search(
            data=[query_embedding],
            anns_field="embedding",
            param={"metric_type": "COSINE", "params": {"nprobe": 10}},
            limit=top_k,
            output_fields=[
                "anomaly_event",
                "causal_graph",
                "diagnosis_report",
                "execution_result",
                "status",
            ],
        )

        similar = []
        for hits in results:
            for hit in hits:
                if hit.score >= min_score:
                    similar.append(
                        {
                            "score": hit.score,
                            "anomaly_event": hit.entity.get("anomaly_event"),
                            "causal_graph": hit.entity.get("causal_graph"),
                            "diagnosis_report": hit.entity.get("diagnosis_report"),
                            "execution_result": hit.entity.get("execution_result"),
                            "status": hit.entity.get("status"),
                        }
                    )

        logger.info("Retrieved %d similar diagnoses from Milvus", len(similar))
        return similar

    except ImportError:
        logger.warning("pymilvus not installed, cannot retrieve from Milvus")
        return _retrieve_local_fallback(anomaly_fingerprint, top_k)
    except Exception as e:
        logger.warning("Milvus retrieval failed: %s. Using local fallback.", e)
        return _retrieve_local_fallback(anomaly_fingerprint, top_k)


def _retrieve_local_fallback(
    anomaly_fingerprint: str, top_k: int = 3
) -> List[Dict]:
    """Fallback: read from local JSON files when Milvus is unavailable."""
    store_dir = os.path.join(os.path.dirname(__file__), "..", "data", "diagnoses")
    if not os.path.isdir(store_dir):
        return []

    results = []
    for fname in sorted(os.listdir(store_dir), reverse=True)[:top_k]:
        if fname.endswith(".json"):
            with open(os.path.join(store_dir, fname)) as f:
                try:
                    record = json.load(f)
                    results.append(record)
                except json.JSONDecodeError:
                    continue

    logger.info("Retrieved %d diagnoses from local files", len(results))
    return results


def build_diagnosis_context(
    anomaly_fingerprint: str, retrieved: List[Dict]
) -> str:
    """
    Build a context string from retrieved records for LLM injection.

    Args:
        anomaly_fingerprint: Current anomaly description.
        retrieved: List of similar historical records.

    Returns:
        Context string to be injected into the LLM diagnosis prompt.
    """
    if not retrieved:
        return ""

    lines = [
        "## Similar Historical Diagnoses (RAG Retrieval)",
        "",
    ]
    for i, rec in enumerate(retrieved[:3], 1):
        diag = rec.get("diagnosis_report", {})
        result = rec.get("execution_result", {})
        lines.append(f"### Case {i} (similarity: {rec.get('score', 0):.2f})")
        lines.append(f"- Root cause: {diag.get('root_cause', 'unknown')}")
        lines.append(f"- Explanation: {diag.get('explanation', '')[:200]}")
        lines.append(f"- Actions taken: {diag.get('recommended_actions', [])}")
        lines.append(f"- Outcome: {result.get('status', 'unknown')}")
        lines.append("")

    return "\n".join(lines)
