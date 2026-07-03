"""
AetherOps — RAG Knowledge Base (Milvus storage).

Stores historical diagnosis records (symptom → cause → fix → outcome)
as vector embeddings in Milvus for future retrieval.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Milvus collection name
COLLECTION_NAME = "aetheops_diagnoses"
VECTOR_DIM = 768  # Matches text-embedding-3-small dimension


def _get_milvus_connection():
    """Get or create Milvus connection."""
    from pymilvus import Collection, CollectionSchema, connections

    uri = os.getenv("MILVUS_URI", "http://localhost:19530")
    alias = "aetherops"

    try:
        connections.connect(alias=alias, uri=uri)
        logger.info("Connected to Milvus at %s", uri)
    except Exception as e:
        logger.warning("Milvus connection failed: %s. Using in-memory fallback.", e)
        return None

    # Create collection if not exists
    if not Collection.has_collection(COLLECTION_NAME, using=alias):
        from pymilvus import (
            CollectionSchema,
            DataType,
            FieldSchema,
        )

        fields = [
            FieldSchema(name="id", dtype=DataType.VARCHAR, is_primary=True, max_length=64),
            FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=VECTOR_DIM),
            FieldSchema(name="anomaly_event", dtype=DataType.JSON),
            FieldSchema(name="causal_graph", dtype=DataType.JSON),
            FieldSchema(name="diagnosis_report", dtype=DataType.JSON),
            FieldSchema(name="execution_result", dtype=DataType.JSON),
            FieldSchema(name="status", dtype=DataType.VARCHAR, max_length=32),
            FieldSchema(name="created_at", dtype=DataType.INT64),
        ]
        schema = CollectionSchema(fields, description="AetherOps diagnosis history")
        Collection(name=COLLECTION_NAME, schema=schema, using=alias)

    return Collection(name=COLLECTION_NAME, using=alias)


def _compute_embedding(text: str) -> List[float]:
    """Compute embedding vector for text using a simple hash-based fallback.

    In production, replace with an actual embedding model (e.g., OpenAI text-embedding-3-small).
    """
    try:
        import numpy as np
        from openai import OpenAI

        client = OpenAI(api_key=os.getenv("LLM_API_KEY"))
        resp = client.embeddings.create(
            model="text-embedding-3-small",
            input=text,
        )
        return resp.data[0].embedding
    except Exception as e:
        logger.warning("Embedding API failed: %s. Using deterministic fallback.", e)
        # Deterministic fallback for demo purposes.
        import hashlib

        h = hashlib.sha256(text.encode()).digest()
        vec = [float(b) / 255.0 for b in h[:VECTOR_DIM]]
        # Pad or truncate to VECTOR_DIM.
        if len(vec) < VECTOR_DIM:
            vec.extend([0.0] * (VECTOR_DIM - len(vec)))
        return vec[:VECTOR_DIM]


def _embedding_text(record: Dict) -> str:
    """Create a searchable text representation of the diagnosis record."""
    parts = []
    if anomaly := record.get("anomaly_event"):
        parts.append(f"anomaly: {anomaly.get('node_id', '')} score={anomaly.get('anomaly_score', 0)}")
    if diag := record.get("diagnosis_report"):
        parts.append(f"root_cause: {diag.get('root_cause', '')} confidence={diag.get('confidence', 0)}")
        parts.append(f"explanation: {diag.get('explanation', '')}")
        for action in diag.get("recommended_actions", []):
            parts.append(f"action: {action.get('action', '')} target={action.get('target', '')}")
    return " | ".join(parts)


def store_diagnosis(record: Dict) -> bool:
    """
    Store a completed diagnosis record to Milvus.

    Args:
        record: Dict with keys:
            - anomaly_event: The triggering anomaly
            - causal_graph: Causal inference result
            - diagnosis_report: LLM diagnosis report
            - execution_result: Remediation execution result
            - status: "success" or "failed"

    Returns:
        True if stored successfully.
    """
    try:
        collection = _get_milvus_connection()
        if collection is None:
            logger.info("Milvus not available, storing diagnosis locally (JSON)")
            _store_local_fallback(record)
            return True

        record_id = hashlib.md5(
            json.dumps(record, sort_keys=True, default=str).encode()
        ).hexdigest()[:16]

        text = _embedding_text(record)
        embedding = _compute_embedding(text)

        collection.insert(
            [
                {
                    "id": record_id,
                    "embedding": embedding,
                    "anomaly_event": record.get("anomaly_event", {}),
                    "causal_graph": record.get("causal_graph", {}),
                    "diagnosis_report": record.get("diagnosis_report", {}),
                    "execution_result": record.get("execution_result", {}),
                    "status": record.get("status", "unknown"),
                    "created_at": int(time.time()),
                }
            ]
        )
        collection.flush()
        logger.info("Stored diagnosis record %s to Milvus", record_id)
        return True

    except Exception as e:
        logger.error("Failed to store to Milvus: %s", e)
        _store_local_fallback(record)
        return False


def _store_local_fallback(record: Dict) -> None:
    """Fallback: store to local JSON file when Milvus is unavailable."""
    import json
    import os

    store_dir = os.path.join(os.path.dirname(__file__), "..", "data", "diagnoses")
    os.makedirs(store_dir, exist_ok=True)

    filename = f"diag_{int(time.time())}_{hashlib.md5(str(record).encode()).hexdigest()[:8]}.json"
    with open(os.path.join(store_dir, filename), "w") as f:
        json.dump(record, f, default=str, indent=2)
    logger.info("Stored diagnosis to local file: %s", filename)
