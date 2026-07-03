"""
AetherOps — DSPy Prompt Optimizer.

Uses the DSPy framework to automatically optimize the LLM diagnosis
prompt's few-shot examples based on historical success/failure cases.

This module runs asynchronously after each diagnosis cycle to
continuously improve diagnosis accuracy.
"""

from __future__ import annotations

import json
import logging
import os
import random
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Path to the DSPy optimization cache.
DSPY_CACHE_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "dspy")


def async_optimize() -> bool:
    """
    Trigger DSPy prompt optimization using the latest successful cases.

    Reads recent diagnosis records, splits into train/validation sets,
    and runs DSPy's Bayesian signature optimizer to improve few-shot
    examples in the LLM diagnosis prompt.

    Returns:
        True if optimization was triggered successfully.
    """
    try:
        os.makedirs(DSPY_CACHE_DIR, exist_ok=True)

        cases = _load_recent_cases()
        if len(cases) < 3:
            logger.info("Not enough cases for DSPy optimization (need >=3, have %d)", len(cases))
            return False

        train, val = _split_cases(cases)
        _run_optimization(train, val)
        return True

    except Exception as e:
        logger.warning("DSPy optimization failed (non-critical): %s", e)
        return False


def _load_recent_cases(max_count: int = 50) -> List[Dict]:
    """Load recent diagnosis cases from local store."""
    cases = []
    store_dir = os.path.join(os.path.dirname(__file__), "..", "data", "diagnoses")
    if not os.path.isdir(store_dir):
        return []

    files = sorted(os.listdir(store_dir), reverse=True)[:max_count]
    for fname in files:
        if fname.endswith(".json"):
            try:
                with open(os.path.join(store_dir, fname)) as f:
                    record = json.load(f)
                    if record.get("diagnosis_report") and record.get("execution_result"):
                        cases.append(record)
            except (json.JSONDecodeError, IOError):
                continue

    return cases


def _split_cases(
    cases: List[Dict], val_ratio: float = 0.2
) -> tuple[List[Dict], List[Dict]]:
    """Split cases into training and validation sets."""
    random.shuffle(cases)
    split = max(1, int(len(cases) * val_ratio))
    return cases[split:], cases[:split]


def _run_optimization(train: List[Dict], val: List[Dict]) -> None:
    """
    Run DSPy optimization on the diagnosis prompt.

    Uses BootstrapFewShotWithRandomSearch to find the optimal set of
    few-shot examples for the diagnosis task.

    This is a simplified DSPy integration. In production, define
    a proper DSPy Signature and Teleprompter for end-to-end optimization.
    """
    try:
        import dspy
        from dspy.teleprompt import BootstrapFewShotWithRandomSearch

        lm = dspy.LM(
            model=os.getenv("LLM_MODEL", "claude-sonnet-4-6"),
            api_key=os.getenv("LLM_API_KEY"),
            api_base=os.getenv("LLM_API_URL", "https://api.openai.com/v1"),
        )
        dspy.configure(lm=lm)

        # Define a simple DSPy signature for diagnosis.
        class Diagnosis(dspy.Signature):
            """Given anomaly context and causal graph, identify root cause and remediation."""

            causal_graph = dspy.InputField(desc="JSON causal graph from causal discovery")
            anomaly_context = dspy.InputField(desc="Anomaly metrics and topology")
            root_cause = dspy.OutputField(desc="Identified root cause service")
            confidence = dspy.OutputField(desc="Confidence score 0-1")

        # Convert cases to DSPy examples.
        trainset = []
        for case in train:
            diag = case.get("diagnosis_report", {})
            trainset.append(
                dspy.Example(
                    causal_graph=json.dumps(case.get("causal_graph", {})),
                    anomaly_context=json.dumps(case.get("anomaly_event", {})),
                    root_cause=diag.get("root_cause", ""),
                    confidence=diag.get("confidence", 0.5),
                ).with_inputs("causal_graph", "anomaly_context")
            )

        teleprompter = BootstrapFewShotWithRandomSearch(
            metric=_diagnosis_accuracy,
            max_bootstrapped_demos=4,
            max_labeled_demos=8,
            num_candidate_programs=4,
        )

        compiled = teleprompter.compile(
            Diagnosis(),
            trainset=trainset[:20],
            valset=val[:10],
        )

        # Save the optimized prompt to cache.
        cache_path = os.path.join(DSPY_CACHE_DIR, "optimized_prompt.json")
        with open(cache_path, "w") as f:
            json.dump(
                {
                    "optimized_program": str(compiled),
                    "train_size": len(trainset),
                    "timestamp": __import__("time").time(),
                },
                f,
                indent=2,
            )
        logger.info("DSPy optimization complete. Cached at %s", cache_path)

    except ImportError as e:
        logger.warning("DSPy not fully installed: %s. Skipping optimization.", e)
    except Exception as e:
        logger.warning("DSPy optimization error: %s", e)


def _diagnosis_accuracy(
    example: dspy.Example, prediction: dspy.Prediction, trace=None
) -> float:
    """Metric function for DSPy: Jaccard similarity of root cause names."""
    expected = set(example.root_cause.lower().split())
    predicted = set(prediction.root_cause.lower().split())
    if not expected and not predicted:
        return 1.0
    if not expected or not predicted:
        return 0.0
    intersection = expected & predicted
    union = expected | predicted
    return len(intersection) / len(union)
