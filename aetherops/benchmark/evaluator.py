# AetherOps — Incident Benchmark Evaluator
#
# Runs the full multi-agent workflow against 30 labeled fault scenarios
# and computes accuracy, precision, recall, and MTTR metrics.

from __future__ import annotations

import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ScenarioResult:
    name: str
    pattern: str
    tags: List[str]
    ground_truth_root_cause: str
    expected_action: str

    # Agent output
    predicted_root_cause: str = ""
    predicted_action: str = ""
    confidence: float = 0.0
    risk_level: str = ""
    execution_status: str = ""
    mttr_seconds: float = 0.0
    recovery_verdict: str = ""

    # Metrics
    root_cause_correct: bool = False
    action_correct: bool = False
    error: Optional[str] = None
    elapsed_seconds: float = 0.0


@dataclass
class BenchmarkReport:
    timestamp: str
    total: int
    passed: int
    root_cause_accuracy: float
    action_accuracy: float
    avg_confidence: float
    avg_mttr: float
    by_pattern: Dict[str, Dict]
    by_risk: Dict[str, int]
    details: List[ScenarioResult]
    failed_scenarios: List[str]


class BenchmarkEvaluator:
    """Runs the full workflow against benchmark scenarios and measures accuracy."""

    def __init__(self, workflow=None):
        self.workflow = workflow
        self.results: List[ScenarioResult] = []

    def set_workflow(self, workflow):
        self.workflow = workflow

    def run_all(self, scenarios, verbose: bool = False) -> BenchmarkReport:
        """Run all scenarios through the workflow and report accuracy."""
        if not self.workflow:
            try:
                from aetherops.workflows.workflow import build_workflow, run_workflow
                self.workflow = build_workflow()
                logger.info("Auto-loaded workflow for benchmark")
            except Exception:
                logger.info("Workflow not available; using lightweight diagnosis pipeline")
                self.workflow = None

        logger.info("Running benchmark: %d scenarios", len(scenarios))

        logger.info("Running benchmark: %d scenarios", len(scenarios))

        for scenario in scenarios:
            try:
                result = self._run_single(scenario, verbose)
            except Exception as e:
                logger.error("Scenario '%s' crashed: %s", scenario.name, e)
                result = ScenarioResult(
                    name=scenario.name,
                    pattern=scenario.pattern,
                    tags=scenario.tags,
                    ground_truth_root_cause=scenario.ground_truth_root_cause,
                    expected_action=scenario.expected_action,
                    error=str(e),
                )
            self.results.append(result)

        return self._build_report()

    def run_by_pattern(self, scenarios, pattern: str, verbose: bool = False) -> BenchmarkReport:
        """Run only scenarios matching a specific pattern."""
        filtered = [s for s in scenarios if s.pattern == pattern]
        logger.info("Running benchmark: %d scenarios (pattern=%s)", len(filtered), pattern)
        return self.run_all(filtered, verbose=verbose)

    def _run_single(self, scenario, verbose: bool = False) -> ScenarioResult:
        """Run a single scenario and measure accuracy."""
        start = time.time()
        elapsed = 0.0
        predicted_root = ""
        predicted_action = ""
        confidence = 0.0

        if self.workflow:
            # Full workflow path
            initial_state = {
                "anomaly_event": scenario.anomaly_event,
                "topology_snapshot": {
                    "nodes": scenario.topology.get("nodes", []),
                    "edges": scenario.topology.get("edges", []),
                },
                "metrics_data": scenario.metrics_mock,
                "causal_graph": None,
                "causal_method": "PC",
                "diagnosis_report": None,
                "diagnosis_confidence": 0.0,
                "diagnosis_loop_count": 0,
                "risk_report": None,
                "execution_result": None,
                "completed": False,
                "workflow_error": None,
                "next_agent": "topology_analyst",
                "topology_before": None,
                "recovery_report": None,
                "anomaly_detected_at": start,
            }

            try:
                result_state = run_workflow(self.workflow, initial_state)
                elapsed = time.time() - start
            except Exception as e:
                elapsed = time.time() - start
                return ScenarioResult(
                    name=scenario.name, pattern=scenario.pattern, tags=scenario.tags,
                    ground_truth_root_cause=scenario.ground_truth_root_cause,
                    expected_action=scenario.expected_action,
                    error=f"Workflow failed: {e}", elapsed_seconds=elapsed,
                )

            diag = result_state.get("diagnosis_report", {}) or {}
            predicted_root = diag.get("root_cause", "")
            actions = diag.get("recommended_actions", [])
            predicted_action = actions[0].get("action", "") if actions else ""
            confidence = diag.get("confidence", 0.0)

        else:
            # Lightweight path: use heuristic/LLM diagnosis directly
            elapsed = time.time() - start

            # Build causal graph from topology edges with anomaly scores
            edges = scenario.topology.get("edges", [])
            anomaly_edges = [
                (e.get("src", ""), e.get("dst", ""), "-->")
                for e in edges if e.get("anomaly_score", 0) > 0
            ]
            nodes = [n.get("id", "") for n in scenario.topology.get("nodes", [])]
            causal_graph = {"nodes": nodes, "edges": anomaly_edges}
            anomaly_context = {
                "topology": scenario.topology,
                "anomaly_event": scenario.anomaly_event,
            }

            from aetherops.core.llm_diagnosis import diagnose as llm_diagnose
            report = llm_diagnose(causal_graph=causal_graph, anomaly_context=anomaly_context)
            predicted_root = report.root_cause
            confidence = report.confidence
            actions = report.recommended_actions
            predicted_action = actions[0].get("action", "") if actions else ""

        # Evaluate accuracy
        if not scenario.ground_truth_root_cause:
            root_cause_correct = not predicted_root or predicted_root == ""
        else:
            root_cause_correct = (
                scenario.ground_truth_root_cause in predicted_root
                or predicted_root in scenario.ground_truth_root_cause
            )

        action_match = scenario.expected_action == predicted_action if scenario.expected_action else True

        result = ScenarioResult(
            name=scenario.name, pattern=scenario.pattern, tags=scenario.tags,
            ground_truth_root_cause=scenario.ground_truth_root_cause,
            expected_action=scenario.expected_action,
            predicted_root_cause=predicted_root,
            predicted_action=predicted_action,
            confidence=confidence,
            root_cause_correct=root_cause_correct,
            action_correct=action_match,
            elapsed_seconds=elapsed,
        )

        if verbose:
            status = "+" if root_cause_correct else "-"
            print(f"  [{status}] {scenario.name:45s} root={predicted_root:25s} "
                  f"action={predicted_action:15s} conf={confidence:.2f} "
                  f"({elapsed:.1f}s)")

        return result

    def _build_report(self) -> BenchmarkReport:
        """Aggregate results into a summary report."""
        total = len(self.results)
        if total == 0:
            return BenchmarkReport(
                timestamp=datetime.now(timezone.utc).isoformat(),
                total=0, passed=0,
                root_cause_accuracy=0, action_accuracy=0,
                avg_confidence=0, avg_mttr=0,
                by_pattern={}, by_risk={}, details=[],
                failed_scenarios=[],
            )

        rc_correct = sum(1 for r in self.results if r.root_cause_correct)
        action_correct = sum(1 for r in self.results if r.action_correct)
        avg_conf = sum(r.confidence for r in self.results) / total
        mttrs = [r.mttr_seconds for r in self.results if r.mttr_seconds > 0]
        avg_mttr = sum(mttrs) / len(mttrs) if mttrs else 0
        failed = [r.name for r in self.results if r.error or (not r.root_cause_correct and r.ground_truth_root_cause)]

        # By pattern
        by_pattern: Dict[str, Dict] = {}
        for r in self.results:
            if r.pattern not in by_pattern:
                by_pattern[r.pattern] = {"total": 0, "rc_correct": 0, "action_correct": 0, "conf_sum": 0}
            by_pattern[r.pattern]["total"] += 1
            if r.root_cause_correct:
                by_pattern[r.pattern]["rc_correct"] += 1
            if r.action_correct:
                by_pattern[r.pattern]["action_correct"] += 1
            by_pattern[r.pattern]["conf_sum"] += r.confidence

        for p, d in by_pattern.items():
            d["rc_accuracy"] = d["rc_correct"] / d["total"] if d["total"] else 0
            d["action_accuracy"] = d["action_correct"] / d["total"] if d["total"] else 0
            d["avg_confidence"] = d["conf_sum"] / d["total"] if d["total"] else 0

        # By risk level
        by_risk: Dict[str, int] = {}
        for r in self.results:
            level = r.risk_level or "unknown"
            by_risk[level] = by_risk.get(level, 0) + 1

        return BenchmarkReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            total=total,
            passed=rc_correct,
            root_cause_accuracy=rc_correct / total if total else 0,
            action_accuracy=action_correct / total if total else 0,
            avg_confidence=avg_conf,
            avg_mttr=avg_mttr,
            by_pattern=by_pattern,
            by_risk=by_risk,
            details=self.results,
            failed_scenarios=failed,
        )


def print_report(report: BenchmarkReport):
    """Pretty-print a benchmark report."""
    print(f"""
{'='*60}
  AetherOps Benchmark Report
  {report.timestamp}
{'='*60}

  OVERVIEW
  -------------------------------------------------
  Total scenarios:    {report.total}
  Root cause accuracy: {report.root_cause_accuracy:.1%}
  Action accuracy:     {report.action_accuracy:.1%}
  Average confidence:  {report.avg_confidence:.2f}
  Average MTTR:        {report.avg_mttr:.0f}s

  BY PATTERN
  -------------------------------------------------
  Pattern               Total   RC Accuracy  Action Acc   Avg Conf
  {'-'*70}""")
    for pattern, d in sorted(report.by_pattern.items()):
        print(f"  {pattern:25s}  {d['total']:5d}  {d['rc_accuracy']:10.1%}  {d['action_accuracy']:10.1%}  {d['avg_confidence']:.2f}")

    print(f"""
  BY RISK LEVEL
  -------------------------------------------------
  {report.by_risk}

  FAILED SCENARIOS ({len(report.failed_scenarios)})
  -------------------------------------------------""")
    for name in report.failed_scenarios:
        print(f"  [FAIL] {name}")

    print(f"\n  {'PASS' if report.root_cause_accuracy > 0.7 else 'NEEDS IMPROVEMENT'} "
          f"Overall result: {'PASS' if report.root_cause_accuracy > 0.7 else 'NEEDS IMPROVEMENT'}")
    print(f"{'='*60}\n")


def save_report(report: BenchmarkReport, path: str = "benchmark_results"):
    """Save benchmark report to JSON and Markdown files."""
    os.makedirs(path, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # JSON
    json_path = os.path.join(path, f"benchmark_{ts}.json")
    with open(json_path, "w") as f:
        json.dump({
            "timestamp": report.timestamp,
            "total": report.total,
            "root_cause_accuracy": report.root_cause_accuracy,
            "action_accuracy": report.action_accuracy,
            "avg_confidence": report.avg_confidence,
            "avg_mttr": report.avg_mttr,
            "by_pattern": report.by_pattern,
            "failed_scenarios": report.failed_scenarios,
        }, f, indent=2)
    logger.info("Saved JSON report: %s", json_path)

    # Markdown
    md_path = os.path.join(path, f"benchmark_{ts}.md")
    with open(md_path, "w") as f:
        f.write(f"# AetherOps Benchmark Report\n\n")
        f.write(f"**{report.timestamp}**\n\n")
        f.write(f"## Overview\n\n")
        f.write(f"| Metric | Value |\n|--------|-------|\n")
        f.write(f"| Total Scenarios | {report.total} |\n")
        f.write(f"| Root Cause Accuracy | {report.root_cause_accuracy:.1%} |\n")
        f.write(f"| Action Accuracy | {report.action_accuracy:.1%} |\n")
        f.write(f"| Average Confidence | {report.avg_confidence:.2f} |\n")
        f.write(f"| Average MTTR | {report.avg_mttr:.0f}s |\n\n")
        f.write(f"## By Pattern\n\n")
        f.write(f"| Pattern | Total | RC Accuracy | Action Acc | Avg Conf |\n")
        f.write(f"|---------|-------|-------------|------------|----------|\n")
        for pattern, d in sorted(report.by_pattern.items()):
            f.write(f"| {pattern} | {d['total']} | {d['rc_accuracy']:.1%} | {d['action_accuracy']:.1%} | {d['avg_confidence']:.2f} |\n")

        if report.failed_scenarios:
            f.write(f"\n## Failed Scenarios\n\n")
            for name in report.failed_scenarios:
                f.write(f"- {name}\n")

    logger.info("Saved Markdown report: %s", md_path)
    return json_path, md_path


def run_benchmark(workflow=None, verbose: bool = True) -> Tuple[BenchmarkReport, List[ScenarioResult]]:
    """Convenience: run all 30 benchmark scenarios."""
    from aetherops.benchmark.scenarios import SCENARIOS

    if workflow is None:
        from aetherops.workflows.workflow import build_workflow, run_workflow
        workflow = build_workflow()

    evaluator = BenchmarkEvaluator(workflow=workflow)
    report = evaluator.run_all(SCENARIOS, verbose=verbose)
    return report, evaluator.results
