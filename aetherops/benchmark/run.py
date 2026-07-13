#!/usr/bin/env python3
"""AetherOps — Run the full 30-scenario benchmark and print report.

Usage:
    python -m aetherops.benchmark.run                 # Quick run (no workflow)
    python -m aetherops.benchmark.run --workflow      # Run with workflow
    python -m aetherops.benchmark.run --pattern cache_avalanche  # Single pattern
    python -m aetherops.benchmark.run --verbose       # Full detail
"""

from __future__ import annotations

import argparse
import logging
import sys

logging.basicConfig(level=logging.WARNING, format="%(message)s")


def main():
    parser = argparse.ArgumentParser(description="AetherOps Incident Benchmark")
    parser.add_argument("--workflow", action="store_true", help="Run with actual LangGraph workflow")
    parser.add_argument("--pattern", type=str, default="", help="Run only specific fault pattern")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose per-scenario output")
    parser.add_argument("--save", type=str, default="", help="Save report to directory")
    args = parser.parse_args()

    from aetherops.benchmark.scenarios import SCENARIOS
    from aetherops.benchmark.evaluator import BenchmarkEvaluator, print_report, save_report

    # Resolve scenarios
    scenarios = (
        [s for s in SCENARIOS if s.pattern == args.pattern]
        if args.pattern else SCENARIOS
    )

    print(f"\n  AetherOps Benchmark: {len(scenarios)} scenarios")
    if args.pattern:
        print(f"  Pattern filter: {args.pattern}")
    print()

    if args.workflow:
        print("  Loading workflow...")
        from aetherops.workflows.workflow import build_workflow
        workflow = build_workflow()
    else:
        print("  +------------------- BENCHMARK MODE -------------------+")
        print("  | Running standalone benchmark (no workflow)               |")
        print("  | Use --workflow to run with the full agent pipeline       |")
        print("  +-----------------------------------------------------+")
        workflow = None

    evaluator = BenchmarkEvaluator(workflow=workflow)
    report = evaluator.run_all(scenarios, verbose=args.verbose)

    print_report(report)

    if args.save:
        json_path, md_path = save_report(report, args.save)
        print(f"  Reports saved:\n    JSON: {json_path}\n    MD:   {md_path}")

    return 0 if report.root_cause_accuracy > 0.7 else 1


if __name__ == "__main__":
    sys.exit(main())
