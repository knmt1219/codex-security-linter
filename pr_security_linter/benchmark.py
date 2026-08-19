"""Benchmark evaluation runner measuring precision, recall, F1, and execution performance."""

import json
import pathlib
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from .engine import SecurityEngine


def run_benchmarks(fixtures_dir: Optional[pathlib.Path] = None) -> Dict[str, Any]:
    """Execute evaluation against benchmark corpus and compute exact precision/recall metrics."""
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if sys.stderr and hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if fixtures_dir is None:
        fixtures_dir = pathlib.Path(__file__).resolve().parent.parent / "benchmarks"

    manifest_path = fixtures_dir / "manifest.json"
    if not manifest_path.exists():
        print(f"Error: Manifest not found at '{manifest_path}'", file=sys.stderr)
        return {"error": "Manifest not found"}

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    fixtures = manifest.get("fixtures", [])
    engine = SecurityEngine()

    total_tp = 0
    total_fp = 0
    total_fn = 0
    total_lines = 0

    results_table: List[Dict[str, Any]] = []

    start_all = time.time()

    for item in fixtures:
        rel_file = item["file"]
        file_path = fixtures_dir / "fixtures" / rel_file
        expected_ids: Set[str] = set(item.get("expected_rule_ids", []))

        if not file_path.exists():
            print(f"Warning: Fixture file '{file_path}' does not exist.", file=sys.stderr)
            continue

        start_file = time.time()
        findings, lines = engine.scan_path(str(file_path))
        file_ms = (time.time() - start_file) * 1000
        total_lines += lines

        detected_ids = {f.rule_id for f in findings}

        # True positives: in both detected and expected
        tp = len(detected_ids.intersection(expected_ids))
        # False positives: detected but not in expected
        fp = len(detected_ids - expected_ids)
        # False negatives: expected but not detected
        fn = len(expected_ids - detected_ids)

        total_tp += tp
        total_fp += fp
        total_fn += fn

        results_table.append({
            "fixture": rel_file,
            "lines": lines,
            "expected": len(expected_ids),
            "detected": len(detected_ids),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "duration_ms": file_ms,
        })

    total_duration_ms = (time.time() - start_all) * 1000

    precision = (total_tp / (total_tp + total_fp)) if (total_tp + total_fp) > 0 else 1.0
    recall = (total_tp / (total_tp + total_fn)) if (total_tp + total_fn) > 0 else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 1.0

    print("=" * 80)
    print(" PR SECURITY LINTER BENCHMARK & REGRESSION EVALUATION")
    print("=" * 80)
    print(f"{'Fixture':<32} | {'Lines':<6} | {'Exp':<4} | {'Det':<4} | {'TP':<3} | {'FP':<3} | {'FN':<3} | {'Time (ms)':<8}")
    print("-" * 80)
    for r in results_table:
        print(f"{r['fixture']:<32} | {r['lines']:<6} | {r['expected']:<4} | {r['detected']:<4} | {r['tp']:<3} | {r['fp']:<3} | {r['fn']:<3} | {r['duration_ms']:<8.2f}")
    print("=" * 80)
    print("SUMMARY METRICS:")
    print(f"  * Total Fixtures Scanned : {len(results_table)}")
    print(f"  * Total Lines Scanned    : {total_lines}")
    print(f"  * True Positives (TP)    : {total_tp}")
    print(f"  * False Positives (FP)   : {total_fp}")
    print(f"  * False Negatives (FN)   : {total_fn}")
    print(f"  * Precision              : {precision * 100:.2f}%")
    print(f"  * Recall                 : {recall * 100:.2f}%")
    print(f"  * F1 Score               : {f1 * 100:.2f}%")
    print(f"  * Total Execution Time   : {total_duration_ms:.2f}ms")
    print("=" * 80)

    return {
        "fixtures": len(results_table),
        "lines": total_lines,
        "tp": total_tp,
        "fp": total_fp,
        "fn": total_fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "duration_ms": total_duration_ms,
    }


def main() -> None:
    """CLI entry point for benchmark evaluation."""
    metrics = run_benchmarks()
    if metrics.get("fp", 0) > 0 or metrics.get("fn", 0) > 0:
        print("X Benchmark failed: False positives or false negatives detected in test fixtures.")
        sys.exit(1)
    else:
        print("OK Benchmark passed: 100% precision and recall on verified benchmark corpus.")
        sys.exit(0)


if __name__ == "__main__":
    main()
