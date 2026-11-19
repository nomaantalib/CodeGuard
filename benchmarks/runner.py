"""Calibration Benchmark Runner: measures Precision, Recall, and F1 score against seeded ground-truth bugs."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

from codeguard.config import Config
from codeguard.scanner import scan_source


def run_benchmark(benchmark_dir: Optional[Path] = None) -> Tuple[float, float, float]:
    b_dir = benchmark_dir or Path(__file__).parent
    gt_file = b_dir / "ground_truth.json"
    if not gt_file.is_file():
        print(f"Error: ground_truth.json not found in {b_dir}", file=sys.stderr)
        return 0.0, 0.0, 0.0

    gt_data = json.loads(gt_file.read_text(encoding="utf-8"))
    cfg = Config(use_llm=False)
    from codeguard.scanner import build_context, collect
    inv = collect(b_dir, cfg)
    ctx = build_context(b_dir, inv, cfg)

    true_positives = 0
    false_positives = 0
    false_negatives = 0

    print("Running CodeGuard Calibration Benchmark...")
    print("-" * 60)

    for case in gt_data.get("cases", []):
        file_path = b_dir / case["file"]
        if not file_path.is_file():
            print(f"Skipping missing sample file: {file_path}", file=sys.stderr)
            continue

        code = file_path.read_text(encoding="utf-8")
        findings = scan_source(case["file"], code, ctx, cfg)
        detected_rules: Set[str] = {f.rule for f in findings}
        expected_rules: Set[str] = set(case.get("expected_rules", []))

        tp = len(detected_rules & expected_rules)
        fp = len(detected_rules - expected_rules)
        fn = len(expected_rules - detected_rules)

        true_positives += tp
        false_positives += fp
        false_negatives += fn

        status = "PASS" if fp == 0 and fn == 0 else "DIFF"
        print(f"[{status}] {case['file']:25s} | Expected: {list(expected_rules)} | Detected: {list(detected_rules)}")

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 1.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 1.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    print("-" * 60)
    print(f"Benchmark Results:")
    print(f"  True Positives : {true_positives}")
    print(f"  False Positives: {false_positives}")
    print(f"  False Negatives: {false_negatives}")
    print(f"  Precision      : {precision * 100:.1f}%")
    print(f"  Recall         : {recall * 100:.1f}%")
    print(f"  F1 Score       : {f1 * 100:.1f}%")
    print("-" * 60)

    return precision, recall, f1


if __name__ == "__main__":
    p, r, f1 = run_benchmark()
    # Calibration regression gate: require F1 >= 80%
    if f1 < 0.80:
        print(f"FAILED: Benchmark F1 score {f1*100:.1f}% is below regression threshold 80%", file=sys.stderr)
        sys.exit(1)
    print("SUCCESS: Calibration benchmark passed.")
    sys.exit(0)
