"""Scoring: 0-100 per category, weighted into one overall grade."""
from __future__ import annotations

from typing import Dict, Iterable, Optional

from .models import Finding, RunResult

PENALTY = {"critical": 30, "high": 15, "medium": 6, "low": 2, "info": 0}
WEIGHTS = {"security": 0.35, "tests": 0.25, "quality": 0.15, "workflow": 0.10, "deps": 0.15}
NO_TESTS_SCORE = 40


def grade(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"


def penalty(findings: Iterable[Finding]) -> int:
    return sum(PENALTY.get(f.severity, 0) for f in findings)


def score(findings: Iterable[Finding], tests: Optional[RunResult]) -> Dict:
    findings = list(findings)
    cats: Dict[str, Optional[int]] = {}
    for c in ("security", "quality", "workflow", "deps"):
        cats[c] = max(0, 100 - penalty(f for f in findings if f.category == c))
    if tests is None:
        cats["tests"] = None  # tests were not run: weight is redistributed
    elif tests.ran and tests.total > 0:
        cats["tests"] = round(100 * tests.passed / tests.total)
    else:
        cats["tests"] = NO_TESTS_SCORE
    live = {c: v for c, v in cats.items() if v is not None}
    wsum = sum(WEIGHTS[c] for c in live)
    overall = round(sum(WEIGHTS[c] * v for c, v in live.items()) / wsum) if wsum else 0
    counts = {s: 0 for s in PENALTY}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {"overall": overall, "grade": grade(overall), "categories": cats, "counts": counts, "total": len(findings)}
