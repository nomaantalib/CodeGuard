"""Scoring: Composite 70% LLM reasoning + 30% deterministic evidence.

Bands:
>= 80: Good
30-79: Needs Work
< 30: CRITICAL (generates prioritized remediation fix plan)
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from .models import Finding, RunResult

PENALTY = {"critical": 30, "high": 15, "medium": 6, "low": 2, "info": 0}
WEIGHTS = {"security": 0.35, "tests": 0.25, "quality": 0.15, "workflow": 0.10, "deps": 0.15}
NO_TESTS_SCORE = 40


def grade(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"


def band(overall: int) -> str:
    if overall >= 80:
        return "Good"
    if overall >= 30:
        return "Needs Work"
    return "CRITICAL"


def penalty(findings: Iterable[Finding]) -> int:
    return sum(PENALTY.get(f.severity, 0) for f in findings)


def score(findings: Iterable[Finding], tests: Optional[RunResult]) -> Dict:
    """Deterministic score calculation (backward-compatible with v0.1)."""
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
    return {
        "overall": overall,
        "grade": grade(overall),
        "band": band(overall),
        "categories": cats,
        "counts": counts,
        "total": len(findings),
        "is_partial": False,
    }


def composite_score(
    findings: List[Finding],
    tests: Optional[RunResult],
    llm_used: bool = False,
    llm_weight: float = 0.70,
    det_weight: float = 0.30,
) -> Dict:
    """70% LLM reasoning + 30% deterministic evidence composite scorecard."""
    det = score([f for f in findings if f.source != "llm_v2"], tests)
    det_score = det["overall"]

    if not llm_used:
        # Honest reporting: never invent an LLM score if LLM was unavailable
        det["status"] = "PARTIAL (Deterministic Only)"
        det["is_partial"] = True
        det["llm_score"] = None
        det["deterministic_score"] = det_score
        return det

    # LLM reasoning score rubric per dimension (0-100)
    llm_findings = [f for f in findings if f.source in ("llm", "llm_v2")]
    dim_penalties = {
        "correctness": 0,
        "security": 0,
        "reasoning": 0,
        "robustness": 0,
        "tests": 0,
        "maintainability": 0,
    }

    for f in llm_findings:
        p = PENALTY.get(f.severity, 5)
        cat = getattr(f, "category", "correctness").lower()
        if "sec" in cat:
            dim_penalties["security"] += p
        elif "rob" in cat:
            dim_penalties["robustness"] += p
        elif "test" in cat:
            dim_penalties["tests"] += p
        elif "maint" in cat:
            dim_penalties["maintainability"] += p
        else:
            dim_penalties["correctness"] += p

    rubric = {dim: max(0, 100 - pen) for dim, pen in dim_penalties.items()}
    avg_llm_score = round(sum(rubric.values()) / len(rubric))

    # Normalize weights
    total_w = llm_weight + det_weight
    final_score = round((llm_weight * avg_llm_score + det_weight * det_score) / total_w)

    current_band = band(final_score)
    fix_plan = []
    if current_band == "CRITICAL":
        critical_findings = [f for f in findings if f.severity in ("critical", "high")]
        for idx, f in enumerate(critical_findings[:5], 1):
            fix_plan.append(f"Step {idx}: Address {f.severity.upper()} issue at {f.file}:{f.line} - {f.message}")

    return {
        "overall": final_score,
        "grade": grade(final_score),
        "band": current_band,
        "status": "FINAL",
        "is_partial": False,
        "llm_score": avg_llm_score,
        "deterministic_score": det_score,
        "rubric": rubric,
        "categories": det["categories"],
        "counts": det["counts"],
        "total": len(findings),
        "prioritized_fix_plan": fix_plan,
    }
