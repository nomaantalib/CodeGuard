"""Shared data models."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    rule: str
    severity: str
    category: str  # security | tests | quality | workflow | deps
    file: str
    line: int
    message: str
    hint: str = ""
    end_line: int = 0
    source: str = "builtin"  # builtin | bandit | ruff | pip-audit | llm
    fixable: bool = False  # a deterministic auto-fixer exists for this finding

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RunResult:
    """Outcome of running a project's test suite."""

    framework: str = "none"
    ran: bool = False
    passed: int = 0
    failed: int = 0
    errors: int = 0
    returncode: int = 0
    duration: float = 0.0
    note: str = ""
    output_tail: str = ""

    @property
    def total(self) -> int:
        return self.passed + self.failed + self.errors

    @property
    def bad(self) -> int:
        return self.failed + self.errors


@dataclass
class FixRecord:
    file: str
    method: str  # deterministic | llm
    rules: List[str]
    status: str  # accepted | reverted
    detail: str = ""


@dataclass
class Report:
    target: str
    version: str
    started: str
    duration: float
    files_scanned: int
    llm_used: bool
    sandbox: str
    findings_before: List[Finding]
    findings_after: List[Finding]
    tests_before: Optional[RunResult]
    tests_after: Optional[RunResult]
    score_before: Dict[str, Any]
    score_after: Dict[str, Any]
    fixes: List[FixRecord] = field(default_factory=list)
    patch: str = ""
    gate: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["patch_bytes"] = len(d.pop("patch") or "")
        return d
