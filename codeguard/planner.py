"""P0 Repo Planner: maps entry points, dependencies, test commands, risk-ranks files, and estimates dry-run cost."""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .config import Config
from .discovery import read_text
from .workflow import TEST_RX

SENSITIVE_KEYWORDS = {
    "eval", "exec", "subprocess", "shell", "os.system", "popen",
    "password", "secret", "token", "api_key", "apikey", "private_key",
    "jwt", "sql", "cursor.execute", "authenticate", "authorize",
    "csrf", "cors", "pickle", "yaml.load", "requests", "urllib",
    "prompt", "completion", "openai", "anthropic", "llm"
}


@dataclass
class FileRisk:
    rel_path: str
    lines: int
    complexity: int
    sensitive_token_count: int
    risk_score: float  # 0.0 to 100.0
    reasons: List[str] = field(default_factory=list)


@dataclass
class RepoPlan:
    root: str
    languages: List[str]
    entry_points: List[str]
    dependencies: List[str]
    test_command: str
    files: List[FileRisk]
    total_files: int
    total_lines: int
    estimated_prompt_tokens: int
    estimated_cost_usd: float

    def summary(self) -> Dict[str, Any]:
        return {
            "root": self.root,
            "languages": self.languages,
            "entry_points": self.entry_points,
            "test_command": self.test_command,
            "total_files": self.total_files,
            "total_lines": self.total_lines,
            "top_risk_files": [f.rel_path for f in self.files[:5]],
            "estimated_tokens": self.estimated_prompt_tokens,
            "estimated_cost_usd": self.estimated_cost_usd,
        }


def compute_file_risk(rel_path: str, code: str) -> FileRisk:
    lines = len(code.splitlines())
    complexity = 1
    reasons = []

    # AST complexity for Python
    if rel_path.endswith(".py"):
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With)):
                    complexity += 1
        except Exception:
            complexity += 3
            reasons.append("syntax parse error or complex syntax")

    # Sensitive token analysis
    code_lower = code.lower()
    token_hits = 0
    for kw in SENSITIVE_KEYWORDS:
        if kw in code_lower:
            count = code_lower.count(kw)
            token_hits += min(count, 5)
            reasons.append(f"sensitive keyword '{kw}' ({count}x)")

    # Score calculation
    # Normalized: lines (max 30 pts) + complexity (max 35 pts) + keywords (max 35 pts)
    line_score = min(lines / 20.0, 30.0)
    comp_score = min(complexity * 2.0, 35.0)
    kw_score = min(token_hits * 3.5, 35.0)
    score = round(line_score + comp_score + kw_score, 1)

    return FileRisk(
        rel_path=rel_path,
        lines=lines,
        complexity=complexity,
        sensitive_token_count=token_hits,
        risk_score=score,
        reasons=reasons[:4],
    )


def plan_repo(root: Path, cfg: Config, src_files: List[str]) -> RepoPlan:
    root = Path(root).resolve()
    languages = set()
    entry_points = []
    dependencies = []
    risks: List[FileRisk] = []
    total_lines = 0

    # Detect languages
    for f in src_files:
        if f.endswith(".py"):
            languages.add("python")
        elif f.endswith((".js", ".jsx", ".mjs")):
            languages.add("javascript")
        elif f.endswith((".ts", ".tsx")):
            languages.add("typescript")
        elif f.endswith(".go"):
            languages.add("go")
        elif f.endswith(".rs"):
            languages.add("rust")

    # Detect entry points
    candidates = ["main.py", "app.py", "server.py", "cli.py", "index.js", "app.js", "server.js", "index.ts", "main.go"]
    for cand in candidates:
        for f in src_files:
            if f.endswith(cand) or f == cand:
                entry_points.append(f)

    # Detect dependencies
    req = root / "requirements.txt"
    if req.is_file():
        deps = [line.strip() for line in (read_text(req) or "").splitlines() if line.strip() and not line.startswith("#")]
        dependencies.extend(deps[:15])

    pkg = root / "package.json"
    if pkg.is_file():
        try:
            import json
            data = json.loads(read_text(pkg) or "{}")
            dependencies.extend(list(data.get("dependencies", {}).keys())[:15])
        except Exception:
            pass

    # Detect test command
    if "python" in languages:
        test_cmd = "pytest" if (root / "tests").is_dir() else "python -m unittest discover"
    elif "javascript" in languages or "typescript" in languages:
        test_cmd = "npm test"
    else:
        test_cmd = "unknown"

    # Analyze file risks
    for rel in src_files:
        text = read_text(root / rel) or ""
        total_lines += len(text.splitlines())
        risks.append(compute_file_risk(rel, text))

    # Sort descending by risk score
    risks.sort(key=lambda r: -r.risk_score)

    # Estimate prompt tokens and cost
    # Approx 1 token per 3.5 chars of code, plus 1000 prompt tokens per file
    total_chars = sum(len(read_text(root / r.rel_path) or "") for r in risks[:cfg.max_llm_files])
    est_tokens = int(total_chars / 3.5) + (len(risks[:cfg.max_llm_files]) * 1200)
    est_cost = round((est_tokens / 1_000_000) * 0.25, 4)

    return RepoPlan(
        root=str(root),
        languages=sorted(list(languages)),
        entry_points=sorted(list(set(entry_points))),
        dependencies=dependencies,
        test_command=test_cmd,
        files=risks,
        total_files=len(src_files),
        total_lines=total_lines,
        estimated_prompt_tokens=est_tokens,
        estimated_cost_usd=est_cost,
    )
