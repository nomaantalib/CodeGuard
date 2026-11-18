"""Optional bridges to best-in-class tools when they are installed (bandit, ruff, pip-audit)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import List

from .config import Config
from .models import Finding
from .rules.catalog import mk

BANDIT_SEV = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def _run(cmd, cwd, timeout=180):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None


def _rel(root: Path, name: str) -> str:
    try:
        return Path(os.path.relpath(name, root)).as_posix()
    except ValueError:
        return name


def run_bandit(root: Path, cfg: Config) -> List[Finding]:
    if not shutil.which("bandit"):
        return []
    excl = ",".join(str(root / d) for d in cfg.ignore_dirs)
    p = _run(["bandit", "-r", str(root), "-f", "json", "-q", "-x", excl], root)
    if not p or not p.stdout.strip():
        return []
    try:
        data = json.loads(p.stdout)
    except ValueError:
        return []
    out = []
    for r in data.get("results", []):
        f = mk("LLM001", _rel(root, r["filename"]), r.get("line_number", 1), f"[bandit {r['test_id']}] {r['issue_text']}",
               r.get("more_info", ""), severity=BANDIT_SEV.get(r.get("issue_severity", "LOW"), "low"), source="bandit")
        f.rule, f.category = r["test_id"], "security"
        out.append(f)
    return out


def run_ruff(root: Path, cfg: Config) -> List[Finding]:
    if not shutil.which("ruff"):
        return []
    p = _run(["ruff", "check", "--output-format=json", "--no-cache", str(root)], root)
    if not p or not p.stdout.strip():
        return []
    try:
        data = json.loads(p.stdout)
    except ValueError:
        return []
    out = []
    for r in data:
        code = r.get("code") or "ruff"
        sev = "medium" if code.startswith(("F8", "E9", "F6", "F7")) else "low"
        f = mk("LLM001", _rel(root, r["filename"]), (r.get("location") or {}).get("row", 1),
               f"[ruff {code}] {r.get('message', '')}", severity=sev, source="ruff")
        f.rule, f.category = code, "quality"
        out.append(f)
    return out


def run_pip_audit(root: Path, cfg: Config) -> List[Finding]:
    req = root / "requirements.txt"
    if not shutil.which("pip-audit") or not req.is_file():
        return []
    p = _run(["pip-audit", "-r", str(req), "-f", "json", "--progress-spinner", "off"], root, 240)
    if not p or not p.stdout.strip():
        return []
    try:
        data = json.loads(p.stdout)
    except ValueError:
        return []
    out = []
    for d in data.get("dependencies", []):
        for v in d.get("vulns", []):
            fix = ", ".join(v.get("fix_versions", [])) or "no fix yet"
            out.append(mk("DEP002", "requirements.txt", 1, f"{d['name']}=={d.get('version')} has {v['id']} (fix: {fix})",
                          "Upgrade the dependency.", source="pip-audit"))
    return out


def run_all(root: Path, cfg: Config) -> List[Finding]:
    return run_bandit(root, cfg) + run_ruff(root, cfg) + run_pip_audit(root, cfg)
