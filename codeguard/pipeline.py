"""The review -> fix -> verify pipeline.

Safety model: all edits happen in a throw-away copy of the project. A fix is only
kept if (1) the file still parses, (2) the project's tests do not get worse, and
(3) for AI fixes, built-in findings for that file do not increase. Nothing touches
your working tree unless you pass --apply.
"""
from __future__ import annotations

import difflib
import os
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from . import __version__, fixer, scanner
from .config import Config
from .discovery import read_text
from .llm import LLM
from .models import SEV_RANK, Finding, FixRecord, Report, RunResult
from .rules.catalog import RULES
from .scoring import penalty, score
from .testrunner import regressed, run_tests


def _workspace(root: Path) -> Tuple[Path, Path]:
    tmp = Path(tempfile.mkdtemp(prefix="codeguard-"))
    work = tmp / "work"
    ignore = shutil.ignore_patterns(".git", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache",
                                    "node_modules", ".tox", "codeguard-report")
    shutil.copytree(root, work, ignore=ignore, symlinks=True)
    nm = root / "node_modules"
    if nm.is_dir():
        try:
            os.symlink(nm, work / "node_modules")
        except OSError:
            pass
    return tmp, work


def _patch(root: Path, work: Path, changed: List[str]) -> str:
    out: List[str] = []
    for rel in changed:
        a = (read_text(root / rel) or "").splitlines(keepends=True)
        b = (read_text(work / rel) or "").splitlines(keepends=True)
        for line in difflib.unified_diff(a, b, f"a/{rel}", f"b/{rel}"):
            out.append(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n")
    return "".join(out)


def _gate(findings: List[Finding], sc: Dict, cfg: Config) -> Dict:
    reasons = []
    if cfg.fail_under and sc["overall"] < cfg.fail_under:
        reasons.append(f"score {sc['overall']} is below the required {cfg.fail_under}")
    if cfg.fail_on:
        n = sum(1 for f in findings if SEV_RANK[f.severity] >= SEV_RANK[cfg.fail_on])
        if n:
            reasons.append(f"{n} finding(s) at or above severity '{cfg.fail_on}'")
    return {"passed": not reasons, "reasons": reasons}


def review(root, cfg: Config, fix: bool = False, apply: bool = False,
           log: Optional[Callable[[str], None]] = None) -> Report:
    log = log or (lambda m: None)
    root = Path(root).resolve()
    t0, started = time.time(), datetime.now(timezone.utc).isoformat(timespec="seconds")
    notes: List[str] = []
    llm = LLM(cfg) if cfg.use_llm else None
    llm_on = bool(llm and llm.available)
    if cfg.use_llm and not llm_on:
        notes.append("AI review/fix unavailable. Check the configured local Ollama service/model or provider credentials. Static rules and tests still ran.")
    elif llm_on and llm:
        if cfg.model != llm.model:
            notes.append(f"AI: auto-selected installed Ollama model '{llm.model}' (requested '{cfg.model}')")
            cfg.model = llm.model

    log("Scanning project...")
    before, inv, ctx = scanner.scan_project(root, cfg)
    src_set = set(inv.src)
    tmp, work = _workspace(root)
    try:
        tests_before: Optional[RunResult] = None
        if cfg.run_tests:
            log("Running test suite (baseline)...")
            tests_before = run_tests(work, cfg, inv.all)
            if tests_before.note:
                notes.append(f"Tests: {tests_before.note}")

        llm_findings: List[Finding] = []
        if llm_on:
            log("AI review...")
            counts: Dict[str, int] = {}
            for f in before:
                counts[f.file] = counts.get(f.file, 0) + 1
            order = sorted(inv.src, key=lambda r: -counts.get(r, 0))[:cfg.max_llm_files]
            for rel in order:
                src = read_text(root / rel)
                if src and len(src) < 40000:
                    llm_findings += llm.review(rel, src, [f for f in before if f.file == rel])
            before = scanner._finalize(before + llm_findings, cfg)

        fixes: List[FixRecord] = []
        patch, final, tests_after = "", before, tests_before
        if fix:
            baseline = tests_before or RunResult()
            originals: Dict[str, str] = {}
            llm_fixed = set()
            llm_count = 0
            files = sorted({f.file for f in before if f.file in src_set},
                           key=lambda r: -penalty(f for f in before if f.file == r))

            def attempt(rel: str, path: Path, cur: str, new: str, rules: List[str], method: str) -> str:
                err = fixer.check_syntax(rel, new)
                if err:
                    fixes.append(FixRecord(rel, method, rules, "reverted", err))
                    return cur
                path.write_text(new, encoding="utf-8")
                if cfg.run_tests and cfg.verify_each and baseline.ran:
                    res = run_tests(work, cfg, inv.all)
                    if regressed(res, baseline):
                        path.write_text(cur, encoding="utf-8")
                        fixes.append(FixRecord(rel, method, rules, "reverted",
                                               f"tests regressed ({baseline.bad} -> {res.bad} failing)"))
                        return cur
                fixes.append(FixRecord(rel, method, rules, "accepted",
                                       "; ".join(RULES[r][2] for r in rules if r in RULES)[:200]))
                return new

            for rel in files:
                path = work / rel
                cur = read_text(path)
                if cur is None:
                    continue
                originals[rel] = cur
                for rule in fixer.fixable_rules([f for f in before if f.file == rel]):
                    cur_findings = scanner.scan_source(rel, cur, ctx, cfg)
                    if not any(f.rule == rule and f.fixable for f in cur_findings):
                        continue
                    new = fixer.apply_rule(cur, cur_findings, rule)
                    if new != cur:
                        log(f"Fixing {rel} [{rule}]")
                        cur = attempt(rel, path, cur, new, [rule], "deterministic")
                if llm_on and llm_count < cfg.max_llm_files and len(cur) < 60000:
                    now = scanner.scan_source(rel, cur, ctx, cfg)
                    remaining = [f for f in now if SEV_RANK[f.severity] >= SEV_RANK["low"]]
                    remaining += [f for f in llm_findings if f.file == rel]
                    if remaining:
                        llm_count += 1
                        log(f"AI fix for {rel}...")
                        new = llm.fix(rel, cur, remaining)
                        rules = sorted({f.rule for f in remaining})[:6]
                        if new and new.strip() and new != cur and len(new) <= 3 * len(cur) + 200:
                            if penalty(scanner.scan_source(rel, new, ctx, cfg)) > penalty(now):
                                fixes.append(FixRecord(rel, "llm", rules, "reverted", "AI patch introduced new findings"))
                            else:
                                if attempt(rel, path, cur, new, rules, "llm") == new:
                                    llm_fixed.add(rel)

            if cfg.run_tests and not cfg.verify_each and baseline.ran and fixes:
                res = run_tests(work, cfg, inv.all)
                if regressed(res, baseline):
                    for rel, text in originals.items():
                        (work / rel).write_text(text, encoding="utf-8")
                    for fr in fixes:
                        if fr.status == "accepted":
                            fr.status, fr.detail = "reverted", "tests regressed after batch fixes"

            changed = [r for r in originals if read_text(work / r) != read_text(root / r)]
            patch = _patch(root, work, changed)
            log("Re-scanning fixed code...")
            rescanned, _, _ = scanner.scan_project(work, cfg)
            final = scanner._finalize(rescanned + [f for f in llm_findings if f.file not in llm_fixed], cfg)
            if cfg.run_tests and changed:
                tests_after = run_tests(work, cfg, inv.all)
            if apply:
                for rel in changed:
                    (root / rel).write_text(read_text(work / rel) or "", encoding="utf-8")
                notes.append(f"Applied fixes to {len(changed)} file(s) in place.")
            elif changed:
                notes.append(f"{len(changed)} file(s) have verified fixes in the patch; re-run with --apply to write them.")

        sb, sa = score(before, tests_before), score(final, tests_after)
        gate = _gate(final if apply else before, sa if apply else sb, cfg)
        return Report(target=str(root), version=__version__, started=started, duration=round(time.time() - t0, 2),
                      files_scanned=len(inv.src) + len(inv.text_only), llm_used=llm_on, sandbox=cfg.sandbox,
                      findings_before=before, findings_after=final, tests_before=tests_before,
                      tests_after=tests_after, score_before=sb, score_after=sa, fixes=fixes, patch=patch,
                      gate=gate, notes=notes)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
