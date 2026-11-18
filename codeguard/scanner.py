"""Static scan orchestration."""
from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

from . import deps, external, workflow
from .config import Config
from .discovery import JS_EXT, Inventory, collect, read_text
from .models import SEV_RANK, Finding
from .rules import generic, python_rules


def build_context(root: Path, inv: Inventory, cfg: Config) -> python_rules.Context:
    local = set()
    for rel in inv.src:
        parts = rel.split("/")
        local.update(parts[:-1])
        local.add(parts[-1].rsplit(".", 1)[0])
    return python_rules.Context(deps.declared_python(root, inv), local, cfg.max_complexity)


def scan_source(rel: str, src: str, ctx: python_rules.Context, cfg: Config) -> List[Finding]:
    """Built-in rules for a single source file (fast; used again after every fix)."""
    out: List[Finding] = []
    if rel.endswith(".py"):
        out += python_rules.scan_python(rel, src, ctx)
    elif rel.lower().endswith(JS_EXT):
        out += generic.scan_js(rel, src)
    out += generic.scan_secrets(rel, src)
    out += generic.scan_markers(rel, src)
    out = generic.apply_suppressions(out, src)
    return [f for f in out if f.rule not in cfg.disabled_rules]


def _finalize(findings: List[Finding], cfg: Config) -> List[Finding]:
    seen, out = set(), []
    for f in findings:
        k = (f.rule, f.file, f.line, f.message)
        if f.rule in cfg.disabled_rules or k in seen:
            continue
        seen.add(k)
        out.append(f)
    out.sort(key=lambda f: (-SEV_RANK.get(f.severity, 0), f.file, f.line))
    return out


def scan_project(root: Path, cfg: Config, external_tools: bool = True) -> Tuple[List[Finding], Inventory, python_rules.Context]:
    root = Path(root)
    inv = collect(root, cfg)
    ctx = build_context(root, inv, cfg)
    findings: List[Finding] = []
    for rel in inv.src:
        text = read_text(root / rel)
        if text is not None:
            findings += scan_source(rel, text, ctx, cfg)
    for rel in inv.text_only:
        text = read_text(root / rel)
        if text is not None:
            findings += generic.apply_suppressions(generic.scan_secrets(rel, text), text)
    findings += workflow.check_project(root, inv)
    findings += deps.check(root, inv)
    if external_tools and cfg.use_external_tools:
        findings += external.run_all(root, cfg)
    return _finalize(findings, cfg), inv, ctx
