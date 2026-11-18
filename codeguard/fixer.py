"""Deterministic, line-level auto-fixers. Every fix is verified (syntax + tests) by the pipeline."""
from __future__ import annotations

import ast
import re
from typing import Callable, Dict, List, Optional, Set, Tuple

from .models import Finding
from .rules.generic import SIMPLE_ASSIGN


def ensure_import(src: str, module: str) -> str:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return src
    for n in tree.body:
        if isinstance(n, ast.Import) and any(a.name == module and not a.asname for a in n.names):
            return src
    insert_after = 0
    for i, n in enumerate(tree.body):
        if i == 0 and isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str):
            insert_after = n.end_lineno
        elif isinstance(n, ast.ImportFrom) and n.module == "__future__":
            insert_after = n.end_lineno
        else:
            break
    lines = src.splitlines(keepends=True)
    lines.insert(insert_after, f"import {module}\n")
    return "".join(lines)


def _eval(l: str) -> str:
    return re.sub(r"(?<![\w.])eval\(", "ast.literal_eval(", l)


LINE_FIXERS: Dict[str, Tuple[Callable[[str], str], Optional[str]]] = {
    "PY001": (_eval, "ast"),
    "PY004": (lambda l: re.sub(r"\byaml\.load\(", "yaml.safe_load(", l), None),
    "PY006": (lambda l: re.sub(r"\bhashlib\.(?:md5|sha1)\(", "hashlib.sha256(", l), None),
    "PY007": (lambda l: re.sub(r"verify\s*=\s*False", "verify=True", l), None),
    "PY008": (lambda l: re.sub(r"^(\s*)except\s*:", r"\1except Exception:", l), None),
    "PY012": (lambda l: re.sub(r"(?i)\b(debug\s*=\s*)True\b", r"\1False", l), None),
}
SECRET_LINE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([\"']).*\3\s*$")


def fixable_rules(findings: List[Finding]) -> List[str]:
    return sorted({f.rule for f in findings if f.fixable and (f.rule in LINE_FIXERS or f.rule == "SEC001")})


def apply_rule(src: str, findings: List[Finding], rule: str) -> str:
    """Apply one rule's deterministic fix to every matching finding; returns new source."""
    lines = src.splitlines(keepends=True)
    needs: Set[str] = set()
    for f in findings:
        if f.rule != rule or not f.fixable:
            continue
        if rule == "SEC001":
            i = f.line - 1
            if 0 <= i < len(lines) and SIMPLE_ASSIGN.match(lines[i]):
                m = SECRET_LINE.match(lines[i].rstrip("\n"))
                if m:
                    nl = "\n" if lines[i].endswith("\n") else ""
                    lines[i] = f'{m.group(1)}{m.group(2)} = os.environ.get("{m.group(2)}", ""){nl}'
                    needs.add("os")
            continue
        fn, imp = LINE_FIXERS[rule]
        for i in range(max(f.line - 1, 0), min(max(f.end_line, f.line), len(lines))):
            new = fn(lines[i])
            if new != lines[i]:
                lines[i] = new
                if imp:
                    needs.add(imp)
    out = "".join(lines)
    for mod in sorted(needs):
        out = ensure_import(out, mod)
    return out


def check_syntax(rel: str, src: str) -> Optional[str]:
    """Return an error string if the source is not valid, else None."""
    if rel.endswith(".py"):
        try:
            ast.parse(src)
        except (SyntaxError, ValueError) as e:
            return f"syntax error: {e}"
    return None
