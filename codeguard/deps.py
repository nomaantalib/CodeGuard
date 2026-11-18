"""Dependency checks: declared packages (for import resolution) and pinning hygiene."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Set, Tuple

from .discovery import Inventory, read_text
from .models import Finding
from .rules.catalog import mk

REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*([^;#]*)")


def parse_requirements(text: str) -> List[Tuple[str, str]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        m = REQ.match(line)
        if m:
            out.append((m.group(1), m.group(2).strip()))
    return out


def _req_files(inv: Inventory) -> List[str]:
    return [r for r in inv.all if re.search(r"(^|/)requirements[^/]*\.txt$", r)]


def declared_python(root: Path, inv: Inventory) -> Set[str]:
    names: Set[str] = set()
    for rel in _req_files(inv):
        t = read_text(root / rel)
        if t:
            names |= {n for n, _ in parse_requirements(t)}
    py = root / "pyproject.toml"
    if py.is_file():
        t = read_text(py) or ""
        try:
            import tomllib
            data = tomllib.loads(t)
            deps = list(data.get("project", {}).get("dependencies", []))
            for group in data.get("project", {}).get("optional-dependencies", {}).values():
                deps += group
            deps += list(data.get("tool", {}).get("poetry", {}).get("dependencies", {}).keys())
            names |= {re.split(r"[\s\[<>=!~;]", d, 1)[0] for d in deps if d}
        except Exception:
            for m in re.finditer(r"""["']([A-Za-z0-9][A-Za-z0-9._-]*)\s*[<>=!~\[;"']""", t):
                names.add(m.group(1))
    for rel in ("setup.py", "Pipfile"):
        t = read_text(root / rel) if (root / rel).is_file() else None
        if t:
            names |= set(re.findall(r"""["']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~\[][^"']*)?["']""", t))
    return names


def check(root: Path, inv: Inventory) -> List[Finding]:
    out: List[Finding] = []
    for rel in _req_files(inv):
        t = read_text(root / rel)
        if not t:
            continue
        loose = [n for n, spec in parse_requirements(t) if not re.search(r"(==|~=|===)", spec)]
        if loose:
            shown = ", ".join(loose[:5]) + ("..." if len(loose) > 5 else "")
            out.append(mk("DEP001", rel, 1, f"{len(loose)} dependency(ies) not pinned to an exact version: {shown}",
                          "Pin with == (or use a lock file) so builds are reproducible and auditable."))
    pj = root / "package.json"
    if "package.json" in inv.all and pj.is_file():
        try:
            data = json.loads(read_text(pj) or "{}")
            loose = [n for sect in ("dependencies", "devDependencies") for n, v in (data.get(sect) or {}).items()
                     if str(v).strip() in ("*", "latest", "")]
            if loose:
                out.append(mk("DEP001", "package.json", 1, f"Unpinned npm dependencies: {', '.join(loose[:5])}", "Use a concrete semver range."))
        except (ValueError, AttributeError):
            pass
    return out
