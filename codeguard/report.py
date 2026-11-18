"""Report writers: Markdown (PR comments), HTML (shareable), JSON (machines), patch."""
from __future__ import annotations

import html
import json
from pathlib import Path
from typing import List

from .models import Finding, Report
from .rules.catalog import RULES

EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def _tests_line(t) -> str:
    if t is None:
        return "not run"
    if not t.ran:
        return t.note or "no tests"
    return f"{t.passed} passed, {t.failed} failed, {t.errors} errors ({t.framework}, {t.duration:.1f}s)"


def _arrow(a, b) -> str:
    return "n/a" if a is None else (str(a) if a == b else f"{a} -> {b}")


def to_markdown(r: Report, limit: int = 40) -> str:
    sb, sa = r.score_before, r.score_after
    fixed = any(f.status == "accepted" for f in r.fixes)
    L: List[str] = [f"# CodeGuard report", ""]
    head = f"**Score {sb['overall']} ({sb['grade']})**"
    if fixed or sb["overall"] != sa["overall"]:
        head = f"**Score {sb['overall']} ({sb['grade']}) -> {sa['overall']} ({sa['grade']}) after verified fixes**"
    L += [head, "", f"{sb['total']} finding(s) -> {sa['total']} | Tests: {_tests_line(r.tests_after or r.tests_before)} | "
          f"AI: {'on' if r.llm_used else 'off'} | Sandbox: {r.sandbox}", ""]
    L += ["| Category | Before | After |", "|---|---|---|"]
    for c in ("security", "tests", "quality", "workflow", "deps"):
        L.append(f"| {c} | {_arrow(sb['categories'][c], sb['categories'][c])} | {_arrow(sa['categories'][c], sa['categories'][c])} |")
    L.append("")
    if r.gate and not r.gate.get("passed", True):
        L += ["> ❌ **Quality gate failed:** " + "; ".join(r.gate["reasons"]), ""]
    if r.fixes:
        L += ["## Fixes", ""]
        for f in r.fixes:
            icon = "✅" if f.status == "accepted" else "↩️"
            L.append(f"- {icon} `{f.file}` ({f.method}): {', '.join(f.rules)} - {f.status}" + (f" - {f.detail}" if f.detail else ""))
        L.append("")
    L += [f"## Findings ({len(r.findings_after)})", ""]
    if r.findings_after:
        L += ["| Sev | Rule | Location | Issue |", "|---|---|---|---|"]
        for f in r.findings_after[:limit]:
            L.append(f"| {EMOJI[f.severity]} {f.severity} | {f.rule} | `{f.file}:{f.line}` | {f.message.replace('|', '/')} |")
        if len(r.findings_after) > limit:
            L.append(f"\n_...and {len(r.findings_after) - limit} more in the JSON/HTML report._")
    else:
        L.append("No findings. 🎉")
    if r.notes:
        L += ["", "## Notes", ""] + [f"- {n}" for n in r.notes]
    return "\n".join(L) + "\n"


def to_html(r: Report) -> str:
    e = html.escape
    sb, sa = r.score_before, r.score_after

    def rows(fs: List[Finding]) -> str:
        return "".join(
            f"<tr><td class='s-{f.severity}'>{f.severity}</td><td>{e(f.rule)}</td><td><code>{e(f.file)}:{f.line}</code></td>"
            f"<td>{e(f.message)}<div class='hint'>{e(f.hint)}</div></td></tr>" for f in fs) or "<tr><td colspan=4>No findings</td></tr>"

    cats = "".join(f"<div class='card'><div class='k'>{c}</div><div class='v'>{_arrow(sb['categories'][c], sa['categories'][c])}</div></div>"
                   for c in ("security", "tests", "quality", "workflow", "deps"))
    fixes = "".join(f"<li class='{e(f.status)}'><code>{e(f.file)}</code> ({e(f.method)}) {e(', '.join(f.rules))} - {e(f.status)} {e(f.detail)}</li>"
                    for f in r.fixes) or "<li>No fixes attempted.</li>"
    gate = "" if r.gate.get("passed", True) else f"<p class='bad'>Quality gate failed: {e('; '.join(r.gate['reasons']))}</p>"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CodeGuard report</title><style>
:root{{--bg:#fff;--fg:#1a1a1a;--mut:#666;--bd:#ddd;--card:#f6f7f9}}
@media (prefers-color-scheme:dark){{:root{{--bg:#16181d;--fg:#e8e8e8;--mut:#9aa;--bd:#333;--card:#20232a}}}}
body{{font:15px system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:20px;max-width:1000px;margin:auto}}
.big{{font-size:44px;font-weight:700}} .grid{{display:flex;gap:10px;flex-wrap:wrap}}
.card{{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:10px 14px;min-width:110px}}
.k{{color:var(--mut);font-size:12px;text-transform:uppercase}} .v{{font-size:20px;font-weight:600}}
table{{border-collapse:collapse;width:100%;display:block;overflow-x:auto}} td,th{{border-bottom:1px solid var(--bd);padding:6px 8px;text-align:left;vertical-align:top}}
.hint{{color:var(--mut);font-size:12px}} .bad{{color:#d33;font-weight:600}} li.reverted{{color:var(--mut)}}
.s-critical{{color:#d33;font-weight:700}} .s-high{{color:#e8590c;font-weight:600}} .s-medium{{color:#b8860b}} .s-low{{color:#2b7de9}}
</style></head><body>
<h1>CodeGuard report</h1>
<div class="big">{sb['overall']} ({sb['grade']}) &rarr; {sa['overall']} ({sa['grade']})</div>
<p>{e(r.target)} &middot; {r.files_scanned} files &middot; {r.duration}s &middot; tests: {e(_tests_line(r.tests_after or r.tests_before))} &middot; AI {'on' if r.llm_used else 'off'}</p>
{gate}<div class="grid">{cats}</div>
<h2>Fixes</h2><ul>{fixes}</ul>
<h2>Findings ({len(r.findings_after)})</h2>
<table><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Issue</th></tr>{rows(r.findings_after)}</table>
<h2>Notes</h2><ul>{''.join(f'<li>{e(n)}</li>' for n in r.notes) or '<li>-</li>'}</ul>
</body></html>"""


def write_reports(r: Report, outdir, formats=("md", "json", "html")) -> List[Path]:
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    if "md" in formats:
        p = out / "codeguard-report.md"
        p.write_text(to_markdown(r), encoding="utf-8")
        written.append(p)
    if "json" in formats:
        p = out / "codeguard-report.json"
        p.write_text(json.dumps(r.to_dict(), indent=2), encoding="utf-8")
        written.append(p)
    if "html" in formats:
        p = out / "codeguard-report.html"
        p.write_text(to_html(r), encoding="utf-8")
        written.append(p)
    if r.patch:
        p = out / "codeguard-fixes.patch"
        p.write_text(r.patch, encoding="utf-8")
        written.append(p)
    return written


def rules_markdown() -> str:
    L = ["# Built-in rules", "", "| ID | Severity | Category | Description |", "|---|---|---|---|"]
    from .rules.catalog import FIXABLE
    for rid, (sev, cat, title) in RULES.items():
        L.append(f"| {rid} | {sev} | {cat} | {title}{' (auto-fix)' if rid in FIXABLE else ''} |")
    return "\n".join(L) + "\n"
