"""Command line interface."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import load_config
from .models import SEVERITIES


def _review(a) -> int:
    from .pipeline import review
    from .report import write_reports
    root = Path(a.path)
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    try:
        cfg = load_config(root, {
            "model": a.model,
            "use_llm": False if a.no_llm else None, "run_tests": False if a.no_tests else None,
            "use_external_tools": False if a.no_external else None, "sandbox": a.sandbox,
            "fail_under": a.fail_under, "fail_on": a.fail_on, "verify_each": False if a.fast else None})
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    log = (lambda m: None) if a.quiet else (lambda m: print(f"  ... {m}", file=sys.stderr))
    r = review(root, cfg, fix=a.fix or a.apply, apply=a.apply, log=log)
    fmts = tuple(x.strip() for x in a.format.split(",") if x.strip())
    written = write_reports(r, a.out, fmts)
    sb, sa = r.score_before, r.score_after
    print(f"\nCodeGuard {__version__}  -  {r.target}")
    print(f"Score: {sb['overall']} ({sb['grade']})" + (f"  ->  {sa['overall']} ({sa['grade']}) after fixes" if r.fixes else ""))
    print("Findings: " + (", ".join(f"{n} {s}" for s, n in sa["counts"].items() if n) or "none"))
    for t, label in ((r.tests_before, "Tests before"), (r.tests_after, "Tests after ")):
        if t is not None and (t.ran or t.note):
            print(f"{label}: {t.passed} passed, {t.failed} failed, {t.errors} errors" if t.ran else f"{label}: {t.note}")
    for f in r.fixes:
        print(f"  {'OK ' if f.status == 'accepted' else 'REV'} {f.file}: {','.join(f.rules)} ({f.method}) {f.detail if f.status != 'accepted' else ''}")
    for n in r.notes:
        print(f"Note: {n}")
    print("Reports: " + ", ".join(str(p) for p in written))
    if not r.gate.get("passed", True):
        print("GATE FAILED: " + "; ".join(r.gate["reasons"]), file=sys.stderr)
        return 1
    return 0


def _serve(a) -> int:
    from .server import serve
    serve(a.host, a.port)
    return 0


def _keys(a) -> int:
    from .server import Settings
    from .store import Store
    s = Settings()
    store = Store(s.data_dir / "codeguard.db")
    key = store.create_key(a.email, a.plan)
    print(f"API key for {a.email} ({a.plan}). Store it now - it cannot be shown again:\n{key}")
    return 0


def _ui(a) -> int:
    import webbrowser
    from .server import serve, Settings, Store
    s = Settings()
    st = Store(s.data_dir / "codeguard.db")
    local_key = st.create_key("local@codeguard.internal", "enterprise")
    url = f"http://{a.host}:{a.port}/?key={local_key}"
    print(f"\n🛡️  CodeGuard v2 UI starting at: http://{a.host}:{a.port}")
    print(f"Opening browser to interactive dashboard...\n")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    serve(a.host, a.port)
    return 0


def _init(a) -> int:
    from .init_cmd import init_project
    init_project(Path(a.path))
    print("CodeGuard v2 initialized successfully.")
    return 0


def _rules(a) -> int:
    from .report import rules_markdown
    print(rules_markdown())
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="codeguard", description="Review, test and auto-fix AI-written code.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("review", help="scan a project, optionally fix it")
    r.add_argument("path", nargs="?", default=".")
    r.add_argument("--fix", action="store_true", help="try fixes in a temp copy; writes a verified patch")
    r.add_argument("--apply", action="store_true", help="also write verified fixes into the project (implies --fix)")
    r.add_argument("--model", help="LLM model name (e.g. qwen2.5-coder:1.5b or qwen2.5-coder:3b)")
    r.add_argument("--no-llm", action="store_true")
    r.add_argument("--no-tests", action="store_true")
    r.add_argument("--no-external", action="store_true", help="skip bandit/ruff/pip-audit")
    r.add_argument("--fast", action="store_true", help="verify tests once at the end instead of after every fix")
    r.add_argument("--sandbox", choices=["none", "docker"], help="run the tests inside Docker (recommended for untrusted code)")
    r.add_argument("--out", default="codeguard-report")
    r.add_argument("--format", default="md,json,html")
    r.add_argument("--fail-under", type=int, help="exit 1 if score is below this")
    r.add_argument("--fail-on", choices=SEVERITIES, help="exit 1 if any finding is at/above this severity")
    r.add_argument("--quiet", action="store_true")
    r.set_defaults(fn=_review)
    ui_cmd = sub.add_parser("ui", help="launch interactive single-page dashboard in browser")
    ui_cmd.add_argument("--host", default="127.0.0.1")
    ui_cmd.add_argument("--port", type=int, default=8080)
    ui_cmd.set_defaults(fn=_ui)
    init_cmd = sub.add_parser("init", help="scaffold .codeguard config, pre-commit hook and CI workflow")
    init_cmd.add_argument("path", nargs="?", default=".")
    init_cmd.set_defaults(fn=_init)
    s = sub.add_parser("serve", help="run the HTTP API / dashboard")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(fn=_serve)
    k = sub.add_parser("keys", help="create an API key for a customer")
    k.add_argument("--email", required=True)
    k.add_argument("--plan", default="free", choices=["free", "pro", "enterprise"])
    k.set_defaults(fn=_keys)
    ru = sub.add_parser("rules", help="print the rule catalog as Markdown")
    ru.set_defaults(fn=_rules)
    a = p.parse_args(argv)
    return a.fn(a)
