"""Rule catalog: id -> (default severity, category, title)."""
from __future__ import annotations

from ..models import Finding

RULES = {
    "PY001": ("high", "security", "eval() on dynamic input"),
    "PY002": ("high", "security", "exec() on dynamic input"),
    "PY003": ("high", "security", "Shell / command injection risk"),
    "PY004": ("high", "security", "Unsafe yaml.load()"),
    "PY005": ("medium", "security", "Insecure deserialization (pickle/marshal)"),
    "PY006": ("medium", "security", "Weak hash (MD5/SHA1)"),
    "PY007": ("high", "security", "TLS certificate verification disabled"),
    "PY008": ("low", "quality", "Bare except"),
    "PY009": ("low", "quality", "Swallowed exception"),
    "PY010": ("high", "security", "Possible SQL injection"),
    "PY011": ("medium", "security", "Insecure temp file (tempfile.mktemp)"),
    "PY012": ("medium", "security", "Debug mode enabled"),
    "PY013": ("medium", "security", "World-writable file permissions"),
    "PY014": ("medium", "quality", "Mutable default argument"),
    "PY015": ("medium", "deps", "Unresolvable import (possible hallucinated package)"),
    "PY016": ("high", "quality", "Syntax error"),
    "PY017": ("low", "quality", "Stub / unfinished function"),
    "PY018": ("low", "quality", "High cyclomatic complexity"),
    "GEN001": ("info", "quality", "TODO / FIXME markers"),
    "SEC001": ("high", "security", "Hardcoded secret or credential"),
    "SEC002": ("medium", "security", ".env file not git-ignored"),
    "JS001": ("high", "security", "eval() / new Function()"),
    "JS002": ("medium", "security", "Unsafe HTML injection (XSS)"),
    "JS003": ("high", "security", "Command injection via exec()"),
    "JS004": ("high", "security", "TLS certificate verification disabled"),
    "JS005": ("medium", "security", "Math.random() used for secrets"),
    "JS006": ("high", "security", "Possible SQL injection"),
    "WF001": ("medium", "tests", "No automated tests found"),
    "WF002": ("low", "workflow", "No CI configuration"),
    "WF003": ("low", "workflow", "Missing README"),
    "WF004": ("low", "workflow", "Missing .gitignore"),
    "WF005": ("high", "workflow", "CI pipes a remote script into a shell"),
    "WF006": ("medium", "workflow", "Risky pull_request_target trigger"),
    "WF007": ("low", "workflow", "GitHub workflow lacks explicit permissions"),
    "WF008": ("low", "workflow", "Action pinned to a moving ref (main/master/latest)"),
    "WF009": ("low", "workflow", "Dockerfile runs as root or uses :latest"),
    "DEP001": ("low", "deps", "Unpinned dependencies"),
    "DEP002": ("high", "deps", "Known vulnerable dependency"),
    "LLM001": ("medium", "quality", "LLM-identified issue"),
}

FIXABLE = {"PY001", "PY004", "PY006", "PY007", "PY008", "PY012", "SEC001"}


def mk(rule, file, line, message, hint="", end_line=0, fixable=False, severity=None, source="builtin") -> Finding:
    sev, cat, _ = RULES[rule]
    return Finding(rule=rule, severity=severity or sev, category=cat, file=file, line=int(line or 1),
                   message=message, hint=hint, end_line=int(end_line or line or 1), source=source, fixable=fixable)
