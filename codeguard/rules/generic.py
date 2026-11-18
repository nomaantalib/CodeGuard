"""Language-agnostic checks (secrets, TODO markers) and JS/TS regex rules."""
from __future__ import annotations

import re
from typing import List

from ..models import Finding
from .catalog import mk

SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "critical"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "critical"),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "critical"),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "high"),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{16,}\b"), "critical"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("LLM provider API key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{32,}\b"), "critical"),
]
GENERIC = re.compile(
    r"""(?ix)\b([a-z0-9_]*(?:password|passwd|secret|api[_-]?key|token|private[_-]?key)[a-z0-9_]*)\s*[:=]\s*(["'])([^"'\n]{8,})\2""")
PLACEHOLDERS = ("example", "changeme", "change_me", "your", "xxx", "<", "${", "{{", "placeholder", "dummy",
                "sample", "***", "redacted", "todo", "fake", "test", "env")
SIMPLE_ASSIGN = re.compile(r"""^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*(["']).*\1\s*$""")
HINT = "Move it to an environment variable / secret manager and ROTATE it - deleting it from code does not revoke it."
MARKER = re.compile(r"(?i)\b(TODO|FIXME|XXX|HACK)\b")


SUPPRESS = re.compile(r"codeguard:\s*ignore(?:=([A-Za-z0-9_,]+))?")
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__)/|(^|/)test_[^/]*$|_test\.\w+$|\.(test|spec)\.\w+$")


def apply_suppressions(findings: List[Finding], text: str) -> List[Finding]:
    """Honour inline `# codeguard:ignore` or `// codeguard:ignore=PY010,SEC001` comments."""
    lines = text.splitlines()
    kept = []
    for f in findings:
        m = SUPPRESS.search(lines[f.line - 1]) if 1 <= f.line <= len(lines) else None
        if m and (not m.group(1) or f.rule in m.group(1).split(",")):
            continue
        kept.append(f)
    return kept


def _mask(v: str) -> str:
    return f"{v[:2]}***({len(v)} chars)"


def scan_secrets(rel: str, text: str) -> List[Finding]:
    out: List[Finding] = []
    is_py = rel.endswith(".py")
    in_tests = bool(TEST_PATH.search(rel))
    for i, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000 or "os.environ" in line or "getenv" in line or "process.env" in line:
            continue
        hit = False
        for label, rx, sev in SECRET_PATTERNS:
            m = rx.search(line)
            if m:
                out.append(mk("SEC001", rel, i, f"{label} found ({_mask(m.group(0))})", HINT, severity=sev,
                              fixable=is_py and bool(SIMPLE_ASSIGN.match(line))))
                hit = True
                break
        if hit:
            continue
        m = GENERIC.search(line)
        if m and not any(p in m.group(3).lower() for p in PLACEHOLDERS):
            out.append(mk("SEC001", rel, i, f"Hardcoded credential in '{m.group(1)}' ({_mask(m.group(3))})", HINT,
                          fixable=is_py and bool(SIMPLE_ASSIGN.match(line))))
    if in_tests:  # fixtures/dummy credentials in tests are expected; keep them visible but low priority
        for f in out:
            f.severity, f.fixable = "low", False
            f.message += " [test file]"
    return out


def scan_markers(rel: str, text: str) -> List[Finding]:
    hits = [i for i, l in enumerate(text.splitlines(), 1) if MARKER.search(l) and ("#" in l or "//" in l)]
    if not hits:
        return []
    return [mk("GEN001", rel, hits[0], f"{len(hits)} TODO/FIXME marker(s) - unfinished work", "Resolve or track them as issues.")]


JS_RULES = [
    ("JS001", re.compile(r"\beval\s*\(|\bnew\s+Function\s*\("), "Dynamic code execution", "Avoid eval/new Function."),
    ("JS002", re.compile(r"\.(?:innerHTML|outerHTML)\s*=(?!=)|document\.write\s*\(|dangerouslySetInnerHTML"),
     "Unsafe HTML injection (XSS risk)", "Use textContent or sanitize with DOMPurify."),
    ("JS003", re.compile(r"(?:(?<![.\w])|child_process\.)exec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|[^)]*\+)"),
     "Command built from dynamic input", "Use execFile/spawn with an argument array."),
    ("JS004", re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
     "TLS verification disabled", "Remove the override."),
    ("JS005", re.compile(r"(?i)Math\.random\(\).*(?:token|secret|password|session|apikey)|(?:token|secret|password|session|apikey).*Math\.random\(\)"),
     "Math.random() is not cryptographically secure", "Use crypto.randomBytes / crypto.randomUUID."),
    ("JS006", re.compile(r"(?i)(?:query|execute)\s*\(\s*(?:`[^`]*(?:select|insert|update|delete)[^`]*\$\{|[\"'][^\"']*(?:select|insert|update|delete)[^\"']*[\"']\s*\+)"),
     "SQL built with string interpolation", "Use parameterized queries."),
]


def scan_js(rel: str, text: str) -> List[Finding]:
    out: List[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if s.startswith(("//", "*", "/*")) or len(line) > 2000:
            continue
        for rule, rx, msg, hint in JS_RULES:
            if rx.search(line):
                out.append(mk(rule, rel, i, msg, hint))
    return out
