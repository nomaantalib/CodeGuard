"""Project-level workflow hygiene: tests, CI, repo basics, GitHub workflows, Dockerfiles."""
from __future__ import annotations

import re
from pathlib import Path
from typing import List

from .discovery import Inventory, read_text
from .models import Finding
from .rules.catalog import mk

TEST_RX = re.compile(r"(^|/)(tests?|__tests__)/|(^|/)test_[^/]*\.py$|_test\.py$|\.(test|spec)\.(js|jsx|ts|tsx|mjs)$")
CI_NAMES = {".gitlab-ci.yml", "Jenkinsfile", ".travis.yml", "azure-pipelines.yml", "bitbucket-pipelines.yml"}


def check_project(root: Path, inv: Inventory) -> List[Finding]:
    out: List[Finding] = []
    allf = inv.all
    if inv.src and not any(TEST_RX.search(r) for r in allf):
        out.append(mk("WF001", "(project)", 1, "No automated tests found", "Add tests; AI-written code without tests is unverified code."))
    has_ci = any(r.startswith((".github/workflows/", ".circleci/")) or r in CI_NAMES for r in allf)
    if inv.src and not has_ci:
        out.append(mk("WF002", "(project)", 1, "No CI configuration found", "Run tests and CodeGuard on every pull request."))
    if inv.src and not any(r.lower().startswith("readme") for r in allf):
        out.append(mk("WF003", "(project)", 1, "No README", "Document setup, usage and how to run tests."))
    gitignore = (read_text(root / ".gitignore") or "") if ".gitignore" in allf else None
    if inv.src and gitignore is None:
        out.append(mk("WF004", "(project)", 1, "No .gitignore", "Ignore build output, virtualenvs and secrets."))
    for r in allf:
        base = r.rsplit("/", 1)[-1]
        if base == ".env" and not (gitignore and re.search(r"(?m)^\s*/?\.env\b", gitignore)):
            out.append(mk("SEC002", r, 1, ".env file present but not listed in .gitignore", "Add it to .gitignore and commit a .env.example instead."))
        if r.startswith(".github/workflows/") and r.endswith((".yml", ".yaml")):
            out += _check_gh_workflow(r, read_text(root / r) or "")
        if base == "Dockerfile" or base.startswith("Dockerfile."):
            out += _check_dockerfile(r, read_text(root / r) or "")
    return out


def _check_gh_workflow(rel: str, text: str) -> List[Finding]:
    out: List[Finding] = []
    if re.search(r"(?m)^\s*pull_request_target\b", text):
        out.append(mk("WF006", rel, 1, "pull_request_target runs with secrets on untrusted PR code", "Prefer pull_request, or never check out PR head code in this trigger."))
    if not re.search(r"(?m)^\s*permissions\s*:", text):
        out.append(mk("WF007", rel, 1, "No explicit 'permissions:' block (token defaults may be too broad)", "Add least-privilege permissions."))
    for i, line in enumerate(text.splitlines(), 1):
        if re.search(r"(curl|wget)[^|\n]*\|\s*(sudo\s+)?(ba)?sh\b", line):
            out.append(mk("WF005", rel, i, "Remote script piped straight into a shell", "Download, verify a checksum, then run."))
        if re.search(r"uses:\s*[\w./-]+@(main|master|latest)\b", line):
            out.append(mk("WF008", rel, i, "Action pinned to a moving ref", "Pin to a version tag or commit SHA."))
    return out


def _check_dockerfile(rel: str, text: str) -> List[Finding]:
    out: List[Finding] = []
    if text and not re.search(r"(?im)^\s*USER\s+\S+", text):
        out.append(mk("WF009", rel, 1, "Container runs as root (no USER instruction)", "Add a non-root USER."))
    for i, line in enumerate(text.splitlines(), 1):
        if re.match(r"(?i)\s*FROM\s+\S+:latest\b", line):
            out.append(mk("WF009", rel, i, "Base image uses :latest", "Pin an explicit version."))
    return out
