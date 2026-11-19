"""Scaffold .codeguard config, git pre-commit hook, and GitHub Action workflow."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Optional

CONFIG_TEMPLATE = """# CodeGuard v2 Configuration
[codeguard]
# LLM Provider options: ollama, deepseek, qwen, glm, kimi, openrouter, openai, anthropic
provider = "ollama"
model = "qwen2.5-coder:1.5b"
llm_url = "http://localhost:11434"

# Quality & Security Gates
fail_under = 70
fail_on = "high"

# Analysis limits
max_llm_files = 15
verify_each = true
run_tests = true
use_external_tools = true
"""

PRE_COMMIT_HOOK = """#!/bin/sh
# CodeGuard Pre-Commit Quality & Security Gate
echo "[CodeGuard] Running pre-commit check..."
codeguard review . --no-llm --fail-on high --fail-under 60
STATUS=$?
if [ $STATUS -ne 0 ]; then
    echo "[CodeGuard] Gate failed. Review issues or fix them before committing."
    exit 1
fi
echo "[CodeGuard] Checks passed."
exit 0
"""

GITHUB_WORKFLOW = """name: CodeGuard Security & Quality Audit

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  codeguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install CodeGuard
        run: |
          python -m pip install --upgrade pip
          pip install git+https://github.com/nomaantalib/CodeGuard.git

      - name: Run CodeGuard Audit
        run: |
          codeguard review . --no-llm --fail-under 70 --format md,html,json
"""


def init_project(target_dir: Optional[Path] = None) -> Path:
    target = (target_dir or Path(".")).resolve()
    codeguard_dir = target / ".codeguard"
    codeguard_dir.mkdir(parents=True, exist_ok=True)

    # 1. Config file
    cfg_file = codeguard_dir / "codeguard.toml"
    if not cfg_file.exists():
        cfg_file.write_text(CONFIG_TEMPLATE, encoding="utf-8")
        print(f"Created config: {cfg_file.relative_to(target)}")

    # 2. Pre-commit script
    hook_script = codeguard_dir / "pre-commit.sh"
    hook_script.write_text(PRE_COMMIT_HOOK, encoding="utf-8")
    try:
        hook_script.chmod(hook_script.stat().st_mode | stat.S_IEXEC)
    except Exception:
        pass

    # Install git hook if .git exists
    git_hooks = target / ".git" / "hooks"
    if git_hooks.is_dir():
        git_hook_file = git_hooks / "pre-commit"
        git_hook_file.write_text(PRE_COMMIT_HOOK, encoding="utf-8")
        try:
            git_hook_file.chmod(git_hook_file.stat().st_mode | stat.S_IEXEC)
        except Exception:
            pass
        print(f"Installed git pre-commit hook: {git_hook_file.relative_to(target)}")

    # 3. GitHub Action workflow
    gh_dir = target / ".github" / "workflows"
    gh_dir.mkdir(parents=True, exist_ok=True)
    wf_file = gh_dir / "codeguard.yml"
    if not wf_file.exists():
        wf_file.write_text(GITHUB_WORKFLOW, encoding="utf-8")
        print(f"Created GitHub Action workflow: {wf_file.relative_to(target)}")

    return codeguard_dir
