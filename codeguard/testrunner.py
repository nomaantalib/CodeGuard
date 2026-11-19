"""Run the project's own test suite (optionally inside a locked-down Docker container)."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Tuple

from .config import Config
from .discovery import read_text
from .models import RunResult
from .workflow import TEST_RX

SECRET_HINTS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "PASSWD")


def unittest_args(files: List[str]) -> List[str]:
    """unittest's discover skips folders without __init__.py, so name the test modules explicitly."""
    mods = []
    for r in files:
        if r.endswith(".py") and TEST_RX.search(r):
            parts = r[:-3].replace("\\", "/").split("/")
            if all(p.isidentifier() for p in parts):
                mods.append(".".join(parts))
    return ["-q"] + mods if mods else ["discover", "-q"]


def _pytest_or_unittest(files: List[str]) -> str:
    ut = " ".join(unittest_args(files))
    return ("if python -c 'import pytest' 2>/dev/null; then python -m pytest -q --no-header -p no:cacheprovider; "
            f"else python -m unittest {ut}; fi")


def safe_env() -> dict:
    """Never leak our API keys / tokens into the code under test."""
    env = {k: v for k, v in os.environ.items() if not any(h in k.upper() for h in SECRET_HINTS)}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _node_has_tests(root: Path) -> bool:
    try:
        scripts = json.loads(read_text(root / "package.json") or "{}").get("scripts", {})
    except ValueError:
        return False
    t = scripts.get("test", "")
    return bool(t) and "no test specified" not in t


def parse_output(out: str, rc: int) -> Tuple[str, int, int, int]:
    tail = "\n".join(out.strip().splitlines()[-25:])
    m = re.search(r"^Ran (\d+) tests? in", tail, re.M)
    if m:
        total = int(m.group(1))
        failed = errors = 0
        fm = re.search(r"FAILED \(([^)]*)\)", tail)
        if fm:
            f = re.search(r"failures=(\d+)", fm.group(1))
            e = re.search(r"errors=(\d+)", fm.group(1))
            failed, errors = int(f.group(1)) if f else 0, int(e.group(1)) if e else 0
        return "unittest", max(total - failed - errors, 0), failed, errors
    m = re.search(r"Tests:\s+(?:(\d+) failed, )?(?:(\d+) passed, )?(\d+) total", tail)
    if m:
        return "jest", int(m.group(2) or 0), int(m.group(1) or 0), 0
    p = re.search(r"(\d+) passed", tail)
    f = re.search(r"(\d+) failed", tail)
    e = re.search(r"(\d+) errors?", tail)
    if p or f or e:
        return "pytest", int(p.group(1)) if p else 0, int(f.group(1)) if f else 0, int(e.group(1)) if e else 0
    return "unknown", (1 if rc == 0 else 0), (0 if rc == 0 else 1), 0


def _docker(root: Path, cfg: Config, image: str, inner: List[str]) -> List[str]:
    cmd = ["docker", "run", "--rm", "--network", cfg.docker_network, "--memory", "1g", "--cpus", "1",
           "--pids-limit", "256", "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
    if hasattr(os, "getuid"):
        cmd += ["--user", f"{os.getuid()}:{os.getgid()}"]
    return cmd + ["-v", f"{root}:/work", "-w", "/work", image] + inner


def run_tests(root: Path, cfg: Config, files: List[str]) -> RunResult:
    root = Path(root).resolve()
    has_py = any(TEST_RX.search(r) and r.endswith(".py") for r in files)
    has_node = "package.json" in files and _node_has_tests(root)
    if not (has_py or has_node):
        return RunResult(note="no tests found")
    use_docker = cfg.sandbox == "docker"
    if use_docker and not shutil.which("docker"):
        return RunResult(note="docker sandbox requested but docker is not available; tests skipped")
    if has_py:
        if use_docker:
            cmd = _docker(root, cfg, cfg.docker_image, ["sh", "-c", _pytest_or_unittest(files)])
        elif shutil.which(sys.executable) and _has_pytest():
            cmd = [sys.executable, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider"]
        else:
            cmd = [sys.executable, "-m", "unittest"] + unittest_args(files)
    else:
        cmd = (_docker(root, cfg, cfg.docker_image_node, ["npm", "test", "--silent"]) if use_docker
               else ["npm", "test", "--silent"])
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=cfg.test_timeout, env=safe_env())
    except subprocess.TimeoutExpired:
        return RunResult(framework="timeout", ran=True, errors=1, returncode=-1, duration=time.time() - t0,
                         note=f"test run exceeded {cfg.test_timeout}s")
    except OSError as e:
        return RunResult(note=f"could not start test runner: {e}")
    out = (p.stdout or "") + "\n" + (p.stderr or "")
    fw, passed, failed, errors = parse_output(out, p.returncode)
    if passed + failed + errors == 0:
        return RunResult(framework=fw, returncode=p.returncode, note="no tests collected", output_tail=out[-1500:])
    return RunResult(framework=fw, ran=True, passed=passed, failed=failed, errors=errors,
                     returncode=p.returncode, duration=time.time() - t0, output_tail=out[-1500:])


def _has_pytest() -> bool:
    import importlib.util
    return importlib.util.find_spec("pytest") is not None


def regressed(after: RunResult, before: RunResult) -> bool:
    """True if the fix made the test suite worse than the baseline."""
    if not before.ran:
        return False
    return (not after.ran) or after.bad > before.bad or after.passed < before.passed
