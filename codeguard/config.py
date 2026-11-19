"""Configuration: defaults < codeguard.toml (in the target) < CLI/server overrides."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Set

DEFAULT_MODEL = "qwen2.5-coder:3b"

DEFAULT_IGNORE = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".tox", "dist", "build", ".next", "coverage", "site-packages",
    ".idea", ".vscode", "codeguard-report", "benchmarks",
}


def load_env(root: Optional[Path] = None) -> None:
    """Load environment variables from .env in target root, current directory, or package root."""
    candidates = []
    if root:
        candidates.append(Path(root) / ".env")
    candidates.append(Path.cwd() / ".env")
    pkg_root = Path(__file__).resolve().parent.parent / ".env"
    if pkg_root not in candidates:
        candidates.append(pkg_root)

    env_file = next((p for p in candidates if p.is_file()), None)
    if not env_file:
        return

    try:
        from dotenv import load_dotenv
        load_dotenv(env_file, override=False)
        return
    except ImportError:
        pass

    try:
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip()
            if not k or k in os.environ:
                continue
            if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                v = v[1:-1]
            os.environ[k] = v
    except Exception:
        pass


load_env()


@dataclass
class Config:
    ignore_dirs: Set[str] = field(default_factory=lambda: set(DEFAULT_IGNORE))
    max_file_kb: int = 512
    use_llm: bool = True  # local Ollama is the default; no paid API key required
    provider: str = field(default_factory=lambda: os.environ.get("CODEGUARD_LLM_PROVIDER", "ollama"))
    model: str = field(default_factory=lambda: os.environ.get("CODEGUARD_MODEL", DEFAULT_MODEL))
    llm_url: str = field(default_factory=lambda: os.environ.get("CODEGUARD_LLM_URL", "http://localhost:11434"))
    api_key: str = field(default_factory=lambda: os.environ.get("CODEGUARD_LLM_API_KEY", ""))
    max_llm_files: int = 15
    run_tests: bool = True
    test_timeout: int = 300
    sandbox: str = "none"  # none | docker
    docker_image: str = "python:3.12-slim"
    docker_image_node: str = "node:20-slim"
    docker_network: str = "none"
    verify_each: bool = True  # re-run tests after every individual fix
    use_external_tools: bool = True  # bandit / ruff / pip-audit when installed
    disabled_rules: Set[str] = field(default_factory=set)
    max_complexity: int = 12
    fail_under: int = 0
    fail_on: str = ""  # severity name; "" = never fail on severity


def load_config(root: Path, overrides: Optional[Dict[str, Any]] = None) -> Config:
    load_env(root)
    cfg = Config()
    f = Path(root) / "codeguard.toml"
    if f.is_file():
        try:
            import tomllib  # Python 3.11+
        except ModuleNotFoundError:  # pragma: no cover
            tomllib = None
        if tomllib:
            try:
                data = tomllib.loads(f.read_text(encoding="utf-8")).get("codeguard", {})
            except Exception as e:
                raise ValueError(f"Invalid codeguard.toml: {e}") from e
            for k, v in data.items():
                if not hasattr(cfg, k):
                    continue
                if k == "ignore_dirs":
                    cfg.ignore_dirs |= set(v)
                elif k == "disabled_rules":
                    cfg.disabled_rules = set(v)
                else:
                    setattr(cfg, k, v)
    for k, v in (overrides or {}).items():
        if v is not None and hasattr(cfg, k):
            setattr(cfg, k, v)
    return cfg
