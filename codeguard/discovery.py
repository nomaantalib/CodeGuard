"""Find the files worth scanning."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .config import Config

SRC_EXT = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
JS_EXT = SRC_EXT[1:]
TEXT_EXT = (".yml", ".yaml", ".toml", ".cfg", ".ini", ".env", ".sh", ".properties", ".conf", ".json")
SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "composer.lock"}


@dataclass
class Inventory:
    all: List[str] = field(default_factory=list)  # every file (relative, posix)
    src: List[str] = field(default_factory=list)  # source code files
    text_only: List[str] = field(default_factory=list)  # config-ish files (secret scan only)


def collect(root: Path, cfg: Config) -> Inventory:
    root = Path(root)
    inv = Inventory()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in cfg.ignore_dirs and not os.path.islink(os.path.join(dirpath, d))
        )
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            if p.is_symlink():
                continue
            rel = p.relative_to(root).as_posix()
            inv.all.append(rel)
            try:
                if p.stat().st_size > cfg.max_file_kb * 1024:
                    continue
            except OSError:
                continue
            low = fn.lower()
            if low.endswith(SRC_EXT):
                inv.src.append(rel)
            elif fn in SKIP_NAMES:
                continue
            elif low.endswith(TEXT_EXT) or low.startswith(".env"):
                inv.text_only.append(rel)
    return inv


def read_text(p: Path) -> Optional[str]:
    try:
        return Path(p).read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None
