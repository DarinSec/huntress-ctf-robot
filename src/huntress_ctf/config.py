"""Load the Game Master settings from a private, git-ignored .env file."""

from __future__ import annotations

import os
from pathlib import Path

ALLOWED_KEYS = ("HUNTRESS_GM_TOKEN", "HUNTRESS_GM_URL")
REPO_ROOT = Path(__file__).resolve().parents[2]


def load_env(candidates: tuple[Path, ...] | None = None) -> Path | None:
    """Set allowed keys from the first existing .env; real environment variables win.

    Only HUNTRESS_GM_TOKEN and HUNTRESS_GM_URL are read. Values are never printed.
    """
    paths = candidates if candidates is not None else (Path.cwd() / ".env", REPO_ROOT / ".env")
    for path in paths:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip().removeprefix("export ").strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if key in ALLOWED_KEYS and value and not os.environ.get(key):
                os.environ[key] = value
        return path
    return None
