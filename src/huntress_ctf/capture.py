"""Save redacted live responses after a run, so response shapes can be verified offline."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from .display import safe_value


def save_capture(
    root: Path, label: str, responses: dict[str, Any], secrets: tuple[str, ...] = (),
) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    directory = root / f"{label}-{stamp}-{uuid4().hex[:8]}"
    directory.mkdir(parents=True, exist_ok=False)
    for name, value in responses.items():
        with (directory / f"{name}.json").open("x", encoding="utf-8") as stream:
            json.dump(safe_value(value, secrets), stream, indent=2, ensure_ascii=True, sort_keys=True)
            stream.write("\n")
    return directory.resolve()
