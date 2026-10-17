"""Preserve downloaded bytes and provide bounded, terminal-safe previews."""

from __future__ import annotations

import hashlib
from io import BytesIO
from itertools import islice
import json
from pathlib import Path
import re
import zipfile

from .client import GameMasterError


def save_artifact(
    content: bytes, challenge_id: str, directory: Path = Path("artifacts"),
    *, output: Path | None = None, overwrite: bool = False,
) -> tuple[Path, str]:
    digest = hashlib.sha256(content).hexdigest()
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", challenge_id)[:64] or "unknown"
    path = output or directory / f"challenge-{safe_id}-{digest}.bin"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("wb" if overwrite else "xb") as stream:
            stream.write(content)
    except FileExistsError:
        if output is not None or path.is_symlink() or path.read_bytes() != content:
            raise GameMasterError("Artifact destination already exists; choose a new output or use --force.") from None
    return path.resolve(), digest


def artifact_summary(artifact: bytes) -> list[str]:
    lines = [f"Bytes: {len(artifact)}"]
    if artifact.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        try:
            with zipfile.ZipFile(BytesIO(artifact)) as archive:
                entries = archive.infolist()
                lines.append(f"Format: ZIP archive ({len(entries)} entries)")
                lines.extend(
                    f"  {json.dumps(entry.filename, ensure_ascii=True)} ({entry.file_size} bytes)"
                    for entry in entries[:40]
                )
                if len(entries) > 40:
                    lines.append("  ... listing truncated")
        except (zipfile.BadZipFile, ValueError, UnicodeError):
            lines.append("Format: damaged ZIP or unsupported ZIP metadata")
        return lines
    try:
        text = artifact.decode("utf-8")
    except UnicodeDecodeError:
        lines.append("Format: binary or non-UTF-8 data")
        matches = islice(re.finditer(rb"[\x20-\x7e]{5,}", artifact), 20)
        lines.extend(
            "  " + json.dumps(match.group()[:200].decode("ascii"))
            for match in matches
        )
        return lines
    lines.append("Format: UTF-8 text; escaped preview:")
    preview = text[:4000].splitlines()
    lines.extend("  " + json.dumps(line, ensure_ascii=True) for line in preview[:40])
    if len(text) > 4000 or len(preview) > 40:
        lines.append("  ... preview truncated")
    return lines
