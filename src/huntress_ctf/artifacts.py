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


def artifact_path(challenge_id: str, digest: str, directory: Path = Path("artifacts")) -> Path:
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", challenge_id)[:64] or "unknown"
    return directory / f"challenge-{safe_id}-{digest}.bin"


def save_artifact(
    content: bytes, challenge_id: str, directory: Path = Path("artifacts"),
    *, output: Path | None = None, overwrite: bool = False,
) -> tuple[Path, str]:
    digest = hashlib.sha256(content).hexdigest()
    path = output or artifact_path(challenge_id, digest, directory)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("wb" if overwrite else "xb") as stream:
            stream.write(content)
    except FileExistsError:
        if output is not None or path.is_symlink() or path.read_bytes() != content:
            raise GameMasterError("Artifact destination already exists; choose a new output or use --force.") from None
    return path.resolve(), digest


_ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_SIGNATURES = (
    (b"MZ", "PE executable (Windows); lane hint: Binary"),
    (b"\x7fELF", "ELF executable (Linux); lane hint: Binary"),
    (b"dex\n", "Android DEX bytecode; lane hint: Mobile Android"),
    (b"%PDF-", "PDF document; lane hint: Metadata Forensics"),
    (b"\xff\xd8\xff", "JPEG image; lane hint: Metadata Forensics"),
    (b"\x89PNG\r\n\x1a\n", "PNG image; lane hint: Metadata Forensics"),
    (b"GIF8", "GIF image; lane hint: Metadata Forensics"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 compound file (legacy Office, MSI)"),
    (b"\x1f\x8b", "gzip data"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
)
_SCRIPT = re.compile(
    r"\b(?:powershell|invoke-expression|iex|frombase64string|wscript|cscript|createobject|"
    r"invoke-webrequest|downloadstring)\b|-enc(?:odedcommand)?\b|\beval\s*\(|<script\b|"
    r"^\s*(?:function\s+[\w-]+|var\s+\w+\s*=|dim\s+\w+|@echo\s+off|#!)",
    re.I | re.M,
)
_UTF16_STRINGS = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")


def artifact_kind(artifact: bytes) -> str:
    """File type from magic bytes or structure, with the lane it most likely belongs to.

    The challenge's own `lane` field is authoritative; this is a triage hint only.
    """
    for magic, kind in _SIGNATURES:
        if artifact.startswith(magic):
            return kind
    if artifact.startswith(_ZIP_MAGIC):
        try:
            with zipfile.ZipFile(BytesIO(artifact)) as archive:
                entries = archive.infolist()
        except (zipfile.BadZipFile, ValueError, UnicodeError):
            return "damaged ZIP archive"
        names = {entry.filename for entry in entries}
        if "AndroidManifest.xml" in names and any(name.endswith(".dex") for name in names):
            kind = "APK (Android package); lane hint: Mobile Android"
        elif "[Content_Types].xml" in names or any(name.startswith("docProps/") for name in names):
            kind = "Office Open XML document; lane hint: Metadata Forensics"
        else:
            kind = "ZIP archive"
        if any(entry.flag_bits & 0x1 for entry in entries):
            kind += "; encrypted entries (use the lesson's published password)"
        return kind
    try:
        text = artifact.decode("utf-8")
    except UnicodeDecodeError:
        return "unrecognized binary data"
    return "script text; lane hint: Script Analysis" if _SCRIPT.search(text) else "UTF-8 text"


def artifact_summary(artifact: bytes) -> list[str]:
    lines = [f"Bytes: {len(artifact)}", f"Kind: {artifact_kind(artifact)}"]
    if artifact.startswith(_ZIP_MAGIC):
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
        lines.append("ASCII strings:")
        matches = islice(re.finditer(rb"[\x20-\x7e]{5,}", artifact), 20)
        lines.extend(
            "  " + json.dumps(match.group()[:200].decode("ascii"))
            for match in matches
        )
        # Windows binaries and scripts often keep their interesting strings in UTF-16LE.
        wide = list(islice(_UTF16_STRINGS.finditer(artifact), 20))
        if wide:
            lines.append("UTF-16LE strings:")
            lines.extend(
                "  " + json.dumps(match.group()[:400].decode("utf-16-le"))
                for match in wide
            )
        return lines
    lines.append("Format: UTF-8 text; escaped preview:")
    preview = text[:4000].splitlines()
    lines.extend("  " + json.dumps(line, ensure_ascii=True) for line in preview[:40])
    if len(text) > 4000 or len(preview) > 40:
        lines.append("  ... preview truncated")
    return lines
