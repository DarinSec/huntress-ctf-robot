"""Unpack archives in memory so solvers see inner files; nothing is written or executed."""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
import re
import tarfile
import zipfile
import zlib

MAX_MEMBERS = 1000
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_DEPTH = 3
# AGENTS.md: Script Analysis and Binary lessons may publish the archive password `infected`.
DEFAULT_PASSWORDS = ("infected",)
_ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_PASSWORD = re.compile(
    r"\bpassword\b[^:\n]{0,40}?(?::|\bis\b)\s*[\"'`]?([^\s\"'`]{1,64})", re.I,
)
_ZIP_AES = 99


@dataclass(frozen=True)
class Member:
    name: str
    data: bytes


@dataclass(frozen=True)
class Unwrapped:
    members: tuple[Member, ...]
    notes: tuple[str, ...]


def passwords_from(text: str) -> tuple[str, ...]:
    """Passwords stated in public instructions first, then the published defaults."""
    found = [match.group(1).rstrip(".,;)") for match in _PASSWORD.finditer(text)]
    return tuple(dict.fromkeys([*found, *DEFAULT_PASSWORDS]))


def _is_tar(data: bytes) -> bool:
    return len(data) > 262 and data[257:262] == b"ustar"


def unwrap(data: bytes, passwords: tuple[str, ...] = DEFAULT_PASSWORDS) -> Unwrapped:
    """Leaf files inside ZIP (incl. ZipCrypto), gzip, and tar containers, nested to MAX_DEPTH."""
    members: list[Member] = []
    notes: list[str] = []
    budget = [MAX_TOTAL_BYTES]

    def keep(name: str, blob: bytes, depth: int) -> None:
        if len(members) >= MAX_MEMBERS:
            notes.append(f"Member limit {MAX_MEMBERS} reached; the rest was skipped.")
            return
        if depth < MAX_DEPTH and (blob.startswith(_ZIP_MAGIC) or blob.startswith(b"\x1f\x8b") or _is_tar(blob)):
            visit(name, blob, depth + 1)
        else:
            members.append(Member(name, blob))

    def take(size: int, name: str) -> bool:
        # Bounded in total: an oversized file is skipped, smaller ones may still fit.
        if size > budget[0]:
            notes.append(f"Size limit: skipped {name!r}.")
            return False
        budget[0] -= size
        return True

    def visit(name: str, blob: bytes, depth: int) -> None:
        if blob.startswith(_ZIP_MAGIC):
            try:
                archive = zipfile.ZipFile(BytesIO(blob))
            except (zipfile.BadZipFile, ValueError):
                notes.append(f"{name or 'artifact'}: damaged ZIP")
                return
            with archive:
                for info in archive.infolist():
                    if info.is_dir() or len(members) >= MAX_MEMBERS:
                        continue
                    inner = f"{name}/{info.filename}" if name else info.filename
                    if info.flag_bits & 0x1 and info.compress_type == _ZIP_AES:
                        notes.append(f"{inner}: AES-encrypted entry is not supported by the standard library")
                        continue
                    content = None
                    for password in ((None,) if not info.flag_bits & 0x1 else passwords):
                        try:
                            with archive.open(info, pwd=password.encode() if password else None) as stream:
                                content = stream.read(budget[0] + 1)
                            break
                        except (RuntimeError, zipfile.BadZipFile, zlib.error, EOFError,
                                ValueError, NotImplementedError):
                            continue
                    if content is None:
                        notes.append(f"{inner}: could not be decrypted with the known passwords")
                        continue
                    if take(len(content), inner):
                        keep(inner, content, depth)
        elif blob.startswith(b"\x1f\x8b"):
            inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
            try:
                content = inflater.decompress(blob, budget[0] + 1)
            except zlib.error:
                notes.append(f"{name or 'artifact'}: damaged gzip data")
                return
            inner = re.sub(r"\.t?gz$", "", name) if name.endswith(("gz", "tgz")) else f"{name}/gunzip"
            if take(len(content), inner):
                keep(inner.lstrip("/") or "gunzip", content, depth)
        elif _is_tar(blob):
            try:
                with tarfile.open(fileobj=BytesIO(blob), mode="r:") as archive:
                    for info in archive.getmembers():
                        if not info.isfile() or len(members) >= MAX_MEMBERS:
                            continue
                        inner = f"{name}/{info.name}" if name else info.name
                        if not take(info.size, inner):
                            return
                        stream = archive.extractfile(info)
                        if stream is not None:
                            keep(inner, stream.read(), depth)
            except (tarfile.TarError, EOFError):
                notes.append(f"{name or 'artifact'}: damaged tar data")

    if data.startswith(_ZIP_MAGIC) or data.startswith(b"\x1f\x8b") or _is_tar(data):
        visit("", data, 1)
    return Unwrapped(tuple(members), tuple(notes))
