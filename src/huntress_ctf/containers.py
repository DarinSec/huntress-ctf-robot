"""Unpack archives in memory so solvers see inner files; nothing from them is executed.

The standard library decrypts ZipCrypto in pure Python (~1 MB/s), which would put about a
second per megabyte on the timed clock. Larger encrypted ZIPs, and AES ZIPs the standard
library cannot open, go through bsdtar, 7-Zip, or unzip instead: the archive bytes are
written to a private temporary file and the tool streams the members to stdout, so nothing
is extracted to paths named by the archive. Every member is checked against the ZIP's own
sizes and CRC-32 before it is used; anything else falls back to the standard library.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from io import BytesIO
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import zipfile
import zlib

MAX_MEMBERS = 1000
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_DEPTH = 3
# AGENTS.md: Script Analysis and Binary lessons may publish the archive password `infected`.
DEFAULT_PASSWORDS = ("infected",)
# Below this much encrypted data the pure-Python path is faster than starting a process.
FAST_UNZIP_MIN_BYTES = 32 * 1024
TOOL_TIMEOUT_SECONDS = 30
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


class LazyMembers(Sequence[Member]):
    """Archive members unpacked on first use; a solver that never looks pays nothing.

    Unpacking a 3 MB Metadata bundle took 35 ms on the clock although its solver reads
    the archive itself (19 Oct 2026). Separate deliveries (`extra`) follow the members.
    """

    def __init__(self, artifact: bytes, passwords: tuple[str, ...], extra: tuple[Member, ...] = ()) -> None:
        self._artifact, self._passwords, self._extra = artifact, passwords, tuple(extra)
        self._members: tuple[Member, ...] | None = None
        self._notes: tuple[str, ...] = ()

    def _load(self) -> tuple[Member, ...]:
        if self._members is None:
            unwrapped = unwrap(self._artifact, self._passwords)
            self._members, self._notes = unwrapped.members + self._extra, unwrapped.notes
        return self._members

    @property
    def notes(self) -> tuple[str, ...]:
        self._load()
        return self._notes

    def __getitem__(self, index):  # type: ignore[override]
        return self._load()[index]

    def __len__(self) -> int:
        return len(self._load())

    def __iter__(self):
        return iter(self._load())

    def __add__(self, other: tuple[Member, ...]) -> tuple[Member, ...]:
        return self._load() + tuple(other)


def passwords_from(text: str) -> tuple[str, ...]:
    """Passwords stated in public instructions first, then the published defaults."""
    found = [match.group(1).rstrip(".,;)") for match in _PASSWORD.finditer(text)]
    return tuple(dict.fromkeys([*found, *DEFAULT_PASSWORDS]))


def _is_tar(data: bytes) -> bool:
    return len(data) > 262 and data[257:262] == b"ustar"


@dataclass(frozen=True)
class UnzipTool:
    kind: str  # "bsdtar", "7z", or "unzip"
    path: str

    def command(self, archive: str, password: str) -> list[str]:
        """Every member in archive order to stdout; nothing is written to disk."""
        if self.kind == "bsdtar":
            return [self.path, "-xOf", archive, "--passphrase", password]
        if self.kind == "7z":
            return [self.path, "x", "-so", f"-p{password}", "-bd", "-bso0", "-bsp0", "-y", "--", archive]
        return [self.path, "-p", "-P", password, archive]


def _is_bsdtar(path: str) -> bool:
    # GNU tar cannot read ZIP; only libarchive's bsdtar (Windows 10+ tar.exe) can.
    try:
        result = subprocess.run(
            [path, "--version"], capture_output=True, timeout=TOOL_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and b"bsdtar" in result.stdout


@lru_cache(maxsize=None)
def unzip_tool() -> UnzipTool | None:
    """The fastest available external ZIP reader, found once per process."""
    system_root = os.environ.get("SystemRoot")
    tars = [str(Path(system_root, "System32", "tar.exe"))] if system_root else []
    tars += [found for found in (shutil.which("bsdtar"),) if found]
    for path in tars:
        if Path(path).is_file() and _is_bsdtar(path):
            return UnzipTool("bsdtar", path)
    program_files = [os.environ.get(name) for name in ("ProgramFiles", "ProgramW6432")]
    sevens = [shutil.which(name) for name in ("7z", "7zz", "7za")]
    sevens += [str(Path(root, "7-Zip", "7z.exe")) for root in program_files if root]
    for path in sevens:
        if path and Path(path).is_file():
            return UnzipTool("7z", path)
    found = shutil.which("unzip")
    return UnzipTool("unzip", found) if found else None


def prepare_tools() -> None:
    """Find (and for bsdtar, start once) the external reader before the timed clock."""
    unzip_tool()


def _run_bounded(command: list[str], limit: int) -> bytes | None:
    """stdout of a successful run, or None on failure, timeout, or more than limit bytes."""
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
    timer = threading.Timer(TOOL_TIMEOUT_SECONDS, process.kill)
    timer.start()
    try:
        output = process.stdout.read(limit + 1)
        if len(output) > limit:
            process.kill()
        process.stdout.close()
        code = process.wait()
    finally:
        timer.cancel()
    return output if code == 0 and len(output) <= limit else None


def _external_unzip(
    blob: bytes, infos: list[zipfile.ZipInfo], passwords: tuple[str, ...], budget: int,
) -> dict[int, bytes]:
    """Verified member bytes by infolist index; empty when the tool cannot be used."""
    tool = unzip_tool()
    files = [(index, info) for index, info in enumerate(infos) if not info.is_dir()]
    expected = sum(info.file_size for _, info in files)
    if tool is None or not files or expected > budget:
        return {}
    directory = tempfile.mkdtemp(prefix="huntress-zip-")
    try:
        archive = os.path.join(directory, "archive.zip")
        with open(archive, "xb") as stream:
            stream.write(blob)
        for password in passwords:
            output = _run_bounded(tool.command(archive, password), expected)
            if output is None or len(output) != expected:
                continue
            verified: dict[int, bytes] = {}
            offset = 0
            for index, info in files:
                data = output[offset:offset + info.file_size]
                offset += info.file_size
                # AE-2 AES entries store CRC 0; the tool's own HMAC check covered them.
                if zlib.crc32(data) == info.CRC or (info.compress_type == _ZIP_AES and info.CRC == 0):
                    verified[index] = data
            if verified:
                return verified
        return {}
    finally:
        shutil.rmtree(directory, ignore_errors=True)


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
                infos = archive.infolist()
                encrypted = [info for info in infos if info.flag_bits & 0x1 and not info.is_dir()]
                fast: dict[int, bytes] = {}
                if encrypted and (
                    sum(info.compress_size for info in encrypted) >= FAST_UNZIP_MIN_BYTES
                    or any(info.compress_type == _ZIP_AES for info in encrypted)
                ):
                    fast = _external_unzip(blob, infos, passwords, budget[0])
                for index, info in enumerate(infos):
                    if info.is_dir() or len(members) >= MAX_MEMBERS:
                        continue
                    inner = f"{name}/{info.filename}" if name else info.filename
                    if index in fast:
                        if take(len(fast[index]), inner):
                            keep(inner, fast[index], depth)
                        continue
                    if info.flag_bits & 0x1 and info.compress_type == _ZIP_AES:
                        notes.append(f"{inner}: AES-encrypted entry needs bsdtar, 7-Zip, or unzip with a known password")
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
