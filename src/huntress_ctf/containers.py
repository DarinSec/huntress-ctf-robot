"""Unpack archives in memory so solvers see inner files; nothing from them is executed.

The standard library decrypts ZipCrypto in pure Python (~1 MB/s), which would put about a
second per megabyte on the timed clock. Larger encrypted ZIPs, and AES ZIPs the standard
library cannot open, go through bsdtar, 7-Zip, or unzip instead: the archive bytes are
written to a private temporary file and the tool streams the members to stdout, so nothing
is extracted to paths named by the archive. Every member is checked against the ZIP's own
sizes and CRC-32 before it is used; anything else falls back to the standard library.
"""

from __future__ import annotations

from array import array
from collections.abc import Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from functools import lru_cache
from io import BytesIO
import lzma
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import zipfile
import zlib

MAX_MEMBERS = 5000
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_DEPTH = 3
# What reading a damaged ZIP member raises: a bad header or CRC (BadZipFile), a cut or corrupt
# stream (zlib.error, EOFError, lzma/bz2's LZMAError/OSError), a flipped method field
# (NotImplementedError) or encryption flag (RuntimeError). Every reader catches all of them:
# a damaged member is no data, never a crash (found by fuzz.py; ROBUSTNESS.md workstream 3).
ZIP_ERRORS = (zipfile.BadZipFile, zlib.error, EOFError, ValueError, NotImplementedError, RuntimeError,
              OSError, lzma.LZMAError)


class TooLarge(ValueError):
    """A member or stream past its reader's size limit: no data, like damage (it is in ZIP_ERRORS)."""


def read_member(archive: zipfile.ZipFile, member: str | zipfile.ZipInfo, limit: int = MAX_TOTAL_BYTES,
                pwd: bytes | None = None) -> bytes:
    """`archive.read(member)` that never inflates more than `limit` bytes (ROBUSTNESS.md workstream 4).

    The declared size is checked first, and the read stops at it: zipfile's read() inflates
    the whole stream before it cuts it to that size, so a header that understates a bomb
    would cost all of it. The result is what read() returns, CRC-checked the same way.
    """
    info = member if isinstance(member, zipfile.ZipInfo) else archive.getinfo(member)
    if info.file_size > limit:
        raise TooLarge(f"{info.filename}: {info.file_size} bytes, past the {limit} byte limit")
    with archive.open(info, pwd=pwd) as stream:
        return stream.read(info.file_size + 1)


def _unpacker(kind: str):
    if kind in ("zlib", "raw", "gzip"):
        return zlib.decompressobj({"zlib": zlib.MAX_WBITS, "raw": -zlib.MAX_WBITS, "gzip": 16 + zlib.MAX_WBITS}[kind])
    import bz2

    return lzma.LZMADecompressor() if kind == "xz" else bz2.BZ2Decompressor()


def decompress(data: bytes, kind: str, limit: int = MAX_TOTAL_BYTES, *, head: bool = False) -> bytes:
    """zlib/gzip/lzma/bz2.decompress (`kind` "zlib", "raw" deflate, "gzip", "xz" or "bz2") that
    stops past `limit` output bytes: TooLarge, or with `head` the first `limit` bytes.

    Otherwise as those calls: concatenated gzip, xz and bz2 streams are read on (gzip after
    zero padding; xz and bz2 ignore trailing junk), and a stream cut short or damaged raises
    one of ZIP_ERRORS (gzip's junk as zlib.error where gzip.decompress says BadGzipFile).
    """
    if not data and kind in ("gzip", "bz2"):
        return b""  # As gzip.decompress and bz2.decompress answer it.
    parts: list[bytes] = []
    left = limit + 1
    while True:
        unpacker = _unpacker(kind)
        try:
            parts.append(unpacker.decompress(data, left))
        except (lzma.LZMAError, OSError):
            if parts and kind in ("xz", "bz2"):
                return b"".join(parts)  # Not another stream: lzma.decompress and bz2.decompress stop here too.
            raise
        left -= len(parts[-1])
        if left <= 0:
            if head:
                return b"".join(parts)[:limit]
            raise TooLarge(f"{kind} data past the {limit} byte limit")
        if not unpacker.eof:
            raise {"xz": lzma.LZMAError, "bz2": ValueError, "gzip": EOFError}.get(kind, zlib.error)(
                "Compressed data ended before the end-of-stream marker was reached")
        data = unpacker.unused_data.lstrip(b"\0") if kind == "gzip" else unpacker.unused_data
        if kind in ("zlib", "raw") or not data:
            return b"".join(parts)
# Packaged formats are files in their own right, not folders of evidence: one nested JAR's
# 3,134 classes used up the member limit before Day 23 Binary's d08-d23 samples were reached.
# Their solvers read them whole (binary, metadata apk/jar/ooxml, evidence docProps, mobile).
PACKAGE_SUFFIXES = (
    ".jar", ".war", ".ear", ".aar", ".apk", ".apks", ".xapk", ".aab", ".ipa", ".appx", ".msix",
    ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".odt", ".ods", ".odp", ".epub",
    ".vsix", ".nupkg", ".whl", ".egg", ".xpi", ".crx",
)
_PACKAGE_MARKERS = ("META-INF/MANIFEST.MF", "AndroidManifest.xml", "[Content_Types].xml", "mimetype")
# AGENTS.md: Script Analysis and Binary lessons may publish the archive password `infected`.
DEFAULT_PASSWORDS = ("infected",)
# Below this much encrypted data the pure-Python path is faster than starting a process.
FAST_UNZIP_MIN_BYTES = 32 * 1024
TOOL_TIMEOUT_SECONDS = 30
PREFETCH_WORKERS = 4  # External unzips of sibling archives at once.
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


def is_package(name: str, data: bytes) -> bool:
    """A nested JAR/APK/Office-style ZIP, by extension or (when mislabeled) by its marker entry."""
    if name.lower().endswith(PACKAGE_SUFFIXES):
        return True
    if not data.startswith(b"PK\x03\x04"):
        return False
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            names = set(archive.namelist())
    except (zipfile.BadZipFile, ValueError, OSError):
        return False
    return any(marker in names for marker in _PACKAGE_MARKERS)


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


def winzip_counter_blocks(first: int, count: int) -> bytes:
    """WinZip AES-CTR counter blocks first, first+1, ...: 16 bytes each, little-endian.

    Built in C as 64-bit words (counter, then 0): a day 21 Binary Mastery needs 10.5M
    blocks, 0.56 s this way on the Homebase instead of 2.1 s packed one by one.
    """
    if sys.byteorder != "little" or array("Q").itemsize != 8 or first + count > 1 << 64:
        return b"".join(number.to_bytes(16, "little") for number in range(first, first + count))
    words = array("Q", bytes(16 * count))
    words[0::2] = array("Q", range(first, first + count))
    return words.tobytes()


def _aes_member(blob: bytes, info: zipfile.ZipInfo, passwords: tuple[str, ...]) -> bytes | None:
    """A WinZip AES (AE-1/AE-2) member in Python, when no external tool could read it.

    The playing Homebase has only Info-ZIP unzip, which cannot do AES, so the day 20
    Script Analysis archive unpacked to nothing. Needs the `cryptography` package
    (imported here, so a machine without it only loses this path). The HMAC-SHA1
    authentication code is checked like a CRC; nothing unverified is returned.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        return None
    import hashlib
    import hmac
    import struct

    start = info.header_offset
    if blob[start:start + 4] != b"PK\x03\x04":
        return None
    name_length, extra_length = struct.unpack_from("<HH", blob, start + 26)
    extra = info.extra or blob[start + 30 + name_length:start + 30 + name_length + extra_length]
    strength = method = None
    position = 0
    while position + 4 <= len(extra):
        tag, size = struct.unpack_from("<HH", extra, position)
        if tag == 0x9901 and size >= 7:
            strength, method = extra[position + 8], struct.unpack_from("<H", extra, position + 9)[0]
        position += 4 + size
    key_length = {1: 16, 2: 24, 3: 32}.get(strength)
    if key_length is None or method not in (0, 8):
        return None
    body_start = start + 30 + name_length + extra_length
    data = blob[body_start:body_start + info.compress_size]
    salt_length = key_length // 2
    salt, verifier = data[:salt_length], data[salt_length:salt_length + 2]
    cipher_text, code = data[salt_length + 2:-10], data[-10:]
    for password in passwords:
        keys = hashlib.pbkdf2_hmac("sha1", password.encode(), salt, 1000, 2 * key_length + 2)
        if keys[-2:] != verifier:
            continue
        if not hmac.compare_digest(hmac.new(keys[key_length:-2], cipher_text, hashlib.sha1).digest()[:10], code):
            return None
        # WinZip counts the CTR blocks little-endian from 1; one ECB call makes the stream.
        blocks = winzip_counter_blocks(1, len(cipher_text) // 16 + 1)
        stream = Cipher(algorithms.AES(keys[:key_length]), modes.ECB()).encryptor().update(blocks)
        size = len(cipher_text)
        plain = (int.from_bytes(cipher_text, "big") ^ int.from_bytes(stream[:size], "big")).to_bytes(size, "big")
        try:
            content = decompress(plain, "raw", info.file_size) if method == 8 else plain
        except (zlib.error, TooLarge):
            return None
        if info.CRC and zlib.crc32(content) != info.CRC:  # AE-1 keeps the CRC too.
            return None
        return content
    return None


def _wants_tool(infos: list[zipfile.ZipInfo]) -> bool:
    """Encrypted entries big enough (or AES) for the external tool rather than Python's ZipCrypto."""
    encrypted = [info for info in infos if info.flag_bits & 0x1 and not info.is_dir()]
    return bool(encrypted) and (sum(info.compress_size for info in encrypted) >= FAST_UNZIP_MIN_BYTES
                                or any(info.compress_type == _ZIP_AES for info in encrypted))


def unwrap(data: bytes, passwords: tuple[str, ...] = DEFAULT_PASSWORDS) -> Unwrapped:
    """Leaf files inside ZIP (incl. ZipCrypto), gzip, and tar containers, nested to MAX_DEPTH."""
    members: list[Member] = []
    notes: list[str] = []
    budget = [MAX_TOTAL_BYTES]
    prefetched: dict[tuple[str, int, int], Future] = {}

    def keep(name: str, blob: bytes, depth: int) -> None:
        if len(members) >= MAX_MEMBERS:
            notes.append(f"Member limit {MAX_MEMBERS} reached; the rest was skipped.")
            return
        nested = blob.startswith(_ZIP_MAGIC) or blob.startswith(b"\x1f\x8b") or _is_tar(blob)
        if depth < MAX_DEPTH and nested and not (blob.startswith(_ZIP_MAGIC) and is_package(name, blob)):
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

    def prefetch(name: str, archive: zipfile.ZipFile, infos: list[zipfile.ZipInfo], fast: dict[int, bytes]) -> None:
        """Start the external tool on sibling encrypted ZIPs at once (a Script Mastery nests ten,
        74 ms each one after another); visit takes each result, in order, when it gets there."""
        if unzip_tool() is None:
            return
        children = []
        for index, info in enumerate(infos):
            if info.is_dir() or not info.filename.lower().endswith(".zip") or info.file_size > budget[0]:
                continue
            if index in fast:
                child = fast[index]
            elif info.flag_bits & 0x1:
                continue  # Decrypting it twice in Python is what the tool is there to avoid.
            else:
                try:
                    child = read_member(archive, info, budget[0], None)
                except ZIP_ERRORS:
                    continue
            try:
                with zipfile.ZipFile(BytesIO(child)) as nested:
                    child_infos = nested.infolist()
            except ZIP_ERRORS:
                continue
            if _wants_tool(child_infos):
                children.append((f"{name}/{info.filename}" if name else info.filename, child, child_infos))
        if len(children) < 2:
            return
        workers = ThreadPoolExecutor(max_workers=min(PREFETCH_WORKERS, len(children)))
        for inner, child, child_infos in children:
            prefetched[(inner, len(child), zlib.crc32(child))] = workers.submit(
                _external_unzip, child, child_infos, passwords, budget[0])
        workers.shutdown(wait=False)

    def visit(name: str, blob: bytes, depth: int) -> None:
        if blob.startswith(_ZIP_MAGIC):
            try:
                archive = zipfile.ZipFile(BytesIO(blob))
            except ZIP_ERRORS:
                notes.append(f"{name or 'artifact'}: damaged ZIP")
                return
            with archive:
                infos = archive.infolist()
                fast: dict[int, bytes] = {}
                if _wants_tool(infos):
                    started = prefetched.pop((name, len(blob), zlib.crc32(blob)), None)
                    expected = sum(info.file_size for info in infos if not info.is_dir())
                    fast = started.result() if started is not None and expected <= budget[0] \
                        else _external_unzip(blob, infos, passwords, budget[0])
                if depth < MAX_DEPTH:
                    prefetch(name, archive, infos, fast)
                for index, info in enumerate(infos):
                    if info.is_dir() or len(members) >= MAX_MEMBERS:
                        continue
                    inner = f"{name}/{info.filename}" if name else info.filename
                    if info.file_size > budget[0]:  # Declared too large: skipped before inflating any of it.
                        notes.append(f"Size limit: skipped {inner!r}.")
                        continue
                    if index in fast:
                        if take(len(fast[index]), inner):
                            keep(inner, fast[index], depth)
                        continue
                    if info.flag_bits & 0x1 and info.compress_type == _ZIP_AES:
                        content = _aes_member(blob, info, passwords)
                        if content is None:
                            notes.append(f"{inner}: AES-encrypted entry needs bsdtar, 7-Zip, unzip or the "
                                         "cryptography package, and a known password")
                        elif take(len(content), inner):
                            keep(inner, content, depth)
                        continue
                    content = None
                    for password in ((None,) if not info.flag_bits & 0x1 else passwords):
                        try:
                            content = read_member(archive, info, budget[0], password.encode() if password else None)
                            break
                        except ZIP_ERRORS:
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
