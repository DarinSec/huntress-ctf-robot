"""Fuzz harness (ROBUSTNESS.md workstream 3): broken inputs must end in a clean "no answer".

A solver that hangs or raises on a truncated, corrupted or never-seen file is a bug: on the
clock a hang costs the flag, and the watchdog only limits the damage. This feeds every solver
mutants of real-shaped seeds (an assignment: its questions plus its artifact or deliveries)
and reports each input that hangs, raises, or kills the solver's process.

- Structure-aware: almost every artifact is a ZIP, and containers.py checks CRCs, so a random
  byte flip in the archive only ever tests "bad ZIP -> nothing". A ZIP-shaped input is mostly
  mutated one member deep (recursively: classes.dex in an APK in the evidence ZIP) and zipped
  again with valid CRCs; the rest of the time the archive's own bytes are hit.
- Reproducible: mutant N of a seed comes from its own generator ("<seed>:<name>:<N>"), so a
  finding is named by seed name and index and replays anywhere (`mutant`, `scripts/fuzz.py
  --repro`).
- One child per solver walks all mutants and reports each before and after solving. When an
  input outlives its budget the child is killed, the input is a "hang", and a fresh child goes
  on with the next one. The child has a memory ceiling, so a forged 4 GB length field ends as
  a MemoryError finding, not a frozen machine.

- Bombs (ROBUSTNESS.md workstream 4): with `bomb=<bytes>` each mutant replaces one member
  (one ZIP level deep, as above) by a stream that inflates to that size: a ZIP entry whose own
  deflate data is the bomb (honest size and CRC, or a header claiming 1 MiB with that MiB's
  CRC: zipfile's read() inflates it all before it cuts), or a gzip, xz, bz2 or zlib blob. Run with a
  memory ceiling below the bomb, any path that reads it whole meets MemoryError there. A bomb
  is one small compressed piece repeated (a fully flushed deflate block; concatenated gzip,
  xz and bz2 streams), so it costs milliseconds, not the seconds of compressing it.

`scripts/fuzz.py` fuzzes the local replay corpus (real-shaped, never committed);
tests/test_fuzz.py fuzzes synthetic seeds of every non-web lane on each test run, and
tests/test_resources.py sends them bombs.
"""

from __future__ import annotations

import bz2
from dataclasses import dataclass, field
from functools import lru_cache
import gzip
from io import BytesIO
import lzma
import multiprocessing
from multiprocessing.connection import wait
import os
from pathlib import Path
import random
import re
import struct
import sys
import time
import traceback
from typing import Any, Iterator, Sequence
import zipfile
import zlib

from .containers import Member

BUDGET_S = 5.0  # Per input. Every solver answers a small mutant in milliseconds.
MEMORY_HEADROOM = 2 << 30  # The child may grow this much past its size at the fork.
BOMB_FLAVOURS = ("zip-deflate", "zip-understated", "gzip", "xz", "bz2", "zlib")
_STATED = 1 << 20  # What an understated bomb's header claims.
_PIECE = 8 << 20  # Bytes of zeros per concatenated gzip/xz/bz2 stream.
MAX_GROWTH = 1 << 20  # A mutant is at most this much larger than its seed.
PASSWORDS = (b"infected",)  # Reads an encrypted seed member; mutants are zipped without one.
INTERESTING = (0, 1, 2, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
               0xFFFFFFFFFFFFFFFF)


@dataclass(frozen=True)
class Seed:
    """One real-shaped assignment: the record, the attempt (its questions) and its bytes."""

    name: str
    challenge: dict[str, Any]
    attempt: dict[str, Any]
    artifact: bytes
    deliveries: tuple[Member, ...] = ()


@dataclass(frozen=True)
class Finding:
    solver: str
    seed: str
    index: int
    mutation: str
    status: str  # hang, crashed or died
    detail: str = ""
    where: str = ""  # file:line in function, of the innermost frame in this package

    def line(self) -> str:
        return (f"{self.solver}: {self.status} on {self.seed}#{self.index} ({self.mutation})"
                + (f" at {self.where}" if self.where else "") + (f": {self.detail}" if self.detail else ""))


@dataclass
class _Child:
    solver: Any
    jobs: list[tuple[int, int]]  # (seed position, mutant index), in order
    position: int = 0  # The next job this child (or its replacement) works on.
    process: Any = None
    conn: Any = None
    started: float = 0.0  # When the current input began; 0 while between inputs.
    current: tuple[int, int, str] | None = None
    findings: list[Finding] = field(default_factory=list)


def is_zip(data: bytes) -> bool:
    return data[:4] in (b"PK\x03\x04", b"PK\x05\x06")


def _read_zip(data: bytes) -> list[tuple[zipfile.ZipInfo, bytes]] | None:
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            found = []
            for info in archive.infolist():
                try:
                    found.append((info, archive.read(info)))
                except RuntimeError:  # Encrypted: the lesson password, as containers.py reads it.
                    found.append((info, next(archive.read(info, pwd=p) for p in PASSWORDS)))
            return found
    except Exception:
        return None


def _zip(entries: list[tuple[zipfile.ZipInfo, bytes]]) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for info, data in entries:
            clean = zipfile.ZipInfo(info.filename, info.date_time)
            clean.compress_type = zipfile.ZIP_STORED if info.compress_type == zipfile.ZIP_STORED else zipfile.ZIP_DEFLATED
            clean.external_attr = info.external_attr
            archive.writestr(clean, data)
    return buffer.getvalue()


def _raw(data: bytes, rng: random.Random) -> tuple[bytes, str]:
    """One byte-level mutation, aimed at headers (the first 4 KiB) more often than not."""
    out = bytearray(data)
    size = len(out)

    def spot() -> int:
        if not size:
            return 0
        return rng.randrange(min(size, 4096)) if rng.random() < 0.7 else rng.randrange(size)
    kind = rng.choice(("truncate", "flip", "field", "insert", "delete", "repeat", "fill", "text"))
    if kind == "truncate" or not size:
        cut = spot()
        return bytes(out[:cut]), f"truncate to {cut}"
    if kind == "flip":
        flips = rng.randint(1, 8)
        for _ in range(flips):
            at = spot()
            out[at] ^= 1 << rng.randrange(8)
        return bytes(out), f"flip {flips} bit(s)"
    if kind == "field":
        width = rng.choice((2, 4, 8))
        at = spot() & ~(width - 1)
        value = rng.choice(INTERESTING + (size, size + 1, max(size - 1, 0))) & ((1 << (8 * width)) - 1)
        order = rng.choice(("little", "big"))
        out[at:at + width] = value.to_bytes(width, order)
        return bytes(out), f"set {width}-byte {order} field at {at} to {value:#x}"
    if kind == "insert":
        at, count = spot(), rng.randint(1, 256)
        out[at:at] = bytes(rng.randrange(256) for _ in range(count))
        return bytes(out), f"insert {count} random bytes at {at}"
    if kind == "delete":
        at = spot()
        count = rng.randint(1, max(1, min(4096, size - at)))
        del out[at:at + count]
        return bytes(out), f"delete {count} bytes at {at}"
    if kind == "repeat":
        at = spot()
        count = rng.randint(1, max(1, min(4096, size - at)))
        times = rng.randint(2, 64)
        chunk = bytes(out[at:at + count]) * times
        out[at:at + count] = chunk[:count + MAX_GROWTH]
        return bytes(out), f"repeat {count} bytes at {at} x{times}"
    if kind == "fill":
        at = spot()
        count = rng.randint(1, max(1, min(4096, size - at)))
        byte = rng.choice((0x00, 0xFF, 0x41))
        out[at:at + count] = bytes([byte]) * len(out[at:at + count])
        return bytes(out), f"fill {count} bytes at {at} with {byte:#04x}"
    # text: the shapes that break line and token parsers.
    at = spot()
    token = rng.choice((b"\n" * 64, b"\r\n", b"\x00", b"\"", b"'", b"\\", b"{", b"}", b"[", b"]", b"<", b">",
                        "‮İ﻿".encode(), b"\xff\xfe", b"%", b"=" * 64, b"A" * 65536, b"9" * 400))
    out[at:at] = token
    return bytes(out), f"insert {len(token)}-byte token {token[:8]!r} at {at}"


def mutate(data: bytes, rng: random.Random, depth: int = 0) -> tuple[bytes, str]:
    """A mutant of `data` and what was done; a ZIP is usually mutated one member deep."""
    if is_zip(data) and depth < 3 and rng.random() < 0.8:
        entries = _read_zip(data)
        files = [i for i, (info, _) in enumerate(entries or ()) if not info.is_dir()]
        if entries and files:
            pick = rng.choice(files)
            info, inner = entries[pick]
            changed, how = mutate(inner, rng, depth + 1)
            entries[pick] = (info, changed)
            return _zip(entries), f"{info.filename}: {how}"
    for _ in range(10):  # A mutation that changes nothing (a fill over equal bytes) is retried.
        changed, how = _raw(data, rng)
        if changed != data:
            return changed[:len(data) + MAX_GROWTH], how
    return changed, how


@lru_cache(maxsize=None)
def _deflate_bomb(size: int) -> tuple[bytes, int]:
    """Raw deflate inflating to `size` zero bytes, and their CRC-32: after a full flush the
    compressor starts afresh, so one MiB's block repeated is a valid stream."""
    chunk = bytes(1 << 20)
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    block = compressor.compress(chunk) + compressor.flush(zlib.Z_FULL_FLUSH)
    crc = 0
    for _ in range(size >> 20):
        crc = zlib.crc32(chunk, crc)
    return block * (size >> 20) + compressor.flush(), crc


@lru_cache(maxsize=None)
def bomb_blob(flavour: str, size: int) -> bytes:
    """A gzip, xz, bz2 or zlib stream inflating to `size` zero bytes (`size` a multiple of 8 MiB)."""
    if flavour == "zlib":
        deflate, _ = _deflate_bomb(size)
        adler, chunk = 1, bytes(1 << 20)
        for _ in range(size >> 20):
            adler = zlib.adler32(chunk, adler)
        return b"\x78\xda" + deflate + struct.pack(">I", adler)
    compress = {"gzip": lambda d: gzip.compress(d, 9), "xz": lzma.compress, "bz2": bz2.compress}[flavour]
    return compress(bytes(_PIECE)) * (size // _PIECE)  # Each decoder reads concatenated streams.


def _zip_bomb(entries: list[tuple[zipfile.ZipInfo, bytes]], at: int, size: int, understated: bool = False) -> bytes:
    """The ZIP of `entries` with entry `at` a deflate bomb of `size` bytes, written by hand
    (zipfile would have to compress the whole size); `understated`, its header says 1 MiB."""
    out, central = bytearray(), bytearray()
    for index, (info, data) in enumerate(entries):
        name = info.filename.encode()
        if index == at:
            packed, crc = _deflate_bomb(size)
            usize = size
            if understated:
                usize, crc = _STATED, zlib.crc32(bytes(_STATED))
        else:
            compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
            packed, crc, usize = compressor.compress(data) + compressor.flush(), zlib.crc32(data), len(data)
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 8, 0, 0x21, crc, len(packed), usize,
                               len(name), 0, 0, 0, 0, 0, len(out)) + name
        out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 8, 0, 0x21, crc, len(packed), usize, len(name), 0)
        out += name + packed
    return bytes(out + central + struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries),
                                             len(central), len(out), 0))


def bombed(data: bytes, rng: random.Random, size: int, depth: int = 0) -> tuple[bytes, str]:
    """`data` with one member (one ZIP level deep, sometimes two) replaced by a bomb."""
    if is_zip(data) and depth < 3:
        entries = _read_zip(data)
        files = [i for i, (info, _) in enumerate(entries or ()) if not info.is_dir()]
        if entries and files:
            pick = rng.choice(files)
            info, inner = entries[pick]
            if is_zip(inner) and rng.random() < 0.5:
                changed, how = bombed(inner, rng, size, depth + 1)
                entries[pick] = (info, changed)
                return _zip(entries), f"{info.filename}: {how}"
            flavour = rng.choice(BOMB_FLAVOURS)
            if flavour.startswith("zip-"):
                understated = flavour == "zip-understated"
                return (_zip_bomb(entries, pick, size, understated),
                        f"{info.filename}: a {size >> 20} MiB deflate bomb" + (" stated as 1 MiB" if understated else ""))
            entries[pick] = (info, bomb_blob(flavour, size))
            return _zip(entries), f"{info.filename}: a {size >> 20} MiB {flavour} bomb"
    flavour = rng.choice(BOMB_FLAVOURS[2:])
    return bomb_blob(flavour, size), f"a {size >> 20} MiB {flavour} bomb"


def mutant(seed: Seed, index: int, salt: str = "0", bomb: int = 0) -> tuple[Seed, str]:
    """Mutant `index` of `seed`: one of its files mutated (or, with `bomb`, one member replaced
    by a bomb of that many bytes), always the same for the same salt."""
    rng = random.Random(f"{salt}:{seed.name}:{index}")
    change = (lambda data: bombed(data, rng, bomb)) if bomb else (lambda data: mutate(data, rng))
    if seed.deliveries:
        pick = rng.randrange(len(seed.deliveries))
        member = seed.deliveries[pick]
        changed, how = change(member.data)
        deliveries = tuple(Member(m.name, changed) if i == pick else m for i, m in enumerate(seed.deliveries))
        return Seed(seed.name, seed.challenge, seed.attempt, deliveries[0].data, deliveries), f"{member.name}: {how}"
    changed, how = change(seed.artifact)
    return Seed(seed.name, seed.challenge, seed.attempt, changed), how


def context(seed: Seed) -> Any:
    """The solver input for a seed, built as the race builds it (members unpack lazily)."""
    from .autopilot import build_context
    from .state import AttemptState

    answer_ids = AttemptState.parse(seed.attempt).answer_ids
    extra = seed.deliveries if len(seed.deliveries) > 1 else ()
    built, _ = build_context(str(seed.challenge.get("id") or seed.name), seed.challenge, seed.attempt,
                             seed.artifact, Path(seed.name), answer_ids, None, extra)
    return built


def _where(exc: BaseException) -> str:
    """The innermost frame of this package below the harness (else the innermost of all):
    formats.py:822 rather than the zipfile.py line it called."""
    frames = [frame for frame in traceback.extract_tb(exc.__traceback__) if frame.filename != __file__]
    ours = [frame for frame in frames if "huntress_ctf" in frame.filename] or frames
    if not ours:
        return ""
    frame = ours[-1]
    return f"{frame.filename.rsplit('huntress_ctf' + os.sep, 1)[-1]}:{frame.lineno} in {frame.name}"


def _work(solver: Any, seeds: Sequence[Seed], jobs: list[tuple[int, int]], salt: str, conn: Any,
          memory: int, bomb: int) -> None:
    from .watchdog import cap_memory

    sys.stdout = sys.stderr = open(os.devnull, "w")
    cap_memory(memory)
    for seed_at, index in jobs:
        changed, how = mutant(seeds[seed_at], index, salt, bomb)
        conn.send(("begin", seed_at, index, how))
        try:
            list(solver.solve(context(changed)))
            conn.send(("ok",))
        except BaseException as exc:  # noqa: BLE001 - every raise is a finding
            conn.send(("crashed", f"{type(exc).__name__}: {str(exc)[:200]}", _where(exc)))
    conn.close()


def run(
    solvers: Sequence[Any], seeds: Sequence[Seed], count: int, *, budget: float = BUDGET_S, salt: str = "0",
    parallel: int | None = None, progress: Any = None, memory: int = MEMORY_HEADROOM, bomb: int = 0,
) -> list[Finding]:
    """`count` mutants of every seed through every solver; each hang, raise or death found.

    `memory` is each child's ceiling above its size at the fork; `bomb` (bytes) sends bombs
    instead of mutants: keep `memory` below it, so a whole read shows as a MemoryError.
    """
    from .watchdog import solver_name

    for flavour in BOMB_FLAVOURS[2:] if bomb else ():  # Built once here; every child inherits them.
        bomb_blob(flavour, bomb)
    if bomb:
        _deflate_bomb(bomb)
    fork = multiprocessing.get_context("fork")
    jobs = [(seed_at, index) for index in range(count) for seed_at in range(len(seeds))]
    children = [_Child(solver, jobs) for solver in solvers]
    waiting = list(children)
    running: dict[Any, _Child] = {}

    def launch(child: _Child) -> None:
        parent, end = fork.Pipe(duplex=False)
        child.process = fork.Process(target=_work, args=(child.solver, seeds, child.jobs[child.position:], salt, end,
                                                         memory, bomb), daemon=True)
        child.process.start()
        end.close()
        child.conn, child.started, child.current = parent, 0.0, None
        running[parent] = child

    def lose(child: _Child, status: str, detail: str) -> None:
        """The current input hung or killed the child: record it, go on with the next one."""
        running.pop(child.conn, None)
        if child.process.is_alive():
            child.process.kill()
        child.process.join(1)
        child.conn.close()
        if child.current is not None:
            seed_at, index, how = child.current
            child.findings.append(Finding(solver_name(child.solver), seeds[seed_at].name, index, how, status, detail))
            child.position += 1
        if child.position < len(child.jobs):
            launch(child)

    try:
        while waiting or running:
            while waiting and len(running) < max(1, parallel or os.cpu_count() or 1):
                launch(waiting.pop(0))
            now = time.monotonic()
            busy = [child.started + budget - now for child in running.values() if child.started]
            for conn in wait(list(running), timeout=max(0.0, min(busy)) if busy else budget):
                child = running[conn]
                try:
                    message = conn.recv()
                except (EOFError, OSError):
                    child.process.join(1)
                    if child.current is None:  # Finished every job and closed the pipe.
                        running.pop(conn)
                        conn.close()
                        child.process.join(1)
                    else:
                        lose(child, "died", f"the solver process exited with code {child.process.exitcode}")
                    continue
                if message[0] == "begin":
                    child.current, child.started = (message[1], message[2], message[3]), time.monotonic()
                    continue
                seed_at, index, how = child.current
                if message[0] == "crashed":
                    child.findings.append(Finding(solver_name(child.solver), seeds[seed_at].name, index, how,
                                                  "crashed", message[1], message[2]))
                child.current, child.started = None, 0.0
                child.position += 1
                if progress is not None:
                    progress(solver_name(child.solver), child.position, len(child.jobs))
            now = time.monotonic()
            for child in [c for c in running.values() if c.started and now - c.started >= budget]:
                lose(child, "hang", f"no answer within {budget:g} s")
    finally:
        for child in list(running.values()):
            if child.process.is_alive():
                child.process.kill()
            child.process.join(1)
    return [finding for child in children for finding in child.findings]


def question_kind(text: str) -> str:
    """A question with its names and numbers masked: one Mastery kind, many questions."""
    text = re.sub(r"`[^`]*`|\b[\w.-]+\.(?:ps1|exe|dll|zip|apk|evtx|so|bin|json|txt|csv)\b", "<f>", text)
    return re.sub(r"[0-9a-fA-F]{6,}|\d+", "#", text)[:160]


def one_per_kind(attempt: dict[str, Any], limit: int = 60) -> dict[str, Any]:
    """The attempt with one question per kind (at most `limit`): every parser still runs."""
    questions = attempt.get("questions") or []
    kept, seen = [], set()
    for question in questions:
        kind = question_kind(str(question.get("question", "")))
        if kind not in seen:
            seen.add(kind)
            kept.append(question)
    kept = kept[:limit]
    return {**attempt, "questions": kept, "answer_ids": [q.get("id") for q in kept]}


def corpus_seeds(root: Path | None = None, only: str = "") -> Iterator[Seed]:
    """Seeds from the local replay corpus: real-shaped, one question per kind."""
    from . import corpus

    for entry in corpus.entries(root, only):
        saved = corpus._read(entry / "assignment.json")
        files = sorted((entry / "deliveries").iterdir(), key=lambda path: int(path.name.split("-", 1)[0]))
        deliveries = tuple(Member(f"delivery {path.name.split('-', 1)[0]}: {path.name.split('-', 1)[1]}",
                                  path.read_bytes()) for path in files)
        yield Seed(f"{entry.parent.name}/{entry.name[:8]}", saved.get("challenge") or {},
                   one_per_kind(saved.get("attempt") or {}), deliveries[0].data,
                   deliveries if len(deliveries) > 1 else ())
