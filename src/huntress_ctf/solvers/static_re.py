"""Static reverse engineering: the `flag` of a standalone, traditional CTF route.

Day 30 adds one static Single Solve outside the daily lanes: a reverse engineering task
worth 5 points, no Time Trial or Mastery. Such a route asks for one `flag` (the shape of
Day 1's "Read the Rules": answer_ids ["flag"], maybe no questions[] at all). This reads
the bytes only, never runs the sample, and answers only when exactly one flag of the
answer's shape turns up in the artifact or its members:

- plain text, UTF-16LE/BE (.NET user strings), ROT13/ROT47/reversed text;
- one byte operation over the whole file: XOR, ADD and rotate by a constant, XOR/ADD/SUB
  by the index (the crackme classics);
- a string decoded by one or two strict layers (Base64, hex, Base32, Ascii85, ...);
- x86 stack strings: the flag stored a byte, dword or qword at a time (mov [rbp/rsp+d],
  imm; movabs reg, imm64), plain or XORed with one byte;
- zlib streams inside the file (PyInstaller CArchive, packed resources), and UPX packing
  when `upx` is installed (`upx -d` only decompresses, it never runs the sample).

A key computed at run time, anti-debug or a checker that has to be inverted is a human's
(Ghidra/r2): two different flags, or none, answer nothing, so a decoy is never sent.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import time
import zlib
from pathlib import Path

from ..decoders import decode_fragment, rot13, rot47
from .base import AnswerCandidate, SolveContext, question_items

# Huntress flags are flag{32 lowercase hex}; a format that names another shape widens it.
DEFAULT_PREFIX = "flag"
_HEX32 = "[0-9a-f]{32}"
_LOOSE = r"[!-z|~]{4,96}"  # Printable, no space or braces.
_PREFIX = re.compile(r"\b([A-Za-z][A-Za-z0-9_]{1,15})\{")
_SET = re.compile(r"^set\d+\.")
_MAX_FLAG = 128
MAX_FLAG_QUESTIONS = 8  # A traditional task asks one; a lane's thousands are not this.
MAX_SCAN = 32 * 1024 * 1024  # Byte transforms and stack strings stop past this per file.
MAX_STREAMS = 256  # zlib streams inflated per file.
MAX_HEADERS = 20000  # zlib header bytes tried per file (most are chance bytes in code).
STREAM_WINDOW = 8 * 1024 * 1024  # Compressed bytes read per stream.
MAX_TOKENS = 5000  # Encoded-looking strings decoded per file.
DECODE_BUDGET_S = 20.0  # For those strings; the watchdog stops a solver at 90 s.
_ROTATE = tuple(range(1, 8))
_TEXT_STEPS = {"rot13": rot13, "rot47": rot47, "reverse": lambda text: text[::-1]}
_LAYER_CHAINS = (
    *((name,) for name in ("base64", "hex", "base32", "ascii85", "base85", "base58", "decimal",
                           "binary", "octal", "url", "unicode", "base32hex", "base62")),
    ("base64", "base64"), ("base64", "hex"), ("hex", "base64"), ("base64", "zlib"),
    ("base32", "base64"), ("hex", "hex"),
)
# Base64/32/58/62 and hex alphabets; base64 of a 38-character flag is 52, hex 76. Ascii85
# keeps its <~ ~> frame.
_TOKEN = re.compile(rb"[A-Za-z0-9+/=_\-]{40,8192}|<~[!-u\s]{40,8192}~>")
_ZLIB_HEADER = re.compile(rb"\x78[\x01\x5e\x9c\xda]")


def flag_questions(context: SolveContext) -> list[tuple[str, str]]:
    """(answer_id, question text and format) of the questions that want a CTF flag."""
    items = {item.answer_id: item for item in question_items(context)}
    found = []
    for answer_id in context.answer_ids:
        item = items.get(answer_id)
        syntax = str((item.answer_format.get("syntax") or "") if item else "")
        text = f"{item.text if item else ''} {syntax}"
        # Exactly "flag" (Read the Rules, Welcome Robots), never a lane's "..._access_flags".
        if _SET.sub("", answer_id) == "flag" or re.search(r"\bflag\b.*\{", syntax, re.I | re.S):
            found.append((answer_id, text))
    return found if len(found) <= MAX_FLAG_QUESTIONS else []


def flag_pattern(text: str) -> re.Pattern[str]:
    """The flag's shape: the prefix the format names (default flag), a 32-hex body unless
    the format describes another one."""
    prefixes = {match.lower() for match in _PREFIX.findall(text)}
    prefix = prefixes.pop() if len(prefixes) == 1 else DEFAULT_PREFIX
    folded = text.casefold()
    loose = folded.strip() and ("hex" not in folded or not re.search(r"\b32\b", folded))
    named = re.search(r"\b(?:any|printable|text|characters)\b", folded)
    body = _LOOSE if loose and named else _HEX32
    return re.compile(re.escape(prefix) + r"\{" + body + r"\}")


class StaticFlagSolver:
    name = "static-flag"

    def solve(self, context: SolveContext) -> list[AnswerCandidate]:
        wanted = flag_questions(context)
        if not wanted:
            return []
        blobs = [("artifact", bytes(context.artifact))]
        blobs += [(member.name, member.data) for member in context.members]
        candidates = []
        for answer_id, text in wanted:
            pattern = flag_pattern(text)
            found: dict[str, list[str]] = {}
            for name, data in blobs:
                for flag, how in scan(data, pattern):
                    found.setdefault(flag, []).append(f"{name}: {how}")
            if len(found) == 1:
                (flag, hows), = found.items()
                candidates.append(AnswerCandidate(
                    answer_id, flag, self.name,
                    f"The only {pattern.pattern} in the bytes ({'; '.join(sorted(set(hows))[:4])}).",
                ))
        return candidates


def scan(data: bytes, pattern: re.Pattern[str], depth: int = 0) -> list[tuple[str, str]]:
    """Every (flag, how it was found) in one file, its zlib streams and its UPX unpacking."""
    found = _text(data, pattern) + _byte_ops(data, pattern) + _encoded(data, pattern)
    found += _stack_strings(data, pattern)
    if depth < 2:
        for offset, inner in _streams(data):
            found += [(flag, f"zlib at 0x{offset:x}, {how}") for flag, how in scan(inner, pattern, depth + 1)]
        unpacked = _upx(data) if depth == 0 else None
        if unpacked:
            found += [(flag, f"upx -d, {how}") for flag, how in scan(unpacked, pattern, depth + 1)]
    return found


def _matches(text: str, pattern: re.Pattern[str], how: str) -> list[tuple[str, str]]:
    return [(match.group(), how) for match in pattern.finditer(text)]


def _text(data: bytes, pattern: re.Pattern[str]) -> list[tuple[str, str]]:
    latin = data.decode("latin-1")
    found = _matches(latin, pattern, "text")
    if len(data) > MAX_SCAN:
        return found
    for name, step in _TEXT_STEPS.items():
        found += _matches(step(latin), pattern, name)
    for codec in ("utf-16-le", "utf-16-be"):
        for start in (0, 1):
            text = data[start:].decode(codec, errors="replace")
            found += _matches(text, pattern, codec)
    return found


def _byte_ops(data: bytes, pattern: re.Pattern[str]) -> list[tuple[str, str]]:
    """XOR/ADD/rotate by a constant over the whole file (prefix found first), and XOR/ADD/SUB
    by the index from where the flag starts."""
    if len(data) > MAX_SCAN:
        return []
    prefix = pattern.pattern.split("\\{", 1)[0].replace("\\", "").encode() + b"{"
    ops = [(f"xor 0x{key:02x}", lambda b, key=key: b ^ key) for key in range(1, 256)]
    ops += [(f"add 0x{key:02x}", lambda b, key=key: (b + key) & 0xFF) for key in range(1, 256)]
    ops += [(f"rol {bits}", lambda b, bits=bits: ((b << bits) | (b >> (8 - bits))) & 0xFF) for bits in _ROTATE]
    found = []
    for how, encode in ops:
        table = bytes(encode(b) for b in range(256))
        needle = prefix.translate(table)
        if data.find(needle) < 0:
            continue
        inverse = bytes(table.index(b) for b in range(256))
        found += _matches(data.translate(inverse).decode("latin-1"), pattern, how)
    by_index = (
        ("xor index", lambda c, i: c ^ i), ("add index", lambda c, i: c - i), ("sub index", lambda c, i: c + i),
    )
    for how, decode in by_index:
        # The flag's first bytes as this encoding stores them: c = p ^ i, p + i or p - i.
        needle = bytes(next(c for c in range(256) if decode(c, i) & 0xFF == p) for i, p in enumerate(prefix))
        start = data.find(needle)
        while start >= 0:
            window = data[start:start + _MAX_FLAG]
            text = bytes(decode(c, i) & 0xFF for i, c in enumerate(window)).decode("latin-1")
            if match := pattern.match(text):
                found.append((match.group(), f"{how} at 0x{start:x}"))
            start = data.find(needle, start + 1)
    return found


def _encoded(data: bytes, pattern: re.Pattern[str]) -> list[tuple[str, str]]:
    """Encoded-looking strings, decoded by one or two strict layers, then as is or by a
    text step (ROT13 of Base64, reversed hex, ...)."""
    found = []
    seen: set[bytes] = set()
    ends = time.monotonic() + DECODE_BUDGET_S
    for match in _TOKEN.finditer(data):
        token = match.group().strip()
        if token in seen:
            continue
        seen.add(token)
        if len(seen) > MAX_TOKENS or time.monotonic() > ends:
            break
        text = token.decode("ascii")
        for source, label in ((text, ""), *((step(text), f"{name}, ") for name, step in _TEXT_STEPS.items())):
            for chain in _LAYER_CHAINS:
                decoded = decode_fragment(source, chain)
                if decoded is None:
                    continue
                for flag, _ in _matches(decoded, pattern, ""):
                    found.append((flag, f"{label}{'+'.join(chain)} of a string at 0x{match.start():x}"))
                for name, step in _TEXT_STEPS.items():
                    for flag, _ in _matches(step(decoded), pattern, ""):
                        found.append((flag, f"{label}{'+'.join(chain)}+{name} at 0x{match.start():x}"))
    return found


# x86 stack strings: just the instructions compilers build a local string with. An event is
# (file offset, end, kind, ...); the stores land in a frame by base and displacement, so
# gcc's overlapping last store (39 bytes as qwords at 0, 8, 16, 24 and 31) comes out right.
_EVENT = re.compile(
    rb"[\x40-\x4f]?[\xb8-\xbf]"            # mov r32/r64, imm (movabs with REX.W)
    rb"|\x66?[\x40-\x4f]?[\x89\xc6\xc7]"     # mov m, r / mov m8, imm8 / mov m, imm16/32
    rb"|[\x66\xf3]?[\x40-\x4f]?\x0f[\x6f\x28\x10\x29\x11\x7f]",  # SSE 16-byte load / store
)
_GAP = 64  # Bytes of code between two instructions of one string.
_SSE_LOADS = {(0x66, 0x6F), (0xF3, 0x6F), (None, 0x28), (0x66, 0x28), (None, 0x10), (0x66, 0x10)}
_SSE_STORES = {(None, 0x29), (0x66, 0x29), (None, 0x11), (0x66, 0x11), (0x66, 0x7F), (0xF3, 0x7F)}


def _operand(data: bytes, at: int, rex: int) -> tuple[str, int, int, int] | None:
    """ModRM at `at`: (base "rbp"/"rsp"/"rip", displacement, reg field, end) or None."""
    if at >= len(data):
        return None
    modrm = data[at]
    mod, reg, rm = modrm >> 6, (modrm >> 3) & 7 | (rex & 4) << 1, modrm & 7
    at += 1
    if mod == 3 or rex & 1:
        return None  # A register operand, or r12/r13 for a base.
    if rm == 4:
        if at >= len(data) or data[at] != 0x24:
            return None
        base, at = "rsp", at + 1
    elif rm == 5:
        base = "rbp" if mod else "rip"
    else:
        return None
    size = {0: 4 if base == "rip" else 0, 1: 1, 2: 4}[mod]
    if at + size > len(data):
        return None
    disp = int.from_bytes(data[at:at + size], "little", signed=True) if size else 0
    return base, disp, reg, at + size


def _events(data: bytes, spans: list[tuple[int, int]]):
    """Decoded loads and stores in file order: ("imm", reg, bytes) or ("store", base, disp,
    bytes | (reg, size)) or ("sse-load", reg, disp32) or ("sse-store", base, disp, reg).

    A linear sweep: the next search starts where a decoded instruction ends, so an
    immediate that looks like a prefix (0x66 is "f") never swallows the move after it."""
    for start, stop in spans:
        at = start
        while (match := _EVENT.search(data, at, stop)) is not None:
            event = _decode(data, match)
            at = event[1] if event else match.start() + 1
            if event:
                yield event


def _decode(data: bytes, match: re.Match[bytes]) -> tuple | None:
    at, code, end = match.start(), match.group(), match.end()
    prefix = code[0] if code[0] in (0x66, 0xF3) else None
    rex = next((b for b in code if 0x40 <= b <= 0x4F), 0)
    op = code[-1]
    if len(code) >= 2 and code[-2] == 0x0F:
        operand = _operand(data, end, rex)
        if operand is None:
            return None
        base, disp, reg, after = operand
        if (prefix, op) in _SSE_LOADS and base == "rip":
            return at, after, "sse-load", reg, disp
        if (prefix, op) in _SSE_STORES and base != "rip":
            return at, after, "sse-store", base, disp, reg
        return None
    if 0xB8 <= op <= 0xBF:
        size = 8 if rex & 8 else 4
        if prefix or end + size > len(data):
            return None
        return at, end + size, "imm", op - 0xB8 | (rex & 1) << 3, data[end:end + size]
    operand = _operand(data, end, rex)
    if operand is None or operand[0] == "rip":
        return None
    base, disp, reg, after = operand
    if op == 0x89:
        return at, after, "store", base, disp, (reg, 8 if rex & 8 else 2 if prefix else 4)
    if (reg & 7) != 0:  # C6 /0 and C7 /0 are the immediate moves.
        return None
    size = 1 if op == 0xC6 else 2 if prefix else 4
    if after + size > len(data):
        return None
    imm = data[after:after + size]
    if op == 0xC7 and rex & 8:  # Sign-extended to a qword.
        imm += (b"\xff" if imm[-1] & 0x80 else b"\0") * 4
    return at, after + size, "store", base, disp, imm


def _segments(data: bytes) -> tuple[list[tuple[int, int, int]], bool, list[tuple[int, int]]]:
    """(file offset, virtual address, size) of an ELF's PT_LOAD or a PE's sections, whether
    it is 64-bit (a 32-bit [disp32] is an absolute address, not RIP-relative), and the file
    ranges that hold code (PF_X, IMAGE_SCN_MEM_EXECUTE)."""
    u = lambda at, size: int.from_bytes(data[at:at + size], "little")  # noqa: E731
    found: list[tuple[int, int, int]] = []
    code: list[tuple[int, int]] = []
    wide = True
    try:
        if data[:4] == b"\x7fELF" and data[5] == 1:
            wide = data[4] == 2
            phoff, entsize, count = (u(0x20, 8), u(0x36, 2), u(0x38, 2)) if wide else (u(0x1C, 4), u(0x2A, 2), u(0x2C, 2))
            for index in range(min(count, 64)):
                at = phoff + index * entsize
                if u(at, 4) == 1:  # PT_LOAD
                    offset, va, size, flags = ((u(at + 8, 8), u(at + 16, 8), u(at + 32, 8), u(at + 4, 4)) if wide
                                               else (u(at + 4, 4), u(at + 8, 4), u(at + 16, 4), u(at + 24, 4)))
                    found.append((offset, va, size))
                    if flags & 1:
                        code.append((offset, min(offset + size, len(data))))
        elif data[:2] == b"MZ" and data[u(0x3C, 4):u(0x3C, 4) + 4] == b"PE\0\0":
            header = u(0x3C, 4)
            count, optional = u(header + 6, 2), u(header + 20, 2)
            wide = u(header + 24, 2) == 0x20B
            image = u(header + 24 + 24, 8) if wide else u(header + 24 + 28, 4)
            table = header + 24 + optional
            for index in range(min(count, 96)):
                at = table + index * 40
                offset, size = u(at + 20, 4), u(at + 16, 4)
                found.append((offset, image + u(at + 12, 4), size))
                if u(at + 36, 4) & 0x20000000:
                    code.append((offset, min(offset + size, len(data))))
    except IndexError:
        pass
    return found, wide, code


def _stack_strings(data: bytes, pattern: re.Pattern[str]) -> list[tuple[str, str]]:
    """Strings a function builds in its stack frame from immediates and 16-byte constants:
    registers and the frame are tracked over each run of nearby moves (a gap of more than
    _GAP bytes ends it). Each frame is read as is and XORed with one byte."""
    if len(data) > MAX_SCAN:
        return []
    segments, wide, code = _segments(data)

    def at_va(address: int, size: int) -> bytes | None:
        for offset, va, length in segments:
            if va <= address and address + size <= va + length:
                return data[offset + address - va:offset + address - va + size]
        return None

    def to_va(offset: int) -> int | None:
        return next((va + offset - start for start, va, length in segments if start <= offset < start + length), None)

    pieces: list[tuple[int, bytes]] = []
    frames: dict[str, dict[int, int]] = {}
    regs: dict[tuple[str, int], bytes] = {}
    first = last = -1

    def flush() -> None:
        for frame in frames.values():
            if len(frame) >= 8 and max(frame) - min(frame) < 4096:
                low = min(frame)
                pieces.append((first, bytes(frame.get(at, 0) for at in range(low, max(frame) + 1))))
        frames.clear()
        regs.clear()

    for event in _events(data, code or [(0, len(data))]):
        at, end, kind = event[:3]
        if at - last > _GAP:
            flush()
            first = at
        last = end
        if kind == "imm":
            regs[("gpr", event[3])] = event[4]
        elif kind == "sse-load":
            # x86-64 [disp32] is relative to the next instruction; on x86 it is the address.
            here = to_va(end) if wide else 0
            address = None if here is None else (here + event[4]) & 0xFFFFFFFFFFFFFFFF
            value = None if address is None else at_va(address if wide else address & 0xFFFFFFFF, 16)
            if value is not None:
                regs[("xmm", event[3])] = value
        else:
            base, disp = event[3], event[4]
            if kind == "sse-store":
                value = regs.get(("xmm", event[5]))
            elif isinstance(event[5], bytes):
                value = event[5]
            else:
                reg, size = event[5]
                held = regs.get(("gpr", reg))
                value = None if held is None else (held + b"\0" * 8)[:size]
            if value is not None:
                frame = frames.setdefault(base, {})
                for offset, byte in enumerate(value):
                    frame[disp + offset] = byte
    flush()
    prefix = pattern.pattern.split("\\{", 1)[0].replace("\\", "").encode() + b"{"
    found = []
    for at, piece in pieces:
        found += _matches(piece.decode("latin-1"), pattern, f"stack string at 0x{at:x}")
        for key in range(1, 256):
            if bytes(b ^ key for b in prefix) in piece:
                text = bytes(b ^ key for b in piece).decode("latin-1")
                found += _matches(text, pattern, f"stack string at 0x{at:x}, xor 0x{key:02x}")
    return found


def _streams(data: bytes) -> list[tuple[int, bytes]]:
    """zlib streams in the file (PyInstaller packs each file so), inflated to MAX_SCAN bytes.

    Each header gets a 4 KiB probe, then a window of STREAM_WINDOW bytes: zlib keeps what
    it has not read as a copy, so the rest of a 43 MB file per chance header cost 17 s.
    The output cap (max_length) keeps a bomb harmless, as containers.decompress does."""
    found = []
    view = memoryview(data)
    for tried, match in enumerate(_ZLIB_HEADER.finditer(data)):
        if len(found) >= MAX_STREAMS or tried >= MAX_HEADERS:
            break
        start = match.start()
        try:
            if len(zlib.decompressobj().decompress(view[start:start + 4096], 64)) < 16:
                continue
            inner = zlib.decompressobj().decompress(view[start:start + STREAM_WINDOW], MAX_SCAN)
        except zlib.error:
            continue
        found.append((start, inner))
    return found


def _upx(data: bytes) -> bytes | None:
    """The sample unpacked by `upx -d` (decompression only; nothing runs), or None."""
    upx = shutil.which("upx")
    if not upx or b"UPX!" not in data[:4096] or len(data) > MAX_SCAN:
        return None
    with tempfile.TemporaryDirectory(prefix="static-re-") as folder:
        packed, plain = Path(folder, "packed"), Path(folder, "plain")
        packed.write_bytes(data)
        try:
            subprocess.run([upx, "-q", "-d", "-o", str(plain), str(packed)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
            return plain.read_bytes()
        except (OSError, subprocess.SubprocessError):
            return None


SOLVERS = (StaticFlagSolver(),)
