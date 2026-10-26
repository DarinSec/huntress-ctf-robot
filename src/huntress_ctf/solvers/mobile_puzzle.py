"""Mobile Android: the answer code an app's assets/huntress_puzzle.json encodes.

Day 20 and 21 apps carry {"schema": "huntress.mobile.puzzle.v1", "codec": ..., "data": ...};
the backend answer code is the data decoded by the codec ("reverse" on day 21:
"FEDCBA9876543210-SNA" -> "ANS-0123456789ABCDEF", CORRECT live). Mastery bundles earlier
days' codecs: "split" puts parts[i] at position order[i], "reflection" carries the code
as is, "dynamic" names a payload DEX that holds it. Unknown codecs get the value as is,
reversed, and one strict layer from decoders.py.
Day 23 ("huntress.mobile.puzzle.v2", codec "analysis") carries no data: the code is computed
by the app's Java (Release.code), so dexvm.py emulates that bytecode (and a JNI long f(long)
from lib/x86_64) without running the app. A puzzle whose data decodes to nothing is tried the
same way, and as a last resort a code the app ships as text in any member is read.
Only a value that is exactly an answer code ("ANS-" + 16 uppercase hex) is returned.
"""

from __future__ import annotations

import base64
import binascii
import codecs
from io import BytesIO
import json
import re
import zipfile

from .. import dexvm, formats
from ..containers import ZIP_ERRORS, read_member
from ..decoders import LAYERS
from .base import AnswerCandidate, SolveContext, fits_format, question_items

ANSWER = re.compile(r"ANS-[0-9A-F]{16}")
_PACKAGE = re.compile(r"\bin package ([A-Za-z0-9_.]+)")
_IN_TEXT = re.compile(rb"ANS-[0-9A-F]{16}")
MAX_MEMBER_BYTES = 8 * 1024 * 1024  # A code is a string; whole libraries are not read.


def _split(puzzle: dict) -> set[str]:
    parts, order = puzzle.get("parts"), puzzle.get("order")
    if not (isinstance(parts, list) and isinstance(order, list) and sorted(order) == list(range(len(parts)))):
        return set()
    placed = [""] * len(parts)
    for part, position in zip(parts, order):
        placed[position] = str(part)
    return {"".join(placed), "".join(str(parts[index]) for index in order)}  # Both readings of "order".


def _decoded(codec: str, data: str, apk: zipfile.ZipFile, puzzle: dict) -> set[str]:
    codec = codec.lower()
    found: set[str] = set()
    if codec == "split":
        found |= _split(puzzle)
    elif codec in ("reflection", "plain", "none", "identity"):
        found.add(data)
    elif codec == "reverse":
        found.add(data[::-1])
    elif codec == "rot13":
        found.add(codecs.decode(data, "rot13"))
    elif codec in ("hex", "base16"):
        try:
            found.add(bytes.fromhex(data).decode("utf-8", "replace"))
        except ValueError:
            pass
    elif codec in ("base64", "b64"):
        try:
            found.add(base64.b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "replace"))
        except (binascii.Error, ValueError):
            pass
    elif codec == "base32":
        try:
            found.add(base64.b32decode(data + "=" * (-len(data) % 8)).decode("utf-8", "replace"))
        except (binascii.Error, ValueError):
            pass
    elif codec == "caesar" and isinstance(puzzle.get("key"), int):
        # Every character moved by key code points (day 7, key 15: "P]b<" -> "ANS-").
        for shift in (-puzzle["key"], puzzle["key"]):
            if all(0 <= ord(char) + shift < 0x110000 for char in data):
                found.add("".join(chr(ord(char) + shift) for char in data))
    elif codec == "xor" and isinstance(puzzle.get("key"), int):
        # Base64 of the code's bytes XORed with one key byte (days 4, 11 and 18).
        try:
            raw = base64.b64decode(data, validate=True)
        except (binascii.Error, ValueError):
            raw = b""
        found.add(bytes(byte ^ (puzzle["key"] & 0xFF) for byte in raw).decode("latin-1"))
    elif codec == "indexed":
        # data[i] belongs at position order[i] (day 17); both readings, as for "split".
        order = puzzle.get("order")
        if isinstance(order, list) and sorted(order) == list(range(len(data))):
            placed = [""] * len(data)
            for char, position in zip(data, order):
                placed[position] = char
            found |= {"".join(placed), "".join(data[index] for index in order)}
    elif codec == "dynamic" and data in apk.namelist():
        found.update(match.decode() for match in _IN_TEXT.findall(read_member(apk, data)))
    elif codec == "rot47":
        found.add(_rot47(data))
    elif codec == "atbash":
        found.add(_atbash(data))
    elif codec == "vigenere" and isinstance(puzzle.get("key"), str) and puzzle["key"].isalpha():
        found |= {_vigenere(data, puzzle["key"], sign) for sign in (-1, 1)}
    elif codec == "xor" and isinstance(puzzle.get("key"), str) and puzzle["key"]:
        # Repeating string key over Base64 or hex bytes (anticipated: days so far used one key byte).
        key = puzzle["key"].encode()
        for raw in _raw_bytes(data):
            found.add(bytes(byte ^ key[i % len(key)] for i, byte in enumerate(raw)).decode("latin-1"))
    elif codec == "base58":
        found.add(_base58(data))
    else:
        found |= _search(data) | _split(puzzle)
    return {value.strip() for value in found}


# --- Codecs no day has used yet, and a bounded search for unknown codec names --------------------
# Only a result that is exactly an answer code is ever kept, so trying more never invents one.

def _rot47(text: str) -> str:
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in text)


def _atbash(text: str) -> str:
    return "".join(chr(ord("Z") - ord(c) + ord("A")) if "A" <= c <= "Z" else
                   chr(ord("z") - ord(c) + ord("a")) if "a" <= c <= "z" else c for c in text)


def _vigenere(text: str, key: str, sign: int) -> str:
    out, index = [], 0
    for char in text:
        if char.isascii() and char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shift = ord(key[index % len(key)].upper()) - ord("A")
            out.append(chr((ord(char) - base + sign * shift) % 26 + base))
            index += 1
        else:
            out.append(char)
    return "".join(out)


_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58(text: str) -> str:
    if not text or any(c not in _BASE58 for c in text):
        return ""
    number = 0
    for char in text:
        number = number * 58 + _BASE58.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return (b"\0" * (len(text) - len(text.lstrip("1"))) + raw).decode("latin-1")


def _raw_bytes(text: str) -> list[bytes]:
    out = []
    try:
        out.append(base64.b64decode(text + "=" * (-len(text) % 4), validate=True))
    except (binascii.Error, ValueError):
        pass
    try:
        out.append(bytes.fromhex(text))
    except ValueError:
        pass
    return out


def _steps(text: str) -> set[str]:
    """One decoding step: every strict layer, plus the keyless text transforms."""
    out = {text[::-1], codecs.decode(text, "rot13"), _rot47(text), _atbash(text), _base58(text)}
    for _, layer in LAYERS:
        decoded = layer(text.encode())
        if decoded:
            out.add(decoded.decode("utf-8", "replace"))
    return {value for value in out if value and len(value) <= 4096}


def _search(data: str) -> set[str]:
    """Up to two steps, then every Caesar shift and single-byte XOR of the results' bytes."""
    seen = {data}
    frontier = {data}
    for _ in range(2):
        frontier = {value for text in frontier for value in _steps(text)} - seen
        seen |= frontier
    found = {value for value in seen if ANSWER.fullmatch(value.strip())}
    if found:
        return found
    for text in seen:
        if len(text) > 256:
            continue
        for shift in range(1, 26):
            moved = "".join(chr((ord(c) - 65 + shift) % 26 + 65) if "A" <= c <= "Z" else c for c in text)
            if ANSWER.fullmatch(moved):
                found.add(moved)
        for raw in _raw_bytes(text) + [text.encode("latin-1", "replace")]:
            for key in range(1, 256):
                candidate = bytes(byte ^ key for byte in raw)
                if _IN_TEXT.fullmatch(candidate):
                    found.add(candidate.decode())
    return found


def _in_app(apk: zipfile.ZipFile) -> set[str]:
    """Every answer code the app ships as text, for an asset that carries no payload.

    The last resort, after the asset's own data and the emulated code: where the app
    holds the code as a string (a DEX string, a resource, another asset) reading it is
    deterministic, and where the code has to be computed nothing matches, so the question
    stays unanswered rather than guessed. NUL bytes are dropped so a UTF-16LE string
    reads as text too.
    """
    found: set[str] = set()
    for item in apk.infolist():
        if item.is_dir() or item.file_size > MAX_MEMBER_BYTES:
            continue
        data = read_member(apk, item)
        found.update(match.decode() for match in _IN_TEXT.findall(data))
        if b"\0" in data:
            found.update(match.decode() for match in _IN_TEXT.findall(data.replace(b"\0", b"")))
    return found


def answer_code(apk_bytes: bytes) -> str | None:
    """The one answer code the APK's puzzle asset decodes to, or None."""
    try:
        with zipfile.ZipFile(BytesIO(apk_bytes)) as apk:
            names = [name for name in apk.namelist() if name.endswith("huntress_puzzle.json")]
            if len(names) != 1:
                return None
            puzzle = json.loads(read_member(apk, names[0]))
            if not isinstance(puzzle, dict):
                return None
            codes: set[str] = set()
            if isinstance(puzzle.get("data"), str):
                codes = {value for value in _decoded(str(puzzle.get("codec", "")), puzzle["data"], apk, puzzle)
                         if ANSWER.fullmatch(value)}
            literal = _in_app(apk) if not codes else set()  # Read while the zip is open.
    except (*ZIP_ERRORS, KeyError, UnicodeDecodeError):
        return None
    if not codes:
        manifest = formats.apk(apk_bytes) or {}
        computed = dexvm.answer_code(apk_bytes, manifest.get("package_name"))
        # A code the app merely ships as text counts only where nothing computed one, so
        # a literal left in another member can never contradict the emulated answer.
        codes = {computed} if computed else literal
    return codes.pop() if len(codes) == 1 else None


def _apks(context: SolveContext) -> dict[str, bytes]:
    """Every APK in the assignment by base name: the artifact itself, or its members."""
    found = {}
    if context.artifact.startswith(b"PK"):
        try:
            with zipfile.ZipFile(BytesIO(context.artifact)) as archive:
                if "AndroidManifest.xml" in archive.namelist():
                    found["artifact"] = context.artifact
        except ZIP_ERRORS:
            pass
    for member in context.members:
        if member.name.endswith(".apk"):
            found[re.sub(r"^delivery \d+:\s*", "", member.name.rsplit("/", 1)[-1])] = member.data
    return found


class MobilePuzzleSolver:
    name = "mobile-puzzle"
    lanes = frozenset({"mobile-android"})

    def solve(self, context: SolveContext) -> list[AnswerCandidate]:
        lane = context.challenge.get("lane") or context.challenge_id.split("-day-")[0]
        if lane not in self.lanes:
            return []
        apks = _apks(context)
        candidates = []
        for question in question_items(context):
            name = (question.artifact or "").rsplit("->", 1)[-1].strip().rsplit("/", 1)[-1]
            name = re.sub(r"^delivery \d+:\s*", "", name)
            blob = apks.get(name) or (apks.get("artifact") if len(apks) == 1 or name not in apks else None)
            if blob is None:
                continue
            # "For case ... in package <name>": never answer one app's question from another app
            # (a Mastery delivery that is missing must not borrow the first app's code).
            wanted = _PACKAGE.search(question.text)
            if wanted and (formats.apk(blob) or {}).get("package_name") != wanted[1]:
                continue
            code = answer_code(blob)
            if code and fits_format(code, question.answer_format):
                candidates.append(AnswerCandidate(
                    question.answer_id, code, self.name,
                    f"{name or 'the APK'}: assets/huntress_puzzle.json (or the code it names) gives this answer code.",
                ))
        return candidates


SOLVERS = (MobilePuzzleSolver(),)
