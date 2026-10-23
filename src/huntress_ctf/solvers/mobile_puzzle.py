"""Mobile Android: the answer code an app's assets/huntress_puzzle.json encodes.

Day 20 and 21 apps carry {"schema": "huntress.mobile.puzzle.v1", "codec": ..., "data": ...};
the backend answer code is the data decoded by the codec ("reverse" on day 21:
"FEDCBA9876543210-SNA" -> "ANS-0123456789ABCDEF", CORRECT live). Mastery bundles earlier
days' codecs: "split" puts parts[i] at position order[i], "reflection" carries the code
as is, "dynamic" names a payload DEX that holds it. Unknown codecs get the value as is,
reversed, and one strict layer from decoders.py. An asset with no payload at all (day
23's {"schema": "...v2", "codec": "analysis"}) falls back to the codes the app ships as
text in any member.
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

from ..decoders import LAYERS
from .base import AnswerCandidate, SolveContext, fits_format, question_items

ANSWER = re.compile(r"ANS-[0-9A-F]{16}")
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
        found.update(match.decode() for match in _IN_TEXT.findall(apk.read(data)))
    else:
        for _, layer in LAYERS:
            decoded = layer(data.encode())
            if decoded:
                found.add(decoded.decode("utf-8", "replace"))
        found |= {data, data[::-1]} | _split(puzzle)
    return {value.strip() for value in found}


def _in_app(apk: zipfile.ZipFile) -> set[str]:
    """Every answer code the app ships as text, for an asset that carries no payload.

    Day 23's asset declares {"schema": "...v2", "codec": "analysis"} and no data, so the
    code is not in it. Where the app still holds one (a DEX string, a resource, another
    asset), reading it is deterministic; where the code has to be computed, nothing
    matches and the question stays unanswered rather than guessed. NUL bytes are dropped
    so a UTF-16LE string reads as text too.
    """
    found: set[str] = set()
    for item in apk.infolist():
        if item.is_dir() or item.file_size > MAX_MEMBER_BYTES:
            continue
        data = apk.read(item)
        found.update(match.decode() for match in _IN_TEXT.findall(data))
        if b"\0" in data:
            found.update(match.decode() for match in _IN_TEXT.findall(data.replace(b"\0", b"")))
    return found


def answer_code(apk_bytes: bytes) -> str | None:
    """The one answer code the APK's puzzle asset decodes to, or None."""
    try:
        with zipfile.ZipFile(BytesIO(apk_bytes)) as apk:
            names = [name for name in apk.namelist() if name.endswith("huntress_puzzle.json")]
            codes: set[str] = set()
            if len(names) == 1:
                puzzle = json.loads(apk.read(names[0]))
                if isinstance(puzzle, dict) and isinstance(puzzle.get("data"), str):
                    codes = {value for value in _decoded(str(puzzle.get("codec", "")), puzzle["data"], apk, puzzle)
                             if ANSWER.fullmatch(value)}
            if not codes and names:
                codes = _in_app(apk)
    except (zipfile.BadZipFile, ValueError, KeyError, UnicodeDecodeError):
        return None
    return codes.pop() if len(codes) == 1 else None


def _apks(context: SolveContext) -> dict[str, bytes]:
    """Every APK in the assignment by base name: the artifact itself, or its members."""
    found = {}
    if context.artifact.startswith(b"PK"):
        try:
            with zipfile.ZipFile(BytesIO(context.artifact)) as archive:
                if "AndroidManifest.xml" in archive.namelist():
                    found["artifact"] = context.artifact
        except zipfile.BadZipFile:
            pass
    for member in context.members:
        if member.name.endswith(".apk"):
            found[member.name.rsplit("/", 1)[-1]] = member.data
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
            blob = apks.get(name) or (apks.get("artifact") if len(apks) == 1 or name not in apks else None)
            if blob is None:
                continue
            code = answer_code(blob)
            if code and fits_format(code, question.answer_format):
                candidates.append(AnswerCandidate(
                    question.answer_id, code, self.name,
                    f"{name or 'the APK'}: assets/huntress_puzzle.json decodes to this answer code.",
                ))
        return candidates


SOLVERS = (MobilePuzzleSolver(),)
