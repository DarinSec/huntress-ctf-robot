"""Mobile Android: the answer code an app's assets/huntress_puzzle.json encodes.

Day 20 and 21 apps carry {"schema": "huntress.mobile.puzzle.v1", "codec": ..., "data": ...};
the backend answer code is the data decoded by the codec ("reverse" on day 21:
"FEDCBA9876543210-SNA" -> "ANS-0123456789ABCDEF", CORRECT live). "dynamic" names a
payload DEX that holds the code. Unknown codecs get one strict layer from decoders.py.
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


def _decoded(codec: str, data: str, apk: zipfile.ZipFile) -> set[str]:
    codec = codec.lower()
    found: set[str] = set()
    if codec == "reverse":
        found.add(data[::-1])
    elif codec in ("plain", "none", "identity"):
        found.add(data)
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
    elif codec == "dynamic" and data in apk.namelist():
        found.update(match.decode() for match in _IN_TEXT.findall(apk.read(data)))
    else:
        for _, layer in LAYERS:
            decoded = layer(data.encode())
            if decoded:
                found.add(decoded.decode("utf-8", "replace"))
        found.add(data[::-1])
    return {value.strip() for value in found}


def answer_code(apk_bytes: bytes) -> str | None:
    """The one answer code the APK's puzzle asset decodes to, or None."""
    try:
        with zipfile.ZipFile(BytesIO(apk_bytes)) as apk:
            names = [name for name in apk.namelist() if name.endswith("huntress_puzzle.json")]
            if len(names) != 1:
                return None
            puzzle = json.loads(apk.read(names[0]))
            if not isinstance(puzzle, dict) or not isinstance(puzzle.get("data"), str):
                return None
            codes = {value for value in _decoded(str(puzzle.get("codec", "")), puzzle["data"], apk)
                     if ANSWER.fullmatch(value)}
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
