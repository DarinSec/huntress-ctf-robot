"""Small deterministic strategies; only explicit assignment instructions select them."""

from __future__ import annotations

import base64
import binascii
import codecs
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Protocol

from .state import current_fields

MAX_TEXT_BYTES = 1024 * 1024


@dataclass(frozen=True)
class SolveContext:
    challenge_id: str
    challenge: dict[str, Any]
    attempt: dict[str, Any]
    artifact: bytes
    artifact_path: Path
    answer_ids: tuple[str, ...]


@dataclass(frozen=True)
class AnswerCandidate:
    answer_id: str
    answer: str
    solver: str
    evidence: str


class Solver(Protocol):
    name: str

    def solve(self, context: SolveContext) -> list[AnswerCandidate]: ...


def instruction_text(context: SolveContext) -> str:
    """Do not treat status, filenames, hashes, artifact text, or examples as clues."""
    fields = ("description", "instructions", "prompt", "question", "text")
    parts: list[str] = []
    for source in (context.challenge, current_fields(context.attempt)):
        parts.extend(source[key] for key in fields if isinstance(source.get(key), str))
        questions = source.get("questions")
        if isinstance(questions, list):
            for question in questions:
                if isinstance(question, dict):
                    parts.extend(
                        question[key] for key in fields
                        if isinstance(question.get(key), str)
                    )
    return "\n".join(parts)


_ENCODINGS = {
    "base64": re.compile(r"\bbase[\s-]*64\b", re.I),
    "rot13": re.compile(r"\brot[\s-]*13\b", re.I),
    "hex": re.compile(r"\bhex(?:adecimal)?\b", re.I),
    "binary": re.compile(r"\b(?:8[\s-]*bit\s+)?binary\b", re.I),
}
_ACTION = re.compile(r"\b(?:decod(?:e|ed|ing)|convert|translate|plaintext)\b|plain text", re.I)
_OTHER_TASK = re.compile(
    r"\b(?:hash|digest|md5|sha[\s-]*\d+|count|length|how many|number of|"
    r"re[\s-]*encode|do not|don't|not|instead)\b", re.I,
)


def encoding_clue(context: SolveContext) -> str | None:
    if len(context.answer_ids) != 1 or len(context.artifact) > MAX_TEXT_BYTES:
        return None
    text = instruction_text(context)
    choices = [name for name, pattern in _ENCODINGS.items() if pattern.search(text)]
    if len(choices) != 1 or not _ACTION.search(text) or _OTHER_TASK.search(text):
        return None
    return choices[0]


def answer_text(value: bytes) -> str | None:
    try:
        text = value.decode("utf-8").strip("\r\n")
    except UnicodeDecodeError:
        return None
    if not text or any(not char.isprintable() and char not in "\t\r\n" for char in text):
        return None
    return text


class Base64AnswerSolver:
    name = "base64-answer"

    def solve(self, context: SolveContext) -> list[AnswerCandidate]:
        if encoding_clue(context) != "base64":
            return []
        encoded = re.sub(rb"[ \t\r\n]", b"", context.artifact)
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            return []
        if base64.b64encode(decoded) != encoded:
            return []
        answer = answer_text(decoded)
        if answer is None:
            return []
        return [AnswerCandidate(
            context.answer_ids[0], answer, self.name,
            "Explicit Base64 decoding task; canonical Base64 produces printable UTF-8.",
        )]


class CluedTextDecoderSolver:
    name = "clued-text-decoder"

    def solve(self, context: SolveContext) -> list[AnswerCandidate]:
        method = encoding_clue(context)
        if method not in {"rot13", "hex", "binary"}:
            return []
        try:
            source = context.artifact.decode("utf-8").strip("\r\n")
            if method == "rot13":
                decoded = codecs.decode(source, "rot_13").encode("utf-8")
            elif method == "hex":
                decoded = bytes.fromhex(source)
            else:
                bits = re.sub(r"[ \t\r\n]", "", source)
                if not bits or len(bits) % 8 or not re.fullmatch(r"[01]+", bits):
                    return []
                decoded = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
        except (UnicodeError, ValueError):
            return []
        answer = answer_text(decoded)
        if answer is None:
            return []
        return [AnswerCandidate(
            context.answer_ids[0], answer, self.name,
            f"Explicit {method} decoding task; the assigned bytes produce printable UTF-8.",
        )]


def _unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Ambiguous duplicate JSON key")
        obj[key] = value
    return obj


class JsonAnswerMapSolver:
    name = "json-answer-map"

    def solve(self, context: SolveContext) -> list[AnswerCandidate]:
        text = instruction_text(context)
        # Matching IDs alone are not evidence that the values are answers.
        if (
            len(context.artifact) > MAX_TEXT_BYTES
            or not re.search(r"\bJSON\b", text, re.I)
            or not re.search(r"\banswer(?:s)?\s+map(?:ping)?\b", text, re.I)
            or not re.search(r"\b(?:submit|read|use)\b", text, re.I)
            or _OTHER_TASK.search(text)
        ):
            return []
        try:
            payload = json.loads(context.artifact, object_pairs_hook=_unique_object)
        except (ValueError, UnicodeDecodeError, RecursionError):
            return []
        mapping = payload.get("answers", payload) if isinstance(payload, dict) else payload
        if isinstance(mapping, dict):
            items = list(mapping.items())
        elif isinstance(mapping, list):
            items = [
                (entry.get("answer_id"), entry.get("answer"))
                for entry in mapping if isinstance(entry, dict)
            ]
        else:
            return []
        candidates = []
        for answer_id, value in items:
            if (
                answer_id in context.answer_ids
                and type(value) in (str, int)
                and str(value)
            ):
                candidates.append(AnswerCandidate(
                    answer_id, str(value), self.name,
                    "The assignment explicitly requests a JSON answer map; the key is an issued answer ID.",
                ))
        return candidates


SOLVERS: tuple[Solver, ...] = (
    Base64AnswerSolver(), CluedTextDecoderSolver(), JsonAnswerMapSolver(),
)
