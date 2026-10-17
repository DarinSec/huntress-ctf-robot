"""Warmups lane: encoding strategies; explicit instructions or stated answers select them."""

from __future__ import annotations

import base64
import binascii
import codecs
import json
import re

from ..decoders import apply_chain, as_text, extract_answer, peel
from .base import MAX_TEXT_BYTES, AnswerCandidate, SolveContext, instruction_text

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
    """Decoded text, or only the answer it explicitly states.

    Returns None when the text is a further encoding layer that states an answer:
    the layered solver submits that answer, and a disagreeing candidate would block it.
    """
    try:
        text = value.decode("utf-8").strip("\r\n")
    except UnicodeDecodeError:
        return None
    if not text or any(not char.isprintable() and char not in "\t\r\n" for char in text):
        return None
    stated = extract_answer(text)
    if stated is not None:
        return stated
    if len(value) <= MAX_TEXT_BYTES and peel(value):
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


class LayeredDecodeSolver:
    """Peel stacked encodings (e.g. Morse -> hex -> text) until the text states its answer.

    The artifact is only data here: its decoded text yields one candidate for the single
    issued answer ID, and nothing else in it is followed.
    """

    name = "layered-decode"

    def solve(self, context: SolveContext) -> list[AnswerCandidate]:
        if len(context.answer_ids) != 1:
            return []
        sources = [("artifact", context.artifact)] + [
            (member.name, member.data) for member in context.members
        ]
        sources = [(name, data) for name, data in sources if len(data) <= MAX_TEXT_BYTES]
        proven = tuple((context.hint or {}).get("chain") or ())
        if proven:
            # A chain that already scored on this challenge: replay it, skip the search.
            for name, data in sources:
                replayed = apply_chain(data, proven)
                if replayed is not None:
                    return [self._candidate(context, name, proven, replayed[1])]
        found = []
        for name, data in sources:
            found.extend((name, chain, answer) for chain, _, answer in peel(data))
            text = as_text(data) if name != "artifact" else None
            stated = extract_answer(text) if text is not None else None
            if stated is not None and "{" in stated:
                # Unpacking the archive was the layer; only a flag-shaped value counts.
                found.append((name, ("unpack",), stated))
        if len({answer for _, _, answer in found}) != 1:
            return []
        name, chain, answer = found[0]
        return [self._candidate(context, name, chain, answer)]

    def _candidate(self, context, source, chain, answer) -> AnswerCandidate:
        return AnswerCandidate(
            context.answer_ids[0], answer, self.name,
            f"Decoded {source}: {' -> '.join(chain)} to text that explicitly states the answer.",
            tuple(chain),
        )


SOLVERS = (
    LayeredDecodeSolver(), Base64AnswerSolver(), CluedTextDecoderSolver(), JsonAnswerMapSolver(),
)
