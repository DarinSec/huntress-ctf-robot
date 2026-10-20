"""Warmups lane: every question decodes its own blob; Mastery blobs are split messages.

Warmups is a cumulative encoding course. Day N adds one encoding, and a Mastery blob is
the answer sentence cut into numbered lines, each line encoded the way its day teaches:

    01<TAB>TmljZSA=                  Day 1 Base64          -> "Nice "
    02<TAB>jbex q                    Day 2 ROT13           -> "work d"
    12<TAB> rewsn                    Day 12 reversed       -> "nswer "
    19<TAB>fffe7400650072002d...     Day 19 hex of UTF-16  -> "ter-18"

Joining the decoded lines gives "... submit this exact answer to the Game Master: <slug>".
Edge spaces matter ("nswer " + "to"), so lines are decoded without stripping.

CURRICULUM was read from the Day 1-19 single solves: a line's chain is the chain that
decoded its day's whole blob. A later day is learned without code: once the robot scores
that day's single solve, the proven hint's chain is used for its Mastery lines.
"""

from __future__ import annotations

from itertools import product
from pathlib import PurePosixPath
import re

from ..decoders import LAYERS, decode_fragment, extract_answer, peel
from .base import AnswerCandidate, MAX_TEXT_BYTES, Question, SolveContext, fits_format, question_items

CURRICULUM: dict[int, tuple[str, ...]] = {
    1: ("base64",), 2: ("rot13",), 3: ("hex",), 4: ("binary",), 5: ("decimal",),
    6: ("octal",), 7: ("url",), 8: ("html",), 9: ("json",), 10: ("base32",),
    11: ("base64",), 12: ("reverse",), 13: ("atbash",), 14: ("caesar7",), 15: ("rot47",),
    16: ("morse", "hex"), 17: ("bacon", "hex"), 18: ("railfence3",), 19: ("hex",),
}
_LINE = re.compile(r"(\d{1,3})\t(.*)")
_SINGLE_ID = re.compile(r"warmups-day-(\d{1,2})(?:/time_trial)?")
_STRICT = tuple(name for name, _ in LAYERS)


def curriculum() -> dict[int, tuple[str, ...]]:
    """Known day chains, plus later days learned from proven warmups single-solve hints."""
    from ..hints import load_hints  # Lazy: hints imports this package.

    chains = dict(CURRICULUM)
    for challenge_id, hint in load_hints().items():
        match = _SINGLE_ID.fullmatch(challenge_id)
        chain = tuple(hint.get("chain") or ()) if isinstance(hint, dict) else ()
        if match and chain and int(match[1]) not in chains:
            chains[int(match[1])] = chain
    return chains


def _guess_fragment(payload: str) -> str | None:
    """A line from an unknown day: the one printable decoding by strict chains of <= 2 steps.

    Text ciphers (ROT, Atbash, reversal) fit any text, so they are never guessed here.
    """
    found = {
        piece for chain in (*((name,) for name in _STRICT), *product(_STRICT, repeat=2))
        if (piece := decode_fragment(payload, chain)) is not None
    }
    return found.pop() if len(found) == 1 else None


def split_message(text: str, chains: dict[int, tuple[str, ...]]) -> str | None:
    """The sentence a numbered-lines blob encodes, or None if any line does not decode."""
    pieces = []
    for line in text.splitlines():
        if not line.strip():
            continue
        match = _LINE.fullmatch(line)
        if not match:
            return None
        index, payload = int(match[1]), match[2]
        chain = chains.get(index)
        piece = decode_fragment(payload, chain) if chain else _guess_fragment(payload)
        if piece is None:
            return None
        pieces.append((index, piece))
    if not pieces:
        return None
    return "".join(piece for _, piece in sorted(pieces, key=lambda item: item[0]))


class WarmupBlobSolver:
    name = "warmup-blobs"

    def solve(self, context: SolveContext) -> list[AnswerCandidate]:
        lane = context.challenge.get("lane") or context.challenge_id.split("-day-")[0]
        if lane != "warmups":
            return []
        items = question_items(context)
        if not items:
            return []
        blobs = self._blobs(context)
        chains = curriculum()
        candidates = []
        for question in items:
            blob = self._blob_for(context, question, blobs)
            if blob is None or len(blob) > MAX_TEXT_BYTES:
                continue
            answer, evidence = self._decode(blob, chains)
            if answer and fits_format(answer, question.answer_format):
                candidates.append(AnswerCandidate(question.answer_id, answer, self.name, evidence))
        return candidates

    @staticmethod
    def _blobs(context: SolveContext) -> dict[str, bytes]:
        named = {member.name: member.data for member in context.members}
        basenames: dict[str, list[bytes]] = {}
        for member in context.members:
            basenames.setdefault(PurePosixPath(member.name).name, []).append(member.data)
        for name, datas in basenames.items():
            if len(datas) == 1:
                named.setdefault(name, datas[0])
        return named

    @staticmethod
    def _blob_for(context: SolveContext, question: Question, blobs: dict[str, bytes]) -> bytes | None:
        if question.artifact in blobs:
            return blobs[question.artifact]
        # A Time Trial's one question is about the assigned artifact itself.
        if not context.members and len(context.answer_ids) == 1:
            return context.artifact
        return None

    @staticmethod
    def _decode(blob: bytes, chains: dict[int, tuple[str, ...]]) -> tuple[str | None, str]:
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError:
            return None, ""
        if _LINE.match(text.lstrip("\r\n")):
            message = split_message(text, chains)
            answer = extract_answer(message) if message else None
            return answer, "Each numbered line decoded with its day's chain; the joined sentence states the answer."
        answers = {answer for _, _, answer in peel(blob)}
        if len(answers) == 1:
            return answers.pop(), "The blob decodes to text that states exactly one answer."
        return None, ""


SOLVERS = (WarmupBlobSolver(),)
