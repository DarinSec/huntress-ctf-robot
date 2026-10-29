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
decoded its day's whole blob. Days 20-27 come from the Day 27 Mastery's 133 blobs: a fresh
Homebase has no hints.json to learn them from, and guessing failed every blob there (Day 25's
U+ line also reads as unicode/base64 noise). Days 28 and 29 come from their single solves.
A later day is learned without code: once the robot scores that day's single solve, the
proven hint's chain is used for its Mastery lines. Until then its line is guessed, and
several readings are settled by the warmup sentence.

Days 28 and 29 put an earlier day's text cipher first (reversed hex; "Sixty-four invited
thirteen over": ROT13, then Base64), where peel only tries one last. So an unknown day's
single blob also tries each text cipher first, and a line no strict chain reads tries the
course's text ciphers before one strict layer.
"""

from __future__ import annotations

from itertools import product
from pathlib import PurePosixPath
import re

from ..decoders import ANTICIPATED, FINAL_STEPS, LAYERS, WEAK_STEPS, decode_fragment, extract_answer, peel
from .base import AnswerCandidate, MAX_TEXT_BYTES, Question, SolveContext, fits_format, question_items

CURRICULUM: dict[int, tuple[str, ...]] = {
    1: ("base64",), 2: ("rot13",), 3: ("hex",), 4: ("binary",), 5: ("decimal",),
    6: ("octal",), 7: ("url",), 8: ("html",), 9: ("json",), 10: ("base32",),
    11: ("base64",), 12: ("reverse",), 13: ("atbash",), 14: ("caesar7",), 15: ("rot47",),
    16: ("morse", "hex"), 17: ("bacon", "hex"), 18: ("railfence3",), 19: ("hex",),
    20: ("hex",), 21: ("base64", "zlib"), 22: ("base64", "zlib"), 23: ("ascii85",),
    24: ("runlength",), 25: ("unicode",), 26: ("brainfuck",), 27: ("brainfuck",),
    28: ("reverse", "hex"), 29: ("rot13", "base64"),
}
# The sentence every warmup states; it picks the one reading when guessed lines have several.
SENTENCE = re.compile(r"Nice work decoding this warmup! To solve, submit this exact answer to the "
                      r"Game Master: [a-z0-9]+(?:-[a-z0-9]+)*")
MAX_READINGS = 256  # Combinations of guessed lines tried against SENTENCE.
_LINE = re.compile(r"(\d{1,3})\t(.*)")
_SINGLE_ID = re.compile(r"warmups-day-(\d{1,2})(?:/time_trial)?")
_STRICT = tuple(name for name, _ in LAYERS)
# Formats no day has used yet are guessed alone, not paired: 26 layers paired would double the cost.
_PAIRED = tuple(name for name in _STRICT if name not in ANTICIPATED)
# The course's own text ciphers (days 2, 12-15, 18), tried before one strict layer on a line
# no strict chain reads: days 28 and 29 each paired one of them with an earlier encoding.
_COURSE_TEXT = ("rot13", "reverse", "atbash", "caesar7", "rot47", "railfence3")
_FIRST_STEPS = (*FINAL_STEPS, *WEAK_STEPS)  # A single blob is settled by its whole sentence.


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


def _guesses(payload: str) -> set[str]:
    """A line from an unknown day: its printable decodings by strict chains of <= 2 steps.

    Text ciphers (ROT, Atbash, reversal) fit any text, so they are never guessed here.
    """
    return {
        piece for chain in (*((name,) for name in _STRICT), *product(_PAIRED, repeat=2))
        if (piece := decode_fragment(payload, chain)) is not None
    }


def _text_first(payload: str) -> set[str]:
    """A line no strict chain reads: a course text cipher, then one strict layer (Day 29's shape)."""
    return {
        piece for chain in product(_COURSE_TEXT, _PAIRED)
        if (piece := decode_fragment(payload, chain)) is not None
    }


def _guess_fragment(payload: str) -> str | None:
    """The one printable decoding of a line from an unknown day, else None."""
    found = _guesses(payload)
    return found.pop() if len(found) == 1 else None


def split_message(text: str, chains: dict[int, tuple[str, ...]]) -> str | None:
    """The sentence a numbered-lines blob encodes, or None if any line does not decode.

    A guessed line with several readings is settled by SENTENCE: exactly one combination of
    the readings must make the whole blob read as the warmup sentence.
    """
    pieces = []
    for line in text.splitlines():
        if not line.strip():
            continue
        match = _LINE.fullmatch(line)
        if not match:
            return None
        index, payload = int(match[1]), match[2]
        chain = chains.get(index)
        if chain:
            piece = decode_fragment(payload, chain)
            readings = (piece,) if piece is not None else ()
        else:
            readings = tuple(sorted(_guesses(payload) or _text_first(payload)))
        if not readings:
            return None
        pieces.append((index, readings))
    if not pieces:
        return None
    ordered = [readings for _, readings in sorted(pieces, key=lambda item: item[0])]
    combinations = 1
    for readings in ordered:
        combinations *= len(readings)
    if combinations == 1:
        return "".join(readings[0] for readings in ordered)
    if combinations > MAX_READINGS:
        return None
    fits = {message for message in map("".join, product(*ordered)) if SENTENCE.fullmatch(message.strip())}
    return fits.pop() if len(fits) == 1 else None


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
        single = _SINGLE_ID.fullmatch(context.challenge_id)
        day_chain = chains.get(int(single[1]), ()) if single else ()
        candidates = []
        for question in items:
            blob = self._blob_for(context, question, blobs)
            if blob is None or len(blob) > MAX_TEXT_BYTES:
                continue
            answer, evidence, chain = self._decode(blob, chains, day_chain)
            if answer and fits_format(answer, question.answer_format):
                # The chain becomes the day's proven hint, so its Mastery line is no longer guessed.
                candidates.append(AnswerCandidate(question.answer_id, answer, self.name, evidence, chain))
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
    def _decode(blob: bytes, chains: dict[int, tuple[str, ...]],
                day_chain: tuple[str, ...] = ()) -> tuple[str | None, str, tuple[str, ...]]:
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError:
            return None, "", ()
        if _LINE.match(text.lstrip("\r\n")):
            message = split_message(text, chains)
            answer = extract_answer(message) if message else None
            return answer, "Each numbered line decoded with its day's chain; the joined sentence states the answer.", ()
        found = {answer: chain for chain, _, answer in peel(blob)}
        if len(found) == 1:
            answer, chain = found.popitem()
            return answer, "The blob decodes to text that states exactly one answer.", chain
        # Peel never guesses text ciphers (reversal, ROT): Day 28's reversed hex needs the day's chain.
        message = decode_fragment(text.strip(), day_chain) if day_chain else None
        answer = extract_answer(message) if message else None
        if answer:
            return answer, "The blob decodes with its day's chain to text that states the answer.", day_chain
        if found or day_chain:
            return None, "", ()
        # An unknown day: each text cipher first, then peel. Only one stated answer counts.
        first: dict[str, tuple[str, ...]] = {}
        for name, step in _FIRST_STEPS:
            rotated = step(text.strip())
            if rotated:
                for chain, _, stated in peel(rotated.encode()):
                    first.setdefault(stated, (name, *chain))
        if len(first) == 1:
            answer, chain = first.popitem()
            return answer, f"The blob decodes by {' -> '.join(chain)} to text that states exactly one answer.", chain
        return None, "", ()


SOLVERS = (WarmupBlobSolver(),)
