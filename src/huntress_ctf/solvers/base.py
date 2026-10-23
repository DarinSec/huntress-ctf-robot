"""Shared solver types; every lane module builds on these."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, Mapping, Protocol

from ..containers import Member
from ..state import current_fields

MAX_TEXT_BYTES = 1024 * 1024


@dataclass(frozen=True)
class SolveContext:
    """During a timed run artifact_path is written only after submission; read `artifact`.

    `members` are the files unpacked in memory from a container artifact. `hint` is the
    proven solver record for this challenge (see hints.py), or None.
    """

    challenge_id: str
    challenge: dict[str, Any]
    attempt: dict[str, Any]
    artifact: bytes
    artifact_path: Path
    answer_ids: tuple[str, ...]
    members: tuple[Member, ...] = ()
    hint: Mapping[str, Any] | None = None
    # One slot for the parsed question list, shared by every solver of one run. The
    # context is frozen, so the list it holds is the only mutable part.
    cache: list[list[Any]] = field(default_factory=list, repr=False, compare=False)


@dataclass(frozen=True)
class AnswerCandidate:
    answer_id: str
    answer: str
    solver: str
    evidence: str
    chain: tuple[str, ...] = ()
    # Other spellings of the same evidence, best first, where the accepted one is the
    # grader's choice rather than the bytes' (a machine field as a label, a decimal or a
    # hex code). `answer` is the only one a race ever sends; `learn` offers these, one
    # request each, to an answer the service has just rejected.
    alternatives: tuple[str, ...] = ()


class Solver(Protocol):
    name: str

    def solve(self, context: SolveContext) -> list[AnswerCandidate]: ...


TEXT_FIELDS = ("description", "instructions", "prompt", "question", "text")


def questions(context: SolveContext) -> list[tuple[str, str]]:
    """(answer_id, question text) pairs when the service ties questions to answer IDs."""
    pairs: dict[str, str] = {}
    for source in (context.challenge, current_fields(context.attempt)):
        items = source.get("questions")
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            answer_id = item.get("answer_id", item.get("id"))
            text = " ".join(item[key] for key in TEXT_FIELDS if isinstance(item.get(key), str))
            if answer_id in context.answer_ids and text:
                pairs[answer_id] = text
    return list(pairs.items())


@dataclass(frozen=True)
class Question:
    answer_id: str
    text: str
    artifact: str | None  # The file this question is about, e.g. "blob-03.txt"
    answer_format: Mapping[str, Any]
    group: Any = None  # The live `set`: questions about one subject share it.


def question_items(context: SolveContext) -> list[Question]:
    """Issued questions with the artifact each names and its answer format.

    Live shape: questions[{id, question, artifact, answer_format{kind, syntax|...}}].

    Every lane's solver starts here, and a Mastery assignment issues thousands of
    questions, so the result is built once per context and read from `cache` after that:
    on a 9,310-question corpus the first call is ~70 ms and the rest are free (before,
    each call scanned the answer_ids tuple per question - 365 ms, paid by every solver).
    """
    if context.cache:
        return list(context.cache[0])
    issued = frozenset(context.answer_ids)
    items: dict[str, Question] = {}
    for source in (context.challenge, current_fields(context.attempt)):
        for item in source.get("questions") or ():
            if not isinstance(item, dict):
                continue
            answer_id = item.get("answer_id", item.get("id"))
            if answer_id not in issued:
                continue
            text = " ".join(item[key] for key in TEXT_FIELDS if isinstance(item.get(key), str))
            artifact = item.get("artifact")
            answer_format = item.get("answer_format")
            items[answer_id] = Question(
                answer_id, text, artifact if isinstance(artifact, str) else None,
                answer_format if isinstance(answer_format, dict) else {}, item.get("set"),
            )
    questions = list(items.values())
    context.cache.append(questions)  # The one-slot memo of a frozen context.
    return list(questions)


# Answer-format syntaxes seen live, as the patterns they describe.
_SYNTAX_PATTERNS = {
    "three lowercase words separated by hyphens, followed by a hyphen and a two-digit number":
        r"[a-z]+-[a-z]+-[a-z]+-\d{2}",
}


def fits_format(answer: str, answer_format: Mapping[str, Any]) -> bool:
    """False only when a known pattern syntax rules the answer out; unknown ones pass."""
    syntax = answer_format.get("syntax")
    if answer_format.get("kind") != "pattern" or not isinstance(syntax, str):
        return True
    for description, pattern in _SYNTAX_PATTERNS.items():
        if syntax.casefold().startswith(description):
            return re.fullmatch(pattern, answer) is not None
    return True


def instruction_text(context: SolveContext) -> str:
    """Do not treat status, filenames, hashes, artifact text, or examples as clues."""
    fields = TEXT_FIELDS
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
