"""Shared solver types; every lane module builds on these."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
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


@dataclass(frozen=True)
class AnswerCandidate:
    answer_id: str
    answer: str
    solver: str
    evidence: str
    chain: tuple[str, ...] = ()


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
