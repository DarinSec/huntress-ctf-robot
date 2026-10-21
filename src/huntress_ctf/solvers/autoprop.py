"""Metadata Forensics: a new "Determine <property>" answered without a human, when it is clear.

A new property was the team's slowest flag (days 15, 16, 20), and it is often another
header field of an executable format, which formats.py already reads. For a property
that no parser in metadata.PROPERTIES knows:

- Single Solve (untimed, one question): when suggest.confident() finds one field that is
  clearly the property, answer it once. The candidate's chain records the mapping
  ("autoprop", "<property>=<format>:<field>"); a CORRECT single solve stores it in
  hints.json like any proven chain.
- Time Trial and Mastery (and later days): only mappings a CORRECT single solve confirmed.

A wrong guess costs one rejected untimed answer, teaches nothing, and leaves the property
to the AI. Once a parser for the property is added to PROPERTIES, this solver stays out.
"""

from __future__ import annotations

import re

from ..formats import describe
from ..suggest import confident, formatted
from .base import AnswerCandidate, SolveContext, fits_format, question_items
from .metadata import PROPERTIES, Files

_PROPERTY = re.compile(r"Determine ([a-z0-9_.]+) for ")
_MAPPING = re.compile(r"([a-z0-9_.]+)=([a-z_]+):([A-Za-z0-9_]+)")


def confirmed_mappings() -> dict[str, tuple[str, str]]:
    """property -> (format, field) from every proven autoprop chain in hints.json."""
    from ..hints import load_hints  # Lazy, like warmups.curriculum().

    found: dict[str, tuple[str, str]] = {}
    for hint in load_hints().values():
        chain = hint.get("chain") if isinstance(hint, dict) else None
        if isinstance(chain, list) and chain[:1] == ["autoprop"]:
            for item in chain[1:]:
                match = _MAPPING.fullmatch(str(item))
                if match:
                    found[match[1]] = (match[2], match[3])
    return found


def _field(data: bytes, label: str, key: str):
    for found_label, fields in describe(data):
        if found_label.split()[0] == label and key in fields:
            return fields[key]
    return None


class AutoPropertySolver:
    name = "metadata-autoprop"
    lanes = frozenset({"metadata-forensics"})

    def solve(self, context: SolveContext) -> list[AnswerCandidate]:
        lane = context.challenge.get("lane") or context.challenge_id.split("-day-")[0]
        if lane not in self.lanes:
            return []
        items = [
            (question, match[1]) for question in question_items(context)
            if question.artifact and (match := _PROPERTY.search(question.text)) and match[1] not in PROPERTIES
        ]
        if not items:
            return []
        single = "/" not in context.challenge_id
        known = confirmed_mappings()
        files = Files(context)
        candidates = []
        for question, prop in items:
            _, data = files.resolve(question.artifact)
            if data is None:
                continue
            if prop in known:
                label, key = known[prop]
                value = _field(data, label, key)
                if value is None:
                    continue
                answer = formatted(prop, value)
                evidence = f"{prop} = {label} field {key}, a mapping a CORRECT single solve confirmed."
            elif single:
                guess = confident(prop, data)
                if guess is None:
                    continue
                label, key, answer = guess
                evidence = f"{prop} has no parser; {label} field {key} matches it clearly (suggest.py)."
            else:
                continue
            if fits_format(answer, question.answer_format):
                candidates.append(AnswerCandidate(
                    question.answer_id, answer, self.name, evidence,
                    ("autoprop", f"{prop}={label}:{key}"),
                ))
        return candidates


SOLVERS = (AutoPropertySolver(),)
