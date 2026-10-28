"""Metadata Forensics: a new "Determine <property>" answered without a human, when it is clear.

A new property was the team's slowest flag (days 15, 16, 20), and it is often another
header field of an executable format, which formats.py already reads. For a property
that no parser knows (metadata.property_parser: PROPERTIES, or a disk.* field):

- Single Solve (untimed, one question): when suggest.confident() finds one field that is
  clearly the property, answer it once. The candidate's chain records the mapping
  ("autoprop", "<property>=<format>:<field>"); a CORRECT single solve stores it in
  hints.json like any proven chain.
- Untimed Time Trial and Mastery: the same clear guess. A teammate often takes the Single
  Solve by hand, so no mapping gets confirmed and the routes stayed open (Day 23
  sqlite.page_size_bytes). An untimed "incorrect" is resent kind by kind, so a wrong guess
  costs only its own kind.
- Untimed and still not clear: the best-ranked field anyway, with the next few as
  `alternatives` (one request each after a rejection). Day 25's registry.hive_root_name
  ranked root_key_name first at score 1 ("hive" is no word of the field), so no clear
  guess was made: the Single Solve never scored and its Time Trial and Mastery stayed
  locked until a human took them. An untimed wrong guess costs nothing; silence cost a lane.
- Timed races (and later days): only mappings a CORRECT single solve confirmed.

Once a parser for the property is added to PROPERTIES, this solver stays out (Day 28: autoprop
answered disk.partition_start_lba_sequence from the protective MBR, and it was refused).
"""

from __future__ import annotations

import re

from ..formats import describe
from ..state import GameMasterError, current_fields
from ..suggest import confident, formatted, ranked
from .base import AnswerCandidate, SolveContext, fits_format, question_items
from .metadata import Files, _orderings, property_parser

_PROPERTY = re.compile(r"Determine ([a-z0-9_.]+) for ")
_MAPPING = re.compile(r"([a-z0-9_.]+)=([a-z_]+):([A-Za-z0-9_]+)")
# How many ranked fields an untimed, unclear guess offers in all (answer + alternatives).
UNCLEAR_TRIES = 4


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
            if question.artifact and (match := _PROPERTY.search(question.text)) and property_parser(match[1]) is None
        ]
        if not items:
            return []
        try:
            fields = current_fields(context.attempt)
        except GameMasterError:
            fields = {}
        timed = bool(fields.get("run_for_time") or fields.get("deadline"))
        may_guess = "/" not in context.challenge_id or not timed
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
            elif may_guess:
                guess = confident(prop, data)
                if guess is None:
                    unclear = self._unclear(prop, data, question.answer_format)
                    if unclear:
                        candidates.append(unclear(question.answer_id))
                    continue
                label, key, answer = guess
                evidence = f"{prop} has no parser; {label} field {key} matches it clearly (suggest.py)."
            else:
                continue
            if fits_format(answer, question.answer_format):
                # A list's order is the grader's choice, as for the parsers: sorted and basenames, untimed.
                candidates.append(AnswerCandidate(
                    question.answer_id, answer, self.name, evidence,
                    ("autoprop", f"{prop}={label}:{key}"), _orderings(answer, question),
                ))
        return candidates


    def _unclear(self, prop: str, data: bytes, answer_format):
        """Untimed only: the best-ranked fields that fit the format, best first, as one candidate."""
        tries, seen = [], set()
        for _, label, key, value in ranked(prop, data):
            answer = formatted(prop, value)
            if answer in seen or not fits_format(answer, answer_format):
                continue
            seen.add(answer)
            tries.append((label.split()[0], key, answer))
            if len(tries) == UNCLEAR_TRIES:
                break
        if not tries:
            return None
        label, key, answer = tries[0]
        evidence = (f"{prop} has no parser and no clear field; best-ranked {label} field {key}, "
                    f"then {', '.join(k for _, k, _ in tries[1:]) or 'nothing else'} (untimed only).")
        return lambda answer_id: AnswerCandidate(
            answer_id, answer, self.name, evidence, ("autoprop", f"{prop}={label}:{key}"),
            tuple(a for _, _, a in tries[1:]))


SOLVERS = (AutoPropertySolver(),)
