"""Metadata Forensics and Script Analysis: answer "what is the X?" from extracted facts.

Conservative by design: a question must map to exactly one fact category, and that
category must hold exactly one distinct value across the artifact and its members.
"""

from __future__ import annotations

import re

from ..evidence import collect
from .base import AnswerCandidate, SolveContext, instruction_text, questions

# (question pattern, metadata key pattern or None, IOC kind or None)
CATEGORIES = {
    "author": (r"\b(?:author|creator|created by|written by|artist|owner)\b",
               r"(?:Artist|Author|XPAuthor|dc:creator|creator|CameraOwnerName)$", None),
    "last-modified-by": (r"\b(?:last (?:modified|saved) by|modified by)\b", r"lastModifiedBy$", None),
    "software": (r"\b(?:software|producer|application|creator ?tool|program used)\b",
                 r"(?:Software|Producer|CreatorTool|Application|pdf:Producer)$", None),
    "camera": (r"\b(?:camera|phone model|device model|make and model)\b", r"(?:Make|Model)$", None),
    "gps": (r"\b(?:gps|coordinates|latitude and longitude|geolocation)\b", r"GPS:Position$", None),
    "company": (r"\b(?:company|organi[sz]ation)\b", r"Company$", None),
    "comment": (r"\b(?:comment|hidden note)\b", r"(?:Comment|UserComment|XPComment|ZIP:comment)$", None),
    "copyright": (r"\bcopyright\b", r"(?:Copyright|dc:rights)$", None),
    "url": (r"\b(?:url|link)\b", None, "url"),
    "domain": (r"\b(?:domain|hostname|c2 host)\b", None, "domain"),
    "ip": (r"\bip(?:v4)?(?: address)?\b", None, "ipv4"),
    "email": (r"\be-?mail\b", None, "email"),
    "sha256": (r"\bsha-?256\b", None, "sha256"),
    "sha1": (r"\bsha-?1\b", None, "sha1"),
    "md5": (r"\bmd5\b", None, "md5"),
    "registry": (r"\bregistry\b", None, "registry"),
}
_QUESTION = re.compile(r"[^.?!\n]*\?")


def _focus(text: str) -> str:
    """The question sentences of a text; descriptions often mention unrelated nouns."""
    asked = _QUESTION.findall(text)
    return " ".join(asked) if asked else text


def _category(text: str) -> str | None:
    matched = [name for name, (pattern, _, _) in CATEGORIES.items() if re.search(pattern, text, re.I)]
    return matched[0] if len(matched) == 1 else None


def _values(facts, category: str) -> list[str]:
    _, key_pattern, ioc_kind = CATEGORIES[category]
    values: list[str] = []
    if key_pattern:
        # Case-sensitive on purpose: PDF "Creator" is an application, Office "creator" a person.
        for key, items in facts.metadata.items():
            if re.search(key_pattern, key):
                values.extend(items)
    if ioc_kind:
        values.extend(facts.iocs.get(ioc_kind, []))
    unique: dict[str, str] = {}
    for value in values:
        unique.setdefault(value.casefold(), value)
    return list(unique.values())


class FactSolver:
    name = "fact-lookup"

    def solve(self, context: SolveContext) -> list[AnswerCandidate]:
        pairs = questions(context)
        if not pairs and len(context.answer_ids) == 1:
            pairs = [(context.answer_ids[0], instruction_text(context))]
        wanted = [(answer_id, _category(_focus(text))) for answer_id, text in pairs]
        wanted = [(answer_id, category) for answer_id, category in wanted if category]
        if not wanted:
            return []
        facts = collect(context.artifact, context.members)
        candidates = []
        for answer_id, category in wanted:
            values = _values(facts, category)
            if len(values) == 1:
                candidates.append(AnswerCandidate(
                    answer_id, values[0], self.name,
                    f"The question asks for the {category}; exactly one such value was extracted.",
                ))
        return candidates


SOLVERS = (FactSolver(),)
