"""Script Analysis: specimens that carry a HUNTRESS_ANALYSIS_V1 descriptor header.

Every polyglot specimen (php, lua, typescript, wmi_mof, autoit, applescript, perl, ...)
states its modeled plan once, encoded: `HUNTRESS_ANALYSIS_V1:<codec>-<payload>` with codec
B64, HEX, HB64 (hex of Base64) or FRAG (dot-separated hex fragments). Decoded it is
`v=3|language=php|role=stager|...|steps=acquire_remote,dispatch_process|campaign_id=...`,
and each of the specimen's eleven questions asks one of those fields. Day 21: 67 of 149
specimens, 737 of 1,373 questions.
"""

from __future__ import annotations

import base64
import binascii
import re

from .base import AnswerCandidate, SolveContext, fits_format, question_items

_HEADER = re.compile(r"HUNTRESS_ANALYSIS_V1:([A-Z0-9_]+)-([A-Za-z0-9+/=._-]+)")
_DESCRIPTOR = re.compile(r"v=\d+\|[a-z_]+=")
# (question pattern, descriptor field); the first match wins.
_FIELDS = (
    (re.compile(r"^Classify the inert source role", re.I), "role"),
    (re.compile(r"^Map the decoded ordered behavior graph to one primary MITRE", re.I), "attack"),
    (re.compile(r"^Recover the modeled language adapter", re.I), "adapter"),
    (re.compile(r"synthetic campaign identifier", re.I), "campaign_id"),
    (re.compile(r"modeled stage count|number of modeled stages", re.I), "stage_count"),
    (re.compile(r"^Recover the ordered behavior graph using >", re.I), "steps"),
    (re.compile(r"^Identify the script host or (?:webshell )?source container", re.I), "host_profile"),
    (re.compile(r"^Recover the ordered encoding profile", re.I), "obfuscation_profile"),
    (re.compile(r"^Recover the multi-stage relationship profile", re.I), "stage_profile"),
    (re.compile(r"^Recover the next script language", re.I), "next_language"),
    (re.compile(r"^Recover the exact ([a-z_]+) indicator", re.I), None),  # url, file_path, ...
)


def _decode(codec: str, payload: str) -> str | None:
    try:
        if codec == "B64":
            raw = base64.b64decode(payload + "=" * (-len(payload) % 4))
        elif codec == "HEX":
            raw = bytes.fromhex(payload)
        elif codec == "HB64":
            text = bytes.fromhex(payload).decode("ascii")
            raw = base64.b64decode(text + "=" * (-len(text) % 4))
        elif codec == "FRAG":
            raw = bytes.fromhex(payload.replace(".", ""))
        else:
            return None
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return text if _DESCRIPTOR.match(text) else None


def descriptor(text: str) -> dict[str, str] | None:
    """The decoded header descriptor of one specimen, or None."""
    match = _HEADER.search(text)
    if not match:
        return None
    decoded = _decode(match[1], match[2])
    if decoded is None:
        return None
    fields = dict(part.split("=", 1) for part in decoded.split("|") if "=" in part)
    return fields or None


def answer(question: str, fields: dict[str, str]) -> str | None:
    for pattern, key in _FIELDS:
        match = pattern.search(question)
        if not match:
            continue
        key = key or match[1].lower()
        value = fields.get(key)
        if value is None:
            return None
        return value.replace(",", ">") if key == "steps" else value
    return None


def _lookup(described: dict[str, dict[str, str]], by_base: dict[str, list[str]],
            artifact: str) -> dict[str, str] | None:
    """The descriptor of the file a question names: "evidence-03.zip -> x.php" in a Mastery
    bundle is the member "evidence-03.zip/x.php"; in a single solve the archive named
    first is the artifact itself. Five sets share specimen names, so a base name alone
    is used only when it is unique.

    `by_base` (basename -> member names) is built once so this is O(1) per question: a
    Mastery pairs thousands of questions with thousands of members, and a per-question scan
    of the members was quadratic (and silently answered nothing when a path prefix kept the
    exact key from matching)."""
    parts = [part.strip() for part in artifact.split("->") if part.strip()]
    if not parts:
        return None
    for key in ("/".join(parts), "/".join(parts[1:])):
        if key in described:
            return described[key]
    same = by_base.get(parts[-1], ())
    return described[same[0]] if len(same) == 1 else None


class ScriptDescriptorSolver:
    name = "script-descriptors"
    lanes = frozenset({"script-analysis"})

    def solve(self, context: SolveContext) -> list[AnswerCandidate]:
        lane = context.challenge.get("lane") or context.challenge_id.split("-day-")[0]
        if lane not in self.lanes:
            return []
        items = question_items(context)
        if not items:
            return []
        described: dict[str, dict[str, str]] = {}
        by_base: dict[str, list[str]] = {}
        for member in context.members:
            # Only a member that carries the marker can decode; skip the rest without paying
            # to decode a (possibly 1 MB) body to text first.
            if b"HUNTRESS_ANALYSIS_V1:" not in member.data[:1_000_000]:
                continue
            text = member.data[:1_000_000].decode("utf-8", "replace")
            fields = descriptor(text)
            if fields:
                described[member.name] = fields
                by_base.setdefault(member.name.rsplit("/", 1)[-1], []).append(member.name)
        if not described:
            return []
        candidates = []
        for question in items:
            name = (question.artifact or "").rsplit("->", 1)[-1].strip()
            fields = _lookup(described, by_base, question.artifact or "")
            if fields is None:
                continue
            value = answer(question.text, fields)
            if value is not None and fits_format(value, question.answer_format):
                candidates.append(AnswerCandidate(
                    question.answer_id, value, self.name,
                    f"{name}: field of its decoded HUNTRESS_ANALYSIS_V1 descriptor.",
                ))
        return candidates


SOLVERS = (ScriptDescriptorSolver(),)
