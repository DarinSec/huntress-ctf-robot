"""Script Analysis lane: per-file classification from the embedded HUNTRESS_ANALYSIS descriptors.

The heavy logic lives in `analysis.scriptrules` (ported from the proven offline solver): it decodes
each specimen's embedded descriptor (base64/hex/decimal/xor/rolling/repeating-key/... codecs, all
stdlib) to a key=value or JSON record and answers the role / ATT&CK technique / adapter / campaign /
URL / ordered steps / obfuscation / stage fields per language family (jscript, batch, vbscript,
python, bash, nodejs, polyglot, host, and the PowerShell resource/collection/impact samples).

Members are the files the framework already unpacked; this adapter decodes their bytes to text and
keys them by (set, basename) as the rules expect. Single Solve / Time Trial is one set (set 1);
Mastery sets are read from the bundle's inner evidence zips via the framework's container reader.
"""

from __future__ import annotations

import re

from ..analysis import scriptrules
from ..containers import unwrap
from .base import AnswerCandidate, SolveContext, question_items

_SET = re.compile(r"(set(\d+))\.")
_PASSWORDS = ("infected",)
_MAX = 1 << 20  # scripts are small; cap defensively


def _qdict(questions):
    return [{"id": q.answer_id, "artifact": q.artifact or "", "answer_format": q.answer_format}
            for q in questions]


def _text(data: bytes) -> str:
    return data[:_MAX].decode("utf-8", errors="replace")


def _source(context, set_numbers):
    """{(set_no, basename): text} across the assignment's script members."""
    src: dict[tuple[int, str], str] = {}
    if set_numbers:
        for n in set_numbers:
            nested = [m for m in context.members if re.search(rf"evidence-0*{n}\.zip$", m.name)]
            # In one bundle the inner evidence zips are unpacked already ("evidence-02.zip/x.php");
            # the sets share specimen names, so take only this set's members.
            inside = [m for m in context.members if re.search(rf"(^|/)evidence-0*{n}\.zip/", m.name)]
            members = (unwrap(nested[0].data, _PASSWORDS).members if nested else inside or context.members)
            for m in members:
                if not m.name.endswith("/"):
                    src[(n, m.name.rsplit("/", 1)[-1])] = _text(m.data)
    else:
        for m in context.members:
            if not m.name.endswith("/"):
                src[(1, m.name.rsplit("/", 1)[-1])] = _text(m.data)
    return src


class ScriptSolver:
    name = "script-rules"

    def solve(self, context: SolveContext) -> list[AnswerCandidate]:
        lane = context.challenge.get("lane") or ""
        if "script" not in lane and "script-analysis" not in context.challenge_id:
            return []
        qs = question_items(context)
        if not qs:
            return []
        set_numbers = sorted({int(m.group(2)) for q in qs for m in [_SET.match(q.answer_id)] if m})
        source = _source(context, set_numbers)
        if not source:
            return []
        try:
            cands, _missing = scriptrules.solve(source, _qdict(qs))
        except Exception:
            return []
        out: list[AnswerCandidate] = []
        for answer_id, candidates in cands.items():
            if candidates:
                out.append(AnswerCandidate(
                    answer_id, candidates[0], self.name,
                    "Decoded the specimen's embedded HUNTRESS_ANALYSIS descriptor.",
                ))
        return out


SOLVERS = (ScriptSolver(),)
