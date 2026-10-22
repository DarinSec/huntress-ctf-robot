"""Synthetic fixture for the Script Analysis adapter: an embedded HUNTRESS_ANALYSIS descriptor.

The specimen carries a base64-encoded key=value descriptor, exactly the shape the real
Script-analysis samples use. No archive extraction (members passed directly).
"""

import base64
import unittest
from pathlib import Path

from huntress_ctf.containers import Member
from huntress_ctf.solvers.base import SolveContext
from huntress_ctf.solvers.script import ScriptSolver

DESCRIPTOR = (
    "v=3|language=php|role=stager|verdict=suspicious|attack=T1105|adapter=runtime_loader|"
    "host_profile=standalone|obfuscation_profile=base64|stage_profile=two_stage_download_execute|"
    "next_language=jscript|stage_count=2|steps=acquire_remote,dispatch_process|"
    "campaign_id=TEST-abc123|url=https://test-abc123.example.invalid/stage|file_path=/tmp/x.stage"
)


def specimen(campaign: str = "TEST-abc123") -> bytes:
    blob = base64.b64encode(DESCRIPTOR.replace("TEST-abc123", campaign).encode()).decode()
    return (f"<?php\n// HUNTRESS_ANALYSIS_V1:B64-{blob}\ndeclare(strict_types=1);\n").encode()


def context(member_name, questions):
    return SolveContext(
        challenge_id="script-analysis-day-21-x",
        challenge={"lane": "script-analysis", "questions": questions},
        attempt={"attempt_id": "test"},
        artifact=b"",
        artifact_path=Path("unused"),
        answer_ids=tuple(q["id"] for q in questions),
        members=(Member(member_name, specimen()),),
    )


class ScriptSolverTest(unittest.TestCase):
    def test_descriptor_fields(self):
        name = "polyglot-php-stager.php"
        art = f"evidence.zip -> {name}"
        questions = [
            {"id": "polyglot-php-stager-campaign", "question": "campaign?", "artifact": art,
             "answer_format": {"kind": "exact_text"}},
            {"id": "polyglot-php-stager-url", "question": "url?", "artifact": art,
             "answer_format": {"kind": "exact_text"}},
            {"id": "polyglot-php-stager-role", "question": "role?", "artifact": art,
             "answer_format": {"kind": "enum"}},
        ]
        got = {c.answer_id: c.answer for c in ScriptSolver().solve(context(name, questions))}
        self.assertEqual(got["polyglot-php-stager-campaign"], "TEST-abc123")
        self.assertEqual(got["polyglot-php-stager-url"], "https://test-abc123.example.invalid/stage")
        self.assertEqual(got["polyglot-php-stager-role"], "stager")

    def test_mastery_sets_in_one_bundle_keep_their_own_specimens(self):
        # The bundle's inner evidence zips are already unpacked: "evidence-02.zip/<name>".
        # Five sets share specimen names, so a base name alone would mix them up.
        name = "polyglot-php-stager.php"
        questions = [
            {"id": f"set{n}.polyglot-php-stager-campaign", "question": "campaign?",
             "artifact": f"evidence-0{n}.zip -> {name}", "answer_format": {"kind": "exact_text"}}
            for n in (1, 2)
        ]
        members = tuple(
            Member(f"bundle/evidence-0{n}.zip/specimens/{name}", specimen(f"TEST-set{n}")) for n in (1, 2)
        )
        ctx = context(name, questions)
        ctx = SolveContext(ctx.challenge_id, ctx.challenge, ctx.attempt, ctx.artifact,
                           ctx.artifact_path, ctx.answer_ids, members=members)
        got = {c.answer_id: c.answer for c in ScriptSolver().solve(ctx)}
        self.assertEqual(got, {"set1.polyglot-php-stager-campaign": "TEST-set1",
                               "set2.polyglot-php-stager-campaign": "TEST-set2"})


if __name__ == "__main__":
    unittest.main()
