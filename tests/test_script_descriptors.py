"""Script Analysis specimens with a HUNTRESS_ANALYSIS_V1 header (synthetic, built here)."""

import base64
import unittest

from huntress_ctf.containers import Member
from huntress_ctf.solvers import SolveContext
from huntress_ctf.solvers.script_descriptors import ScriptDescriptorSolver, descriptor

PLAN = ("v=3|language=php|role=stager|verdict=suspicious|attack=T1105|adapter=runtime_loader|"
        "host_profile=standalone|obfuscation_profile=base64|stage_profile=two_stage_download_execute|"
        "next_language=jscript|stage_count=2|steps=acquire_remote,dispatch_process|campaign_id=PHP-1234abcd|"
        "url=https://php-1234.example.invalid/stage|file_path=/tmp/x.stage")


def header(codec):
    raw = PLAN.encode()
    payload = {
        "B64": base64.b64encode(raw).decode(),
        "HEX": raw.hex(),
        "HB64": base64.b64encode(raw).hex(),
        "FRAG": ".".join(raw.hex()[i:i + 24] for i in range(0, len(raw.hex()), 24)),
    }[codec]
    return f"<?php\n// HUNTRESS_ANALYSIS_V1:{codec}-{payload}\n$descriptor = \"{payload}\";\n"


class DescriptorTests(unittest.TestCase):
    def test_every_codec_decodes(self):
        for codec in ("B64", "HEX", "HB64", "FRAG"):
            with self.subTest(codec=codec):
                self.assertEqual(descriptor(header(codec))["campaign_id"], "PHP-1234abcd")
        self.assertIsNone(descriptor("no header here"))

    def test_questions_map_to_fields(self):
        texts = {
            "role": "Classify the inert source role.",
            "attack": "Map the decoded ordered behavior graph to one primary MITRE ATT&CK technique using this precedence: ...",
            "steps": "Recover the ordered behavior graph using > separators.",
            "url": "Recover the exact url indicator.",
            "count": "Recover the modeled stage count.",
            "host": "Identify the script host or source container.",
        }
        questions = [{"id": key, "question": text, "artifact": "evidence.zip -> polyglot-php-stager.php"}
                     for key, text in texts.items()]
        ids = tuple(texts)
        context = SolveContext("script-analysis-day-21-x", {"lane": "script-analysis"},
                               {"answer_ids": list(ids), "questions": questions}, b"zip", None, ids,
                               members=(Member("polyglot-php-stager.php", header("FRAG").encode()),))
        answers = {c.answer_id: c.answer for c in ScriptDescriptorSolver().solve(context)}
        self.assertEqual(answers, {"role": "stager", "attack": "T1105", "steps": "acquire_remote>dispatch_process",
                                   "url": "https://php-1234.example.invalid/stage", "count": "2", "host": "standalone"})


if __name__ == "__main__":
    unittest.main()
