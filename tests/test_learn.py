from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from huntress_ctf.autopilot import COMPLETE, UNRESOLVED
from huntress_ctf.learn import kind_of, run_learn
from huntress_ctf.solvers import AnswerCandidate

IDS = ["set1.d04-jpeg-001-dims", "set2.d04-jpeg-001-dims", "set1.d13-msi-001-guid", "set2.d13-msi-001-guid"]


class Solver:
    name = "fake"

    def solve(self, context):
        return [AnswerCandidate(answer_id, "value", self.name, "e") for answer_id in IDS]


class Client:
    def __init__(self, wrong_kind=None):
        self.wrong_kind = wrong_kind
        self.submits = []
        self.calls = []

    def list_challenges(self, day=None, lane=None):
        return {"challenges": [{"id": "metadata-forensics-day-19-x/mastery", "lane": "metadata-forensics"}]}

    def status(self, challenge_id):
        return {"answer_ids": IDS, "result": "CORRECT"}

    def retry(self, challenge_id, timed=False):
        self.calls.append(("retry", timed))
        return {"answer_ids": IDS, "attempt_id": "a", "deadline": "2026-10-20T00:00:00Z"}

    def artifact(self, challenge_id, delivery=None):
        return b"bytes"

    def submit_many(self, challenge_id, answers):
        self.submits.append(dict(answers))
        if any(kind_of(answer_id) == self.wrong_kind for answer_id in answers):
            return {"result": "incorrect"}
        done = sum(len(batch) for batch in self.submits if not any(kind_of(i) == self.wrong_kind for i in batch))
        return {"result": "CORRECT"} if done == len(IDS) else {"result": "accepted", "remaining": len(IDS) - done}


class LearnTests(unittest.TestCase):
    def run_learn(self, client):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(StringIO()) as output, \
                patch("huntress_ctf.learn.SOLVERS", (Solver(),)):
            hints = Path(directory) / "hints.json"
            code = run_learn(client, "metadata-forensics-day-19-x/mastery", hints_path=hints)
            saved = hints.read_text(encoding="utf-8") if hints.exists() else ""
        return code, output.getvalue(), saved

    def test_kinds_group_across_sets(self):
        self.assertEqual(kind_of("set3.d04-jpeg-001-jpeg-sof-dimensions-pixels"), "d#-jpeg-#-jpeg-sof-dimensions-pixels")

    def test_one_request_per_kind_and_the_wrong_kind_is_named(self):
        client = Client(wrong_kind="d#-msi-#-guid")
        code, output, saved = self.run_learn(client)
        self.assertEqual(code, UNRESOLVED)
        self.assertEqual(len(client.submits), 2)  # One per kind; nothing resent.
        report = json.loads(output)
        self.assertEqual(report["kinds"]["d#-msi-#-guid"]["result"], "incorrect")
        self.assertEqual(report["kinds"]["d#-jpeg-#-dims"]["result"], "accepted")
        self.assertEqual(saved, "")

    def test_all_kinds_accepted_records_a_proven_solver(self):
        client = Client()
        code, _, saved = self.run_learn(client)
        self.assertEqual(code, COMPLETE)
        self.assertIn("metadata-forensics-day-19-x/mastery", saved)
        self.assertEqual(client.calls, [("retry", False)])


if __name__ == "__main__":
    unittest.main()
