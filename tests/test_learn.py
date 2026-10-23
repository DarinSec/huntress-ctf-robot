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
    def __init__(self, wrong_kind=None, wrong_ids=(), ids=None):
        self.wrong_kind = wrong_kind
        self.wrong_ids = frozenset(wrong_ids)
        self.ids = list(ids or IDS)
        self.accepted = set()
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
        """All-or-nothing, as the service is: one wrong answer rejects the whole request."""
        self.submits.append(dict(answers))
        if any(kind_of(i) == self.wrong_kind or i in self.wrong_ids for i in answers):
            return {"result": "incorrect"}
        self.accepted.update(answers)  # Accepted answers stay accepted.
        remaining = max(len(self.ids) - len(self.accepted), 0)
        return {"result": "accepted", "remaining": remaining} if remaining else {"result": "CORRECT"}


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
        report = json.loads(output)
        self.assertEqual(report["kinds"]["d#-msi-#-guid"]["result"], "incorrect")
        self.assertEqual(report["kinds"]["d#-jpeg-#-dims"]["result"], "accepted")
        # Every answer of the kind is wrong, so the split names them all and banks none.
        self.assertEqual(report["rejected_answer_ids"],
                         ["set1.d13-msi-001-guid", "set2.d13-msi-001-guid"])
        self.assertEqual(report["kinds"]["d#-msi-#-guid"]["accepted_by_splitting"], 0)
        self.assertEqual(saved, "")

    def test_a_rejected_kind_is_split_until_the_wrong_answer_is_named(self):
        # Day 23 Binary: one of fifteen machine answers was wrong, and the other
        # fourteen stayed open with it. The split banks those and names the one to fix.
        ids = [f"d{number:02}_analysis_machine" for number in range(1, 16)]

        class ManySolver:
            name = "fake"

            def solve(self, context):
                return [AnswerCandidate(answer_id, "62", self.name, "e") for answer_id in ids]

        class OpenClient(Client):
            def status(self, challenge_id):
                return {"answer_ids": self.ids, "attempt_id": "a"}

            def start(self, challenge_id, timed=False):
                self.calls.append(("start", timed))
                return {"answer_ids": self.ids, "attempt_id": "a"}

        client = OpenClient(wrong_ids=["d01_analysis_machine"], ids=ids)
        with redirect_stdout(StringIO()) as output, patch("huntress_ctf.learn.SOLVERS", (ManySolver(),)):
            code = run_learn(client, "binary-day-23-x", open_only=True, challenge={"id": "binary-day-23-x"})
        report = json.loads(output.getvalue())
        self.assertEqual(code, UNRESOLVED)
        self.assertEqual(report["rejected_answer_ids"], ["d01_analysis_machine"])
        self.assertEqual(client.accepted, set(ids) - {"d01_analysis_machine"})  # The rest are in.
        self.assertLessEqual(len(client.submits), 9)  # One kind plus about eight halves.

    def test_open_only_never_starts_a_new_attempt(self):
        client = Client()  # Its status is a completed attempt.
        with redirect_stdout(StringIO()), patch("huntress_ctf.learn.SOLVERS", (Solver(),)):
            code = run_learn(client, "metadata-forensics-day-19-x/mastery", open_only=True,
                             challenge={"id": "metadata-forensics-day-19-x/mastery"})
        self.assertEqual((code, client.calls, client.submits), (UNRESOLVED, [], []))

    def test_questions_without_digits_are_grouped_by_field(self):
        ids = [f"s{chr(97 + n // 26)}{chr(97 + n % 26)}-{field}" for n in range(45) for field in ("attack", "role")]

        class ScriptSolver:
            name = "fake"

            def solve(self, context):
                return [AnswerCandidate(answer_id, "value", self.name, "e") for answer_id in ids]

        class OpenClient(Client):
            def status(self, challenge_id):
                return {"answer_ids": ids, "attempt_id": "a"}

            def start(self, challenge_id, timed=False):
                self.calls.append(("start", timed))
                return {"answer_ids": ids, "attempt_id": "a"}

        client = OpenClient(wrong_kind="never", ids=ids)
        with redirect_stdout(StringIO()), patch("huntress_ctf.learn.SOLVERS", (ScriptSolver(),)):
            run_learn(client, "script-analysis-day-22-x", open_only=True, challenge={"id": "script-analysis-day-22-x"})
        self.assertEqual(client.calls, [("start", False)])  # Reconnects only.
        self.assertEqual(sorted(len(batch) for batch in client.submits), [45, 45])  # attack, role.

    def test_a_rejected_answer_is_retried_with_the_solver_s_other_spellings(self):
        # The grader picks the spelling, not the bytes: day 22 refused "x86" and took the
        # decimal code. Untimed, after the rejection, the robot offers the rest itself.
        ids = ["d01_analysis_machine", "d02_analysis_format"]

        class SpellingSolver:
            name = "fake"

            def solve(self, context):
                return [AnswerCandidate("d01_analysis_machine", "62", self.name, "e",
                                        alternatives=("x86_64", "0x3e")),
                        AnswerCandidate("d02_analysis_format", "ELF", self.name, "e")]

        class OpenClient(Client):
            def status(self, challenge_id):
                return {"answer_ids": self.ids, "attempt_id": "a"}

            def start(self, challenge_id, timed=False):
                return {"answer_ids": self.ids, "attempt_id": "a"}

            def submit_many(self, challenge_id, answers):
                if answers == {"d01_analysis_machine": "x86_64"}:  # The spelling it takes.
                    self.submits.append(dict(answers))
                    self.accepted.update(answers)
                    return {"result": "accepted", "remaining": 0}
                return super().submit_many(challenge_id, answers)

        client = OpenClient(wrong_ids=["d01_analysis_machine"], ids=ids)
        with redirect_stdout(StringIO()) as output, patch("huntress_ctf.learn.SOLVERS", (SpellingSolver(),)):
            run_learn(client, "binary-day-23-x", open_only=True, challenge={"id": "binary-day-23-x"})
        report = json.loads(output.getvalue())
        self.assertEqual(report["alternatives"]["d01_analysis_machine"],
                         {"accepted": "x86_64", "instead_of": "62", "solver": "fake"})
        self.assertNotIn("rejected_answer_ids", report)  # Healed, so nothing is left to fix.
        self.assertIn("d01_analysis_machine", client.accepted)

    def test_a_single_open_question_still_gets_its_other_spellings(self):
        # Day 23 Metadata: 27 of 28 kinds accepted, one left. Splitting one answer of one
        # kind would resend it unchanged - but its other spellings are something new.
        ids = ["d07-zip-001-zip-central-directory-member-names"]
        stored, sorted_names = '["b/x.csv","a/y.csv"]', '["a/y.csv","b/x.csv"]'

        class OneSolver:
            name = "fake"

            def solve(self, context):
                return [AnswerCandidate(ids[0], stored, self.name, "e",
                                        alternatives=(sorted_names, '["x.csv","y.csv"]'))]

        class OpenClient(Client):
            def status(self, challenge_id):
                return {"answer_ids": self.ids, "attempt_id": "a"}

            def start(self, challenge_id, timed=False):
                return {"answer_ids": self.ids, "attempt_id": "a"}

            def submit_many(self, challenge_id, answers):
                self.submits.append(dict(answers))
                if answers == {ids[0]: sorted_names}:
                    return {"result": "CORRECT"}
                return {"result": "incorrect"}

        client = OpenClient(ids=ids)
        with redirect_stdout(StringIO()) as output, patch("huntress_ctf.learn.SOLVERS", (OneSolver(),)):
            code = run_learn(client, "metadata-day-23-x/time_trial", open_only=True,
                             challenge={"id": "metadata-day-23-x/time_trial"})
        report = json.loads(output.getvalue())
        self.assertEqual(code, COMPLETE)
        self.assertEqual(report["alternatives"][ids[0]]["accepted"], sorted_names)
        self.assertEqual(client.submits, [{ids[0]: stored}, {ids[0]: sorted_names}])

    def test_all_kinds_accepted_records_a_proven_solver(self):
        client = Client()
        code, _, saved = self.run_learn(client)
        self.assertEqual(code, COMPLETE)
        self.assertIn("metadata-forensics-day-19-x/mastery", saved)
        self.assertEqual(client.calls, [("retry", False)])


if __name__ == "__main__":
    unittest.main()
