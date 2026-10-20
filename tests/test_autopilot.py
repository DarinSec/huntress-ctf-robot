"""Untimed solves: the same engine as the timed race, with an ordinary start."""

from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from huntress_ctf.autopilot import (
    COMPLETE, CONFLICT, EXPIRED, INCORRECT, PENDING, UNRESOLVED, list_filters, lookup_challenge,
)
from huntress_ctf.client import GameMasterError
from huntress_ctf.fastpath import run_fast
from huntress_ctf.solvers import AnswerCandidate


class FakeClient:
    token = None

    def __init__(self, *, mastery=False, result=None):
        self.artifact_bytes = b'{"answers":{"a":"one","b":"two"}}' if mastery else b"aGVsbG8="
        self.assignment = {
            "answer_ids": ["a", "b"] if mastery else ["a"],
            "attempt_id": "one",
            "artifact_sha256": hashlib.sha256(self.artifact_bytes).hexdigest(),
            "mode": "mastery" if mastery else "single_solve",
            "instructions": (
                "Submit the JSON answer map." if mastery else "Decode the Base64 text."
            ),
        }
        self.result = result if result is not None else {"result": "CORRECT"}
        self.calls = []
        self.challenges = [{"id": "c", "name": "Puzzle", "mode": self.assignment["mode"]}]

    def list_challenges(self):
        self.calls.append("list")
        return {"challenges": self.challenges}

    def start(self, challenge_id, timed=False):
        self.calls.append(("start", timed))
        return deepcopy(self.assignment)

    def retry(self, challenge_id, timed=False):
        self.calls.append(("retry", timed))
        return deepcopy(self.assignment)

    def status(self, challenge_id):
        self.calls.append("status")
        return {**deepcopy(self.assignment), "state": "active"}

    def artifact(self, challenge_id):
        self.calls.append("artifact")
        return self.artifact_bytes

    def submit_many(self, challenge_id, answers):
        self.calls.append(("submit_many", dict(answers)))
        if isinstance(self.result, Exception):
            raise self.result
        return deepcopy(self.result)

    def submissions(self):
        return [call[1] for call in self.calls if call[0] == "submit_many"]


class UntimedSolveTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = StringIO()

    def run_robot(self, client, **kwargs):
        root = Path(self.directory.name)
        with redirect_stdout(self.output):
            return run_fast(
                client, "c", artifact_dir=root, work_dir=root / "work",
                hints_path=root / "hints.json", **kwargs,
            )

    def test_single_solve_takes_four_requests(self):
        client = FakeClient()
        self.assertEqual(self.run_robot(client), COMPLETE)
        self.assertEqual(client.calls, [
            "list", ("start", False), "artifact", ("submit_many", {"a": "hello"}), "status",
        ])
        self.assertEqual(len(list(Path(self.directory.name).glob("*.bin"))), 1)
        self.assertIn("base64-answer", (Path(self.directory.name) / "hints.json").read_text(encoding="utf-8"))

    def test_known_challenge_record_skips_the_list(self):
        client = FakeClient()
        self.assertEqual(self.run_robot(client, challenge=client.challenges[0]), COMPLETE)
        self.assertNotIn("list", client.calls)

    def test_live_ids_list_only_their_own_day_and_lane(self):
        self.assertEqual(list_filters("warmups-day-01"), (1, "warmups"))
        self.assertEqual(list_filters("script-analysis-day-01-native-signals/mastery"), (1, "script-analysis"))
        self.assertEqual(list_filters("binary-reverse-engineering-day-12-x/time_trial"), (12, "binary-reverse-engineering"))
        self.assertEqual(list_filters("welcome-robots"), (None, None))
        self.assertEqual(list_filters("warmups-day-99"), (None, None))

        record = {"id": "web-day-02-x", "lane": "web-exploitation"}
        lists = []

        def list_challenges(day=None, lane=None):
            lists.append((day, lane))
            return {"challenges": [record] if lane is None else []}
        client = FakeClient()
        client.list_challenges = list_challenges
        found, _ = lookup_challenge(client, "web-day-02-x")
        self.assertEqual(found, record)
        # The ID's lane missed, so the day was listed; the 80-second full list never was.
        self.assertEqual(lists, [(2, "web"), (2, None)])

    def test_legacy_route_start_reports_the_running_clock(self):
        client = FakeClient()
        client.assignment.update(mode="time_trial", deadline="2026-10-17T12:00:00Z")
        self.assertEqual(self.run_robot(client), COMPLETE)
        self.assertIn(("start", False), client.calls)
        report = self.output.getvalue()
        self.assertIn("2026-10-17T12:00:00Z", report)
        self.assertIn("the server clock is running", report)
        self.assertIn("may be timed by default", report)

    def test_mastery_answers_share_one_post(self):
        client = FakeClient(mastery=True)
        self.assertEqual(self.run_robot(client), COMPLETE)
        self.assertEqual(client.submissions(), [{"a": "one", "b": "two"}])

    def test_partial_mastery_is_nonzero(self):
        client = FakeClient(mastery=True, result={"result": "accepted", "remaining": 1})
        client.artifact_bytes = b'{"answers":{"a":"one"}}'
        client.assignment["artifact_sha256"] = hashlib.sha256(client.artifact_bytes).hexdigest()
        self.assertEqual(self.run_robot(client), UNRESOLVED)
        self.assertEqual(client.submissions(), [{"a": "one"}])
        self.assertIn('"b"', self.output.getvalue())

    def test_already_accepted_answers_are_not_resent(self):
        client = FakeClient(mastery=True)
        client.assignment["accepted_answer_ids"] = ["a"]
        self.assertEqual(self.run_robot(client), COMPLETE)
        self.assertEqual(client.submissions(), [{"b": "two"}])

    def test_terminal_attempts_do_not_download_submit_or_retry(self):
        for state, expected in (
            ({"result": "CORRECT"}, COMPLETE),
            ({"result": "CORRECT", "status": "pending"}, PENDING),
            ({"state": "expired"}, EXPIRED),
            ({"state": "locked"}, UNRESOLVED),
        ):
            with self.subTest(state=state):
                client = FakeClient()
                client.assignment.update(state)
                self.assertEqual(self.run_robot(client), expected)
                self.assertEqual(client.calls, ["list", ("start", False), "status"])

    def test_submission_outcomes_are_not_confused_with_success(self):
        for result, expected in (
            ({"result": "incorrect"}, INCORRECT),
            ({"result": "expired"}, EXPIRED),
            ({"result": "CORRECT", "status": "pending"}, PENDING),
            ({"result": "accepted", "remaining": 0}, UNRESOLVED),
        ):
            with self.subTest(result=result):
                client = FakeClient(result=result)
                self.assertEqual(self.run_robot(client), expected)
                self.assertEqual(len(client.submissions()), 1)

    def test_unknown_submission_result_is_an_error(self):
        with self.assertRaises(GameMasterError):
            self.run_robot(FakeClient(result={"result": "MAYBE"}))

    def test_hash_mismatch_aborts_before_solving(self):
        client = FakeClient()
        client.artifact_bytes = b"changed bytes"
        with self.assertRaisesRegex(GameMasterError, "SHA-256"):
            self.run_robot(client)
        self.assertFalse(client.submissions())

    def test_native_route_without_ids_is_preserved(self):
        client = FakeClient()
        client.assignment.pop("answer_ids")
        self.assertEqual(self.run_robot(client), UNRESOLVED)
        self.assertNotIn("artifact", client.calls)

    def test_unknown_challenge_is_not_started(self):
        client = FakeClient()
        client.challenges = []
        with self.assertRaises(GameMasterError):
            self.run_robot(client)
        self.assertEqual(client.calls, ["list"])

    def test_conflicting_candidates_are_all_skipped(self):
        class DisagreeingSolver:
            def solve(self, context):
                return [AnswerCandidate("a", "one", "s", "e"), AnswerCandidate("a", "two", "s", "e")]
        client = FakeClient()
        with patch("huntress_ctf.fastpath.SOLVERS", (DisagreeingSolver(),)):
            self.assertEqual(self.run_robot(client), CONFLICT)
        self.assertFalse(client.submissions())
        self.assertIn("attempt is preserved.", self.output.getvalue())

    def test_unsolved_attempt_writes_a_workspace(self):
        client = FakeClient()
        client.artifact_bytes = b"unrecognized"
        client.assignment["artifact_sha256"] = hashlib.sha256(b"unrecognized").hexdigest()
        self.assertEqual(self.run_robot(client), UNRESOLVED)
        self.assertTrue((Path(self.directory.name) / "work" / "c" / "triage.md").is_file())

    def test_uncertain_post_is_not_retried(self):
        client = FakeClient(result=GameMasterError("Transport failed"))
        with self.assertRaises(GameMasterError):
            self.run_robot(client)
        self.assertEqual(len(client.submissions()), 1)


if __name__ == "__main__":
    unittest.main()
