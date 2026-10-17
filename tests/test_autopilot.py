from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from huntress_ctf.autopilot import (
    COMPLETE, CONFLICT, EXPIRED, INCORRECT, PENDING, UNRESOLVED, run_autopilot,
)
from huntress_ctf.client import GameMasterError
from huntress_ctf.solvers import AnswerCandidate


class FakeClient:
    token = None

    def __init__(self, *, mastery=False, results=None):
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
        self.current = {**self.assignment, "state": "active"}
        self.results = results if results is not None else [{"result": "CORRECT"}]
        self.submissions = []
        self.starts = []
        self.status_calls = 0
        self.downloads = 0
        self.change_on_status = None
        self.changed_bytes = None

    def list_challenges(self):
        return {"challenges": [{"id": "c", "name": "Puzzle", "mode": self.assignment["mode"]}]}

    def start(self, challenge_id, timed=False):
        self.starts.append((challenge_id, timed))
        return deepcopy(self.assignment)

    def status(self, challenge_id):
        self.status_calls += 1
        if self.change_on_status:
            self.change_on_status(self)
        return deepcopy(self.current)

    def artifact(self, challenge_id):
        self.downloads += 1
        if self.downloads > 1 and self.changed_bytes is not None:
            return self.changed_bytes
        return self.artifact_bytes

    def submit(self, challenge_id, answer_id, answer):
        self.submissions.append((challenge_id, answer_id, answer))
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        if result.get("result") == "accepted":
            self.current.setdefault("accepted_answer_ids", []).append(answer_id)
        self.current.update(result)
        return deepcopy(result)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = StringIO()

    def run_robot(self, client, **kwargs):
        with redirect_stdout(self.output):
            return run_autopilot(client, "c", artifact_dir=Path(self.directory.name), **kwargs)

    def test_single_solve_submits_derived_answer(self):
        client = FakeClient()
        self.assertEqual(self.run_robot(client), COMPLETE)
        self.assertEqual(client.submissions, [("c", "a", "hello")])
        self.assertEqual(client.starts, [("c", False)])
        self.assertEqual(len(list(Path(self.directory.name).glob("*.bin"))), 1)

    def test_time_trial_opt_in_and_deadline_display(self):
        client = FakeClient()
        client.assignment.update(mode="time_trial", deadline="2026-10-17T12:00:00Z")
        client.current.update(client.assignment)
        self.assertEqual(self.run_robot(client, timed=True), COMPLETE)
        self.assertEqual(client.starts, [("c", True)])
        self.assertIn("2026-10-17T12:00:00Z", self.output.getvalue())
        self.assertIn("Time Trial", self.output.getvalue())

    def test_mastery_submits_each_id_and_requires_correct(self):
        client = FakeClient(mastery=True, results=[
            {"result": "accepted", "remaining": 1}, {"result": "CORRECT"},
        ])
        self.assertEqual(self.run_robot(client), COMPLETE)
        self.assertEqual(client.submissions, [("c", "a", "one"), ("c", "b", "two")])

    def test_partial_mastery_is_nonzero(self):
        client = FakeClient(mastery=True, results=[{"result": "accepted", "remaining": 1}])
        client.artifact_bytes = b'{"answers":{"a":"one"}}'
        digest = hashlib.sha256(client.artifact_bytes).hexdigest()
        client.assignment["artifact_sha256"] = digest
        client.current["artifact_sha256"] = digest
        self.assertEqual(self.run_robot(client), UNRESOLVED)
        self.assertEqual(len(client.submissions), 1)

    def test_already_accepted_answers_are_skipped(self):
        client = FakeClient(mastery=True)
        client.current.update(accepted_answer_ids=["a"], remaining=1)
        self.assertEqual(self.run_robot(client), COMPLETE)
        self.assertEqual(client.submissions, [("c", "b", "two")])

    def test_start_progress_is_preserved_when_status_omits_it(self):
        client = FakeClient(mastery=True)
        client.assignment["accepted_answer_ids"] = ["a"]
        self.assertEqual(self.run_robot(client), COMPLETE)
        self.assertEqual(client.submissions, [("c", "b", "two")])

    def test_terminal_attempts_do_not_download_or_submit(self):
        for state, expected in (
            ({"result": "CORRECT"}, COMPLETE),
            ({"result": "CORRECT", "status": "pending"}, PENDING),
            ({"state": "expired"}, EXPIRED),
            ({"state": "locked"}, UNRESOLVED),
        ):
            with self.subTest(state=state):
                client = FakeClient()
                client.current.update(state)
                self.assertEqual(self.run_robot(client), expected)
                self.assertEqual(client.downloads, 0)
                self.assertFalse(client.submissions)

    def test_submission_outcomes_are_not_confused_with_success(self):
        for result, expected in (
            ({"result": "incorrect"}, INCORRECT),
            ({"result": "expired"}, EXPIRED),
            ({"result": "CORRECT", "status": "pending"}, PENDING),
            ({"result": "accepted", "remaining": 0}, UNRESOLVED),
        ):
            with self.subTest(result=result):
                client = FakeClient(results=[result])
                self.assertEqual(self.run_robot(client), expected)

    def test_unknown_submission_result_is_an_error(self):
        client = FakeClient(results=[{"result": "MAYBE"}])
        with self.assertRaises(GameMasterError):
            self.run_robot(client)

    def test_changed_attempt_blocks_submission(self):
        client = FakeClient()
        def change(c):
            if c.status_calls >= 2:
                c.current["attempt_id"] = "two"
        client.change_on_status = change
        with self.assertRaisesRegex(GameMasterError, "changed"):
            self.run_robot(client)
        self.assertFalse(client.submissions)

    def test_changed_artifact_blocks_submission_without_server_hash(self):
        client = FakeClient()
        client.assignment.pop("artifact_sha256")
        client.current.pop("artifact_sha256")
        client.changed_bytes = b"different"
        with self.assertRaisesRegex(GameMasterError, "artifact changed"):
            self.run_robot(client)
        self.assertFalse(client.submissions)

    def test_identity_is_preserved_across_sparse_status_responses(self):
        client = FakeClient()
        client.assignment.pop("attempt_id")
        client.assignment.pop("artifact_sha256")
        client.current.pop("artifact_sha256")
        def change(c):
            if c.status_calls == 2:
                c.current.pop("attempt_id")
            elif c.status_calls == 3:
                c.current["attempt_id"] = "two"
        client.change_on_status = change
        with self.assertRaisesRegex(GameMasterError, "changed"):
            self.run_robot(client)
        self.assertFalse(client.submissions)

    def test_legacy_identity_free_response_rechecks_bytes(self):
        client = FakeClient()
        for snapshot in (client.assignment, client.current):
            snapshot.pop("artifact_sha256")
            snapshot.pop("attempt_id")
        self.assertEqual(self.run_robot(client), COMPLETE)
        self.assertEqual(client.downloads, 2)

    def test_hash_mismatch_aborts_before_solving(self):
        client = FakeClient()
        client.artifact_bytes = b"changed bytes"
        with self.assertRaisesRegex(GameMasterError, "SHA-256"):
            self.run_robot(client)
        self.assertFalse(client.submissions)

    def test_native_route_without_ids_is_preserved(self):
        client = FakeClient()
        client.assignment.pop("answer_ids")
        client.current.pop("answer_ids")
        self.assertEqual(self.run_robot(client), UNRESOLVED)
        self.assertFalse(client.downloads)

    def test_unknown_challenge_is_not_started(self):
        client = FakeClient()
        client.list_challenges = lambda: {"challenges": []}
        with self.assertRaises(GameMasterError):
            self.run_robot(client)
        self.assertFalse(client.starts)

    def test_conflicting_candidates_are_all_skipped_before_any_submit(self):
        class DisagreeingSolver:
            def solve(self, context):
                return [
                    AnswerCandidate("a", "one", "s", "e"),
                    AnswerCandidate("a", "two", "s", "e"),
                ]
        client = FakeClient()
        with patch("huntress_ctf.autopilot.SOLVERS", (DisagreeingSolver(),)):
            self.assertEqual(self.run_robot(client), CONFLICT)
        self.assertFalse(client.submissions)

    def test_uncertain_post_is_not_retried(self):
        client = FakeClient(results=[GameMasterError("Transport failed")])
        with self.assertRaises(GameMasterError):
            self.run_robot(client)
        self.assertEqual(len(client.submissions), 1)

    def test_scoring_pending_stops_further_mastery_answers(self):
        client = FakeClient(mastery=True, results=[{"result": "CORRECT", "status": "pending"}])
        self.assertEqual(self.run_robot(client), PENDING)
        self.assertEqual(len(client.submissions), 1)


if __name__ == "__main__":
    unittest.main()
