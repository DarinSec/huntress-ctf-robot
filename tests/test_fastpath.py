from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from io import StringIO
from itertools import count
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from huntress_ctf.autopilot import COMPLETE, CONFLICT, EXPIRED, INCORRECT, PENDING, UNRESOLVED
from huntress_ctf.client import GameMasterError
from huntress_ctf.fastpath import run_fast
from huntress_ctf.solvers import AnswerCandidate


class FakeClient:
    token = "private-test-token"

    def __init__(self, stdout, *, mastery=False, result=None):
        self.stdout = stdout
        self.artifact_bytes = b'{"answers":{"a":"one","b":"two"}}' if mastery else b"aGVsbG8="
        self.assignment = {
            "answer_ids": ["a", "b"] if mastery else ["a"],
            "attempt_id": "one",
            "artifact_sha256": hashlib.sha256(self.artifact_bytes).hexdigest(),
            "mode": "mastery" if mastery else "time_trial",
            "deadline": "2026-10-18T12:00:00Z",
            "instructions": (
                "Submit the JSON answer map." if mastery else "Decode the Base64 text."
            ),
        }
        self.result = result if result is not None else {"result": "CORRECT"}
        self.calls = []
        self.output_before_submit = None
        self.status_response = None

    def list_challenges(self):
        self.calls.append("list")
        return {"challenges": [{"id": "c", "name": "Puzzle", "run_for_time_supported": True}]}

    def status(self, challenge_id):
        self.calls.append("status")
        if self.status_response is not None:
            return deepcopy(self.status_response)
        return {**deepcopy(self.assignment), "state": "active"}

    def start(self, challenge_id, timed=False):
        self.calls.append(("start", timed))
        return deepcopy(self.assignment)

    def retry(self, challenge_id, timed=False):
        self.calls.append(("retry", timed))
        return deepcopy(self.assignment)

    def artifact(self, challenge_id):
        self.calls.append("artifact")
        return self.artifact_bytes

    def submit_many(self, challenge_id, answers):
        self.calls.append(("submit_many", dict(answers)))
        self.output_before_submit = self.stdout.getvalue()
        if isinstance(self.result, Exception):
            raise self.result
        return deepcopy(self.result)


class FastPathTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = StringIO()

    def run_fast(self, client, output=None, **kwargs):
        ticks = count()
        root = Path(self.directory.name)
        with redirect_stdout(output or self.output):
            return run_fast(
                client, "c", timed=True, artifact_dir=root, work_dir=root / "work",
                hints_path=root / "hints.json",
                **{"ntp": lambda: None, "clock": lambda: next(ticks) / 1000, **kwargs},
            )

    def pipelining_client(self, early=None):
        """A client on a route whose probe passed; `early` overrides the pipelined bytes."""
        client = FakeClient(self.output)
        client.base_url = "https://gm.example"
        (Path(self.directory.name) / "network.json").write_text(
            '{"https://gm.example": {"pipelining": true}}', encoding="utf-8",
        )

        def start_with_artifact(challenge_id, timed=False, retry=False):
            client.calls.append(("start_with_artifact", timed, retry))
            return deepcopy(client.assignment), client.artifact_bytes if early is None else early
        client.start_with_artifact = start_with_artifact
        return client

    def network_state(self):
        return (Path(self.directory.name) / "network.json").read_text(encoding="utf-8")

    def test_probed_route_pipelines_start_and_artifact(self):
        client = self.pipelining_client()
        self.assertEqual(self.run_fast(client), COMPLETE)
        self.assertEqual(client.calls, [
            "list", "status", ("start_with_artifact", True, False),
            ("submit_many", {"a": "hello"}), "status",
        ])
        self.assertIn('"pipelined": true', self.output.getvalue())
        self.assertIn('"pipelining": true', self.network_state())

    def test_unverifiable_pipelined_bytes_are_fetched_again_and_pipelining_stops(self):
        for early, reason in (
            (b"bytes of the previous attempt", "did not match"),
            (GameMasterError("HTTP 409"), "HTTP 409"),
        ):
            with self.subTest(reason=reason):
                client = self.pipelining_client(early)
                self.assertEqual(self.run_fast(client), COMPLETE)
                self.assertIn("artifact", client.calls)  # The ordinary GET after the pair.
                self.assertIn(("submit_many", {"a": "hello"}), client.calls)
                self.assertIn('"pipelining": false', self.network_state())
                self.assertIn(reason, self.network_state())

    def test_gate_waits_for_a_fast_server_and_never_spends_a_slow_variant(self):
        slow = count()
        pauses = []
        client = FakeClient(self.output)
        code = self.run_fast(client, clock=lambda: next(slow) * 0.5, gate_ms=100, gate_wait=60,
                             sleep=pauses.append)
        self.assertEqual(code, UNRESOLVED)
        self.assertEqual(pauses, [30.0, 30.0])
        self.assertFalse([c for c in client.calls if isinstance(c, tuple) and c[0] in ("start", "retry")])
        self.assertIn("No variant was spent", self.output.getvalue())
        fast = FakeClient(StringIO())
        self.assertEqual(self.run_fast(fast, StringIO(), gate_ms=100), COMPLETE)  # 1 ms per probe

    def test_hedged_download_lets_the_faster_connection_win_and_submit(self):
        import threading
        import time as real_time
        release = threading.Event()

        class Primary(FakeClient):
            def warm(self):
                pass

            def close(self):
                pass

            def clone(self):
                helper = Helper(self.stdout)
                helper.calls = self.helper_calls
                return helper

            def artifact(self, challenge_id, delivery=None):
                release.wait(2)  # Slow: answers only after the helper has won.
                return super().artifact(challenge_id)

        class Helper(Primary):
            def artifact(self, challenge_id, delivery=None):
                self.calls.append("artifact")
                return self.artifact_bytes

            def submit_many(self, challenge_id, answers):
                release.set()
                return super().submit_many(challenge_id, answers)

        client = Primary(self.output)
        client.helper_calls = []
        self.assertEqual(self.run_fast(client), COMPLETE)
        self.assertIn(("submit_many", {"a": "hello"}), client.helper_calls)  # The winner submitted.
        self.assertFalse([c for c in client.calls if c[0] == "submit_many"])
        self.assertEqual(client.calls[-1], "status")  # The report waited for the slow GET.

    def test_server_clock_is_placed_with_the_ntp_offset(self):
        from huntress_ctf.fastpath import Run, _server_clock
        run = Run(timed=True, clock_offset=5.0)  # The local clock runs 5 s fast.
        run.attempt = {"answer_ids": ["a"], "started_at": "2027-01-15T08:00:00.000Z"}
        started = datetime(2027, 1, 15, 8, 0, tzinfo=timezone.utc).timestamp()
        run.wall = {"submit sent": started + 5.0 + 1.145, "submit received": started + 5.0 + 2.921}
        self.assertEqual(_server_clock(run), {"from": 1145, "to": 2921})
        self.assertIsNone(_server_clock(Run(timed=True)))  # No NTP answer: no estimate.

    def test_start_response_link_is_used_for_the_download(self):
        for failing, expected_calls in ((False, ["download"]), (True, ["download", "artifact"])):
            with self.subTest(failing=failing):
                client = FakeClient(StringIO())
                client.assignment.pop("artifact_sha256")
                client.assignment.update(
                    download="/?op=download&capability=cap-123",
                    sha256=hashlib.sha256(client.artifact_bytes).hexdigest(),
                )

                def download(capability, client=client, failing=failing):
                    client.calls.append("download")
                    if failing:
                        raise GameMasterError("Game Master returned HTTP 404.")
                    self.assertEqual(capability, "cap-123")
                    return client.artifact_bytes
                client.download = download
                self.assertEqual(self.run_fast(client, StringIO()), COMPLETE)
                self.assertEqual([c for c in client.calls if c in ("download", "artifact")], expected_calls)

    def test_pipelining_can_be_switched_off(self):
        client = self.pipelining_client()
        self.assertEqual(self.run_fast(client, pipeline=False), COMPLETE)
        self.assertIn(("start", True), client.calls)
        self.assertNotIn(("start_with_artifact", True, False), client.calls)

    def test_only_start_artifact_and_one_submit_are_on_the_clock(self):
        client = FakeClient(self.output)
        self.assertEqual(self.run_fast(client), COMPLETE)
        self.assertEqual(client.calls, [
            "list", "status", ("start", True), "artifact",
            ("submit_many", {"a": "hello"}), "status",
        ])
        self.assertEqual(client.output_before_submit, "")
        report = self.output.getvalue()
        for expected in ("2026-10-18T12:00:00Z", "Time Trial", client.assignment["artifact_sha256"],
                         "timings_ms", "start_response_to_submit_response"):
            self.assertIn(expected, report)
        self.assertNotIn("private-test-token", report)
        self.assertEqual(len(list(Path(self.directory.name).glob("*.bin"))), 1)

    def test_mastery_answers_share_one_post(self):
        client = FakeClient(self.output, mastery=True)
        self.assertEqual(self.run_fast(client), COMPLETE)
        submits = [call for call in client.calls if call[0] == "submit_many"]
        self.assertEqual(submits, [("submit_many", {"a": "one", "b": "two"})])

    def test_already_accepted_answers_are_not_resent(self):
        client = FakeClient(self.output, mastery=True)
        client.assignment["accepted_answer_ids"] = ["a"]
        self.assertEqual(self.run_fast(client), COMPLETE)
        self.assertIn(("submit_many", {"b": "two"}), client.calls)

    def test_unsolved_attempt_is_preserved_and_reported(self):
        client = FakeClient(self.output)
        client.artifact_bytes = b"unrecognized"
        client.assignment["artifact_sha256"] = hashlib.sha256(b"unrecognized").hexdigest()
        self.assertEqual(self.run_fast(client), UNRESOLVED)
        self.assertFalse([call for call in client.calls if call[0] == "submit_many"])
        self.assertIn("clock keeps running", self.output.getvalue())

    def test_questions_are_printed_once(self):
        client = FakeClient(self.output)
        questions = [{"id": "a", "question": "Decode the Base64 text, question %d." % n} for n in range(3)]
        client.assignment["questions"] = questions
        client.status_response = {"attempt": {**client.assignment, "result": "CORRECT"}}
        client.status_response["attempt"].pop("deadline")
        self.run_fast(client)
        output = self.output.getvalue()
        self.assertEqual(output.count("question 2."), 1)
        self.assertIn("[3 questions, as in the assignment]", output)

    def test_web_targets_are_reported_without_a_download(self):
        client = self.pipelining_client()
        client.assignment = {
            "answer_ids": ["flag"], "attempt_id": "w", "state": "active",
            "targets": [{"name": "shop", "url": "http://10.1.2.3:8080/"}],
        }
        record = {"id": "c", "lane": "web-exploitation", "run_for_time_supported": True}
        root = Path(self.directory.name)
        with redirect_stdout(self.output):
            code = run_fast(client, "c", challenge=record, artifact_dir=root, work_dir=root / "work",
                            hints_path=root / "hints.json", ntp=lambda: None)
        self.assertEqual(code, UNRESOLVED)
        # No artifact GET and no pipelined pair, so pipelining stays on for the route.
        self.assertEqual(client.calls, [("start", False), "status"])
        self.assertIn('"pipelining": true', self.network_state())
        self.assertIn("http://10.1.2.3:8080/", self.output.getvalue())
        self.assertIn("need a Web solver", self.output.getvalue())

    def test_conflicting_candidates_are_not_submitted(self):
        class DisagreeingSolver:
            def solve(self, context):
                return [AnswerCandidate("a", "one", "s", "e"), AnswerCandidate("a", "two", "s", "e")]
        client = FakeClient(self.output)
        with patch("huntress_ctf.fastpath.SOLVERS", (DisagreeingSolver(),)):
            self.assertEqual(self.run_fast(client), CONFLICT)
        self.assertFalse([call for call in client.calls if call[0] == "submit_many"])
        self.assertIn("disagree", self.output.getvalue())

    def test_hash_mismatch_aborts_before_submit_but_still_reports(self):
        client = FakeClient(self.output)
        client.artifact_bytes = b"changed bytes"
        with self.assertRaisesRegex(GameMasterError, "SHA-256"):
            self.run_fast(client)
        self.assertFalse([call for call in client.calls if call[0] == "submit_many"])
        self.assertIn("Assignment:", self.output.getvalue())

    def test_terminal_start_does_not_download_or_submit(self):
        for state, expected in (
            ({"result": "CORRECT"}, COMPLETE),
            ({"result": "CORRECT", "status": "pending"}, PENDING),
            ({"state": "expired"}, EXPIRED),
            ({"state": "locked"}, UNRESOLVED),
        ):
            with self.subTest(state=state):
                client = FakeClient(StringIO())
                client.status_response = {"state": "not_started"}
                client.assignment.update(state)
                self.assertEqual(self.run_fast(client, StringIO()), expected)
                self.assertNotIn("artifact", client.calls)

    def test_submission_outcomes(self):
        for result, expected in (
            ({"result": "incorrect"}, INCORRECT),
            ({"result": "expired"}, EXPIRED),
            ({"result": "CORRECT", "status": "pending"}, PENDING),
            ({"result": "accepted", "remaining": 1}, UNRESOLVED),
        ):
            with self.subTest(result=result):
                self.assertEqual(self.run_fast(FakeClient(StringIO(), result=result)), expected)
        with self.assertRaises(GameMasterError):
            self.run_fast(FakeClient(StringIO(), result={"result": "MAYBE"}))

    def test_uncertain_submit_is_not_retried(self):
        client = FakeClient(self.output, result=GameMasterError("Transport failed"))
        with self.assertRaises(GameMasterError):
            self.run_fast(client)
        self.assertEqual(len([call for call in client.calls if call[0] == "submit_many"]), 1)

    def test_completed_attempt_races_through_timed_retry(self):
        client = FakeClient(self.output)
        client.status_response = {"answer_ids": ["a"], "result": "CORRECT", "ranked_attempts_remaining": 2}
        self.assertEqual(self.run_fast(client), COMPLETE)
        self.assertIn(("retry", True), client.calls)
        self.assertNotIn(("start", True), client.calls)
        self.assertIn("Route: retry", self.output.getvalue())

    def test_routes_that_must_not_start_a_timer(self):
        for status, expected, reason in (
            ({"result": "CORRECT", "status": "pending"}, PENDING, "pending"),
            ({"answer_ids": ["a"], "attempt_id": "one", "state": "active"}, UNRESOLVED, "untimed"),
            ({"result": "CORRECT", "ranked_attempts_remaining": 0}, UNRESOLVED, "No fresh timed variant"),
        ):
            with self.subTest(reason=reason):
                client = FakeClient(StringIO())
                client.status_response = status
                output = StringIO()
                self.assertEqual(self.run_fast(client, output), expected)
                self.assertEqual(client.calls, ["list", "status"])
                self.assertIn(reason, output.getvalue())

    def test_proven_solver_runs_alone_and_hint_is_recorded(self):
        class Proven:
            name = "proven"
            def solve(self, context):
                return [AnswerCandidate("a", "hello", self.name, "e", ("base64",))]

        class MustNotRun:
            name = "other"
            calls = 0
            def solve(self, context):
                if context.challenge_id != "warm-up":
                    MustNotRun.calls += 1
                return []

        hints_path = Path(self.directory.name) / "hints.json"
        hints_path.write_text('{"c": {"solvers": ["proven"], "chain": []}}', encoding="utf-8")
        client = FakeClient(self.output)
        with patch("huntress_ctf.fastpath.SOLVERS", (MustNotRun(), Proven())):
            self.assertEqual(self.run_fast(client), COMPLETE)
        self.assertEqual(MustNotRun.calls, 0)
        self.assertIn("other solvers were skipped", self.output.getvalue())
        self.assertIn('"proven"', hints_path.read_text(encoding="utf-8"))

    def test_correct_answer_records_hint_and_gc_is_restored(self):
        import gc
        client = FakeClient(self.output)
        self.assertTrue(gc.isenabled())
        self.assertEqual(self.run_fast(client), COMPLETE)
        self.assertTrue(gc.isenabled())
        hints = (Path(self.directory.name) / "hints.json").read_text(encoding="utf-8")
        self.assertIn("base64-answer", hints)

    def test_unsolved_run_writes_a_workspace(self):
        client = FakeClient(self.output)
        client.artifact_bytes = b"unrecognized"
        client.assignment["artifact_sha256"] = hashlib.sha256(b"unrecognized").hexdigest()
        self.assertEqual(self.run_fast(client), UNRESOLVED)
        triage = Path(self.directory.name) / "work" / "c" / "triage.md"
        self.assertTrue(triage.is_file())
        self.assertIn("triage.md", self.output.getvalue())

    def test_unavailable_pre_start_status_does_not_block_the_run(self):
        client = FakeClient(self.output)
        calls = []

        def status(challenge_id):
            calls.append(challenge_id)
            if len(calls) == 1:
                raise GameMasterError("Game Master returned HTTP 404.")
            return {"state": "complete", "result": "CORRECT"}
        client.status = status
        self.assertEqual(self.run_fast(client), COMPLETE)
        self.assertIn("HTTP 404", self.output.getvalue())


if __name__ == "__main__":
    unittest.main()
