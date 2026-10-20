from contextlib import redirect_stderr, redirect_stdout
import getpass
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import warnings

from huntress_ctf.cli import main
from huntress_ctf.client import GameMasterClient, GameMasterError
from huntress_ctf.diagnostics import compare_routes, probe_pipelining, run_diagnostics, schema_summary


class DiagnosticsTests(unittest.TestCase):
    def client(self):
        client = Mock(spec=GameMasterClient)
        client.token = "private-test-token"
        client.base_url = "https://2026.huntress.ctf.games"
        client.api_schema.return_value = {
            "openapi": "3.1.0", "paths": {"/": {"get": {}, "post": {}}},
            "debug": "private-test-token", "token": "other-secret",
        }
        client.list_challenges.return_value = {"challenges": [
            {"id": "a", "mode": "single_solve"},
            {"id": "b", "mode": "time_trial"},
            {"id": "c", "mode": "mastery"},
        ]}
        client.status.side_effect = lambda challenge_id: {
            "state": "active", "answer_ids": [challenge_id],
            "expected_answer": "private-answer",
        }
        return client

    def assert_read_only(self, client):
        client.start.assert_not_called()
        client.retry.assert_not_called()
        client.submit.assert_not_called()
        client.artifact.assert_not_called()

    def test_three_modes_are_counted_without_starting_any_attempt(self):
        client = self.client()
        report, code = run_diagnostics(client, challenge_ids=("a", "b", "c", "a"))
        self.assertEqual(code, 0)
        self.assertTrue(report["ok"])
        self.assertEqual(report["checks"][1]["details"], {
            "count": 3, "modes": {"Single Solve": 1, "Time Trial": 1, "Mastery Mode": 1},
        })
        self.assertEqual(client.status.call_count, 3)
        self.assert_read_only(client)

    def test_captures_are_redacted_and_preserve_previous_runs(self):
        client = self.client()
        with tempfile.TemporaryDirectory() as directory:
            report, code = run_diagnostics(client, challenge_ids=("c",), output_root=Path(directory))
            self.assertEqual(code, 0)
            first = Path(report["capture_directory"])
            report2, _ = run_diagnostics(client, output_root=Path(directory))
            self.assertNotEqual(first, Path(report2["capture_directory"]))
            self.assertEqual({path.name for path in first.iterdir()}, {
                "schema.json", "challenges.json", "status-001.json", "report.json",
            })
            for path in first.iterdir():
                content = path.read_text(encoding="utf-8")
                self.assertNotIn("private-test-token", content)
                self.assertNotIn("other-secret", content)
                self.assertNotIn("private-answer", content)
            captured = json.loads((first / "schema.json").read_text(encoding="utf-8"))
            self.assertEqual(captured["source"], "live Game Master response")
            self.assertEqual(captured["response"]["token"], "[redacted]")

    def test_failed_schema_is_captured_for_adapter_work_but_does_not_pass(self):
        client = self.client()
        client.api_schema.return_value = {"schema": "different structure"}
        with tempfile.TemporaryDirectory() as directory:
            report, code = run_diagnostics(client, output_root=Path(directory))
            self.assertEqual(code, 1)
            self.assertFalse(report["ok"])
            self.assertEqual(report["checks"][0]["status"], "failed")
            self.assertTrue((Path(report["capture_directory"]) / "schema.json").is_file())
        self.assert_read_only(client)

    def test_missing_authentication_is_reported_without_mutations(self):
        client = self.client()
        client.api_schema.side_effect = GameMasterError("HTTP 401 private-test-token")
        client.list_challenges.side_effect = GameMasterError("HTTP 401")
        report, code = run_diagnostics(client, challenge_ids=("a",))
        self.assertEqual(code, 1)
        self.assertNotIn("private-test-token", json.dumps(report))
        self.assertEqual(report["checks"][-1]["status"], "skipped")
        client.status.assert_not_called()
        self.assert_read_only(client)

    def test_unknown_challenge_or_malformed_list_never_drives_status_requests(self):
        client = self.client()
        report, code = run_diagnostics(client, challenge_ids=("missing",))
        self.assertEqual(code, 1)
        client.status.assert_not_called()
        for response in ({"wrong": []}, [{"id": 1}], [{"id": "a"}, {"id": "a"}]):
            with self.subTest(response=response):
                client.list_challenges.return_value = response
                report, code = run_diagnostics(client, challenge_ids=("a",))
                self.assertEqual(code, 1)
                self.assertEqual(report["checks"][-1]["status"], "skipped")
        client.status.assert_not_called()

    def test_incompatible_status_is_reported_without_starting_or_retrying(self):
        client = self.client()
        client.status.side_effect = None
        client.status.return_value = {"answer_ids": [42]}
        report, code = run_diagnostics(client, challenge_ids=("a",))
        self.assertEqual(code, 1)
        self.assertEqual(report["checks"][-1]["status"], "failed")
        self.assert_read_only(client)

    def test_schema_summary_rejects_non_contract_responses(self):
        for response in ({}, [], {"openapi": "3.1.0", "paths": {}},
                         {"openapi": "3.1.0", "paths": {"/": {"$ref": "other"}}}):
            with self.subTest(response=response), self.assertRaises(GameMasterError):
                schema_summary(response)


class PipelineProbeTests(unittest.TestCase):
    STATUS = {"answer_ids": ["a"], "result": "CORRECT"}

    def probe(self, results, connected=True, pipelined_ms=10, sequential_ms=20):
        client = Mock(base_url="https://gm.example", connected=connected)
        client.pipeline.return_value = results
        now = [0.0]
        spans = [pipelined_ms, sequential_ms]
        ticks = []

        def clock():
            # Calls alternate begin/end; each round times the pipelined pair, then two singles.
            if len(ticks) % 2:
                now[0] += spans[(len(ticks) // 2) % 2] / 1000
            ticks.append(now[0])
            return now[0]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "network.json"
            report = probe_pipelining(client, challenge_id="c", network_path=path, clock=clock)
            saved = json.loads(path.read_text(encoding="utf-8"))["https://gm.example"]
        used = {name.split(".")[0] for name, _, _ in client.mock_calls}
        # Read-only: nothing can start, retry, or submit an attempt.
        self.assertLessEqual(used, {"close", "warm", "pipeline", "request"})
        for _, _, kwargs in client.request.mock_calls:
            self.assertNotIn("payload", kwargs)
        return report, saved

    def test_in_order_pair_on_a_kept_connection_passes_and_is_saved(self):
        report, saved = self.probe([self.STATUS, b"artifact bytes"])
        self.assertTrue(report["pipelining"])
        self.assertIn("saved_per_race_ms", report)
        self.assertTrue(saved["pipelining"])

    def test_correct_but_not_faster_stays_off(self):
        # Measured live: the server answers a pipelined pair one after the other.
        report, saved = self.probe([self.STATUS, b"artifact bytes"], pipelined_ms=1559, sequential_ms=1456)
        self.assertFalse(report["pipelining"])
        self.assertIn("saved -103.0 ms", report["reason"])
        self.assertFalse(saved["pipelining"])
        self.assertEqual(saved["sequential_pair_ms"], 1456.0)

    def test_failures_turn_pipelining_off(self):
        for results, connected, reason in (
            ([self.STATUS, GameMasterError("closed early")], True, "closed early"),
            ([self.STATUS, b"artifact bytes"], False, "closed the connection"),
            ([b"artifact bytes", self.STATUS], True, "status, then artifact"),
        ):
            with self.subTest(reason=reason):
                report, saved = self.probe(results, connected)
                self.assertFalse(report["pipelining"])
                self.assertIn(reason, report["reason"])
                self.assertFalse(saved["pipelining"])

    def test_compare_recommends_the_fastest_reachable_route(self):
        def unreachable():
            raise GameMasterError("Game Master transport failed while connecting.")
        result = compare_routes([
            ("direct", lambda: {"base_url": "https://d", "kept_alive_ms": {"median": 41.0}}),
            ("proxy", unreachable),
            ("other", lambda: {"base_url": "http://o", "kept_alive_ms": {"median": 3.5}}),
        ])
        self.assertEqual(result["recommended"]["route"], "other")
        self.assertIn("unavailable", result["routes"][1])


class HiddenInputTests(unittest.TestCase):
    def test_hidden_input_token_is_only_passed_to_client_and_never_printed(self):
        client = DiagnosticsTests().client()
        with patch("huntress_ctf.cli.getpass.getpass", return_value="private-test-token"):
            with patch("huntress_ctf.cli.GameMasterClient", return_value=client) as constructor:
                with redirect_stdout(StringIO()) as output:
                    code = main(["--prompt-token", "doctor"])
        self.assertEqual(code, 0)
        self.assertEqual(constructor.call_args.kwargs["token"], "private-test-token")
        self.assertNotIn("private-test-token", output.getvalue())

    def test_getpass_echo_fallback_is_refused(self):
        def unsafe_input(*args, **kwargs):
            warnings.warn("Cannot hide input", getpass.GetPassWarning)
            return "should-not-be-read"
        with patch("huntress_ctf.cli.getpass.getpass", side_effect=unsafe_input):
            with patch("huntress_ctf.cli.GameMasterClient") as constructor:
                with redirect_stderr(StringIO()) as error:
                    self.assertEqual(main(["--prompt-token", "doctor"]), 1)
                constructor.assert_not_called()
                self.assertIn("interactive terminal", error.getvalue())

    def test_empty_or_closed_input_fails_cleanly(self):
        for effect in (lambda *args: "", lambda *args: (_ for _ in ()).throw(EOFError())):
            with patch("huntress_ctf.cli.getpass.getpass", side_effect=effect):
                with redirect_stderr(StringIO()) as error:
                    self.assertEqual(main(["--prompt-token", "doctor"]), 1)
                self.assertNotIn("Traceback", error.getvalue())


if __name__ == "__main__":
    unittest.main()
