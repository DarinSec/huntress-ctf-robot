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
from huntress_ctf.diagnostics import run_diagnostics, schema_summary


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
