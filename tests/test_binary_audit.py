"""The offline audit checks the issued hash and never prints candidate values."""
from contextlib import redirect_stdout, redirect_stderr
import hashlib
from io import StringIO
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

from tests.test_binary import pe_fixture


AUDIT = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "audit-binary.py"))


class BinaryAuditTests(unittest.TestCase):
    def saved(self, directory):
        artifact = directory / "artifact.bin"
        artifact.write_bytes(pe_fixture())
        path = directory / "assignment.json"
        path.write_text(json.dumps({
            "challenge": {"id": "binary-day-01", "lane": "binary"},
            "attempt": {"attempt_id": "synthetic", "answer_ids": ["arch", "unsupported"],
                        "accepted_ids": ["arch"],
                        "artifacts": [{"filename": "sample", "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}],
                        "questions": [{"id": "arch", "artifact": "sample", "question": "What is the architecture?"},
                                      {"id": "unsupported", "artifact": "sample", "question": "What arbitrary code runs?"}]},
        }), encoding="utf-8")
        return path, artifact

    def test_hash_checked_coverage_without_network_or_candidate_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            assignment, artifact = self.saved(Path(temporary))
            with patch("urllib.request.urlopen", side_effect=AssertionError("Network call")):
                report = AUDIT["audit"](assignment, artifact)
            self.assertEqual((report["questions"], report["candidates"], report["accepted_id_overlap"]), (2, 1, 1))
            self.assertEqual(report["missing_ids"], ["unsupported"])
            self.assertEqual(report["game_master_requests"], 0)
            self.assertNotIn("x86_64", json.dumps(report))

    def test_mismatched_hash_missing_hash_and_wrong_lane_reject_before_solving(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            assignment, artifact = self.saved(directory)
            original = json.loads(assignment.read_text())
            for changed in ("hash", "missing", "lane", "deliveries"):
                data = json.loads(json.dumps(original))
                if changed == "hash":
                    data["attempt"]["artifacts"][0]["sha256"] = "0" * 64
                elif changed == "missing":
                    data["attempt"]["artifacts"][0].pop("sha256")
                elif changed == "lane":
                    data["challenge"]["lane"] = "metadata-forensics"
                else:
                    data["attempt"]["artifacts"] *= 2
                assignment.write_text(json.dumps(data))
                with self.subTest(changed=changed), patch("huntress_ctf.solvers.binary.BinarySolver.solve") as solve:
                    with self.assertRaises(ValueError):
                        AUDIT["audit"](assignment, artifact)
                    solve.assert_not_called()

    def test_command_writes_report_and_reports_invalid_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            assignment, _ = self.saved(directory)
            report = directory / "coverage.json"
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(AUDIT["main"]([str(assignment), "--output", str(report)]), 0)
            self.assertEqual(json.loads(output.getvalue()), json.loads(report.read_text()))
            errors = StringIO()
            with redirect_stderr(errors):
                self.assertEqual(AUDIT["main"]([str(directory / "missing.json")]), 1)
            self.assertIn("Binary audit failed", errors.getvalue())
            data = json.loads(assignment.read_text())
            data["attempt"]["answer_ids"] = ["arch", "arch"]
            assignment.write_text(json.dumps(data))
            with redirect_stderr(StringIO()):
                self.assertEqual(AUDIT["main"]([str(assignment)]), 1)
