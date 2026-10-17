from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from huntress_ctf import solvers
from huntress_ctf.autopilot import COMPLETE, UNRESOLVED
from huntress_ctf.daily import eligibility, run_daily
from huntress_ctf.hints import get_hint, record_hint
from huntress_ctf.solvers import AnswerCandidate

CHALLENGES = {"challenges": [
    {"id": "single", "mode": "single_solve"},
    {"id": "upgraded", "run_for_time_supported": True},
    {"id": "legacy-timed"},
]}


class ListOnlyClient:
    token = None

    def list_challenges(self, day=None, lane=None):
        return CHALLENGES


class HintTests(unittest.TestCase):
    def test_record_and_read_back(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state" / "hints.json"
            note = record_hint("c", [AnswerCandidate("a", "x", "layered-decode", "e", ("morse", "hex"))], path)
            self.assertIsNone(note)
            hint = get_hint("c", path)
            self.assertEqual(hint["solvers"], ["layered-decode"])
            self.assertEqual(hint["chain"], ["morse", "hex"])
            self.assertIsNone(get_hint("other", path))

    def test_unwritable_location_returns_a_note(self):
        with tempfile.TemporaryDirectory() as directory:
            blocker = Path(directory) / "file"
            blocker.write_text("x")
            note = record_hint("c", [AnswerCandidate("a", "x", "s", "e")], blocker / "hints.json")
            self.assertIn("Could not save", note)


class DailyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def run_daily(self, **kwargs):
        with redirect_stdout(StringIO()) as output:
            code = run_daily(
                ListOnlyClient(), artifact_dir=self.root, work_dir=self.root / "work",
                hints_path=self.root / "hints.json", **kwargs,
            )
        return code, output.getvalue()

    def test_untimed_runs_only_routes_that_cannot_start_a_timer(self):
        with patch("huntress_ctf.daily.run_autopilot", return_value=COMPLETE) as autopilot:
            code, output = self.run_daily()
        self.assertEqual([call.args[1] for call in autopilot.call_args_list], ["single", "upgraded"])
        self.assertEqual(code, COMPLETE)
        self.assertIn("an ordinary start may begin a timer", output)

    def test_timed_races_only_proven_supported_challenges(self):
        record_hint("upgraded", [AnswerCandidate("a", "x", "s", "e")], self.root / "hints.json")
        record_hint("single", [AnswerCandidate("a", "x", "s", "e")], self.root / "hints.json")
        with patch("huntress_ctf.daily.run_timed_fast", return_value=UNRESOLVED) as fast:
            code, output = self.run_daily(timed=True)
        self.assertEqual([call.args[1] for call in fast.call_args_list], ["upgraded"])
        self.assertEqual(code, UNRESOLVED)
        self.assertIn("does not advertise run_for_time_supported", output)

    def test_eligibility_reasons(self):
        self.assertEqual(eligibility({"id": "x", "run_for_time_supported": True}, True, {}),
                         "no proven solver yet; solve it untimed first")
        self.assertIsNone(eligibility({"id": "x", "mode": "Single Solve"}, False, {}))
        self.assertEqual(eligibility({}, False, {}), "no usable challenge ID")


class DiscoveryTests(unittest.TestCase):
    def test_broken_lane_is_reported_not_fatal(self):
        class Module:
            def __init__(self, name):
                self.name = name

        real_import = solvers.importlib.import_module

        def fake_import(name):
            if name.endswith(".broken"):
                raise SyntaxError("bad lane")
            return real_import(name)

        saved = list(solvers.LOAD_ERRORS)
        try:
            with patch.object(solvers.pkgutil, "iter_modules", return_value=[Module("broken"), Module("encoding")]), \
                    patch.object(solvers.importlib, "import_module", side_effect=fake_import):
                found = solvers._discover()
            self.assertTrue(any("broken" in error for error in solvers.LOAD_ERRORS))
            self.assertIn("layered-decode", [solver.name for solver in found])
        finally:
            solvers.LOAD_ERRORS[:] = saved


if __name__ == "__main__":
    unittest.main()
