"""The safe-mode sweep (ROBUSTNESS.md workstream 6): one broken family, solver or lane never
takes the sweep down, and the summary names what was left out and why.

Synthetic routes only. The summary must stay one JSON object after "===== Summary =====":
release_report.py parses it that way, and homebase-day.sh greps it for '"outcome": "error"'.
"""

from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

from huntress_ctf.autopilot import COMPLETE, UNRESOLVED
from huntress_ctf.daily import run_daily

DAY = {"challenges": [
    {"id": "warmups-day-30", "lane": "warmups", "mode": "single_solve"},
    {"id": "warmups-day-30/time_trial", "lane": "warmups", "run_for_time_supported": True},
    {"id": "binary-day-30-x", "lane": "binary-reverse-engineering", "mode": "single_solve"},
    {"id": "binary-day-30-x/time_trial", "lane": "binary-reverse-engineering", "run_for_time_supported": True},
]}
PROBLEM = {"stage": "race", "solver": "binary-static-facts", "status": "timeout", "seconds": 90.0,
           "detail": "killed"}


class Client:
    """One day's list; `clone` and `close` can be made to fail."""

    token = None

    def __init__(self, failing_clones=0, failing_close=False):
        self.failing_clones = failing_clones
        self.failing_close = failing_close

    def list_challenges(self, day=None, lane=None):
        return DAY

    def clone(self):
        if self.failing_clones:
            self.failing_clones -= 1
            raise OSError("connection refused")
        return self

    def close(self):
        if self.failing_close:
            raise OSError("connection reset")


class SafeModeSweepTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def sweep(self, client, fake, **kwargs):
        """(code, the summary JSON, the text after the Summary marker)."""
        with redirect_stdout(StringIO()) as output, patch("huntress_ctf.daily.run_fast", side_effect=fake):
            code = run_daily(client, day=30, artifact_dir=self.root, work_dir=self.root / "work",
                             hints_path=self.root / "hints.json", **kwargs)
        tail = output.getvalue().rpartition("===== Summary =====")[2]
        return code, json.loads(tail), tail

    def test_a_family_without_a_connection_is_an_error_and_the_others_still_run(self):
        code, summary, _ = self.sweep(Client(failing_clones=1), lambda target, challenge_id, **k: COMPLETE)
        outcomes = {entry["challenge"]: entry["outcome"] for entry in summary["challenges"]}
        by_family = {}
        for challenge_id, outcome in outcomes.items():
            by_family.setdefault(challenge_id.split("/")[0], set()).add(outcome)
        # Which family's thread asked first is up to the scheduler: exactly one went without.
        self.assertEqual(sorted(map(sorted, by_family.values())), [["complete"], ["error"]])
        self.assertEqual(code, UNRESOLVED)
        held = summary["safe_mode"]["held_back"]
        self.assertEqual(len(held), 2)
        self.assertTrue(all("connection refused" in entry["reason"] for entry in held))

    def test_a_connection_that_fails_to_close_keeps_its_family_results(self):
        code, summary, _ = self.sweep(Client(failing_close=True), lambda target, challenge_id, **k: COMPLETE)
        self.assertEqual({entry["outcome"] for entry in summary["challenges"]}, {"complete"})
        self.assertEqual(code, COMPLETE)
        self.assertNotIn("safe_mode", summary)

    def test_solver_problems_blocked_modes_and_load_errors_are_named(self):
        def fake(target, challenge_id, report=None, **kwargs):
            if challenge_id == "binary-day-30-x":
                report["solver_problems"] = [PROBLEM]
                return UNRESOLVED
            return COMPLETE
        for workers in (4, 1):  # Families in parallel, then the sequential (timed) path.
            with patch("huntress_ctf.daily.LOAD_ERRORS", ["solvers.script: SyntaxError: bad input"]):
                _, summary, tail = self.sweep(Client(), fake, workers=workers)
            safe = summary["safe_mode"]
            self.assertEqual(safe["load_errors"], ["solvers.script: SyntaxError: bad input"])
            self.assertEqual(safe["solver_problems"], [{"challenge": "binary-day-30-x", **PROBLEM}])
            self.assertEqual(safe["held_back"], [{"challenge": "binary-day-30-x/time_trial",
                                                  "reason": "binary-day-30-x is not solved yet"}])
            # Nothing failed outright, so homebase-day.sh must not spend a retry on it.
            self.assertNotIn('"outcome": "error"', tail)

    def test_repeated_races_name_a_problem_once(self):
        def fake(target, challenge_id, report=None, **kwargs):
            report["solver_problems"] = [PROBLEM]
            return COMPLETE
        from huntress_ctf.hints import record_hint
        from huntress_ctf.solvers import AnswerCandidate
        record_hint("binary-day-30-x/time_trial", [AnswerCandidate("a", "x", "s", "e")], self.root / "hints.json")
        _, summary, _ = self.sweep(Client(), fake, timed=True, repeat=3)
        self.assertEqual(summary["safe_mode"]["solver_problems"],
                         [{"challenge": "binary-day-30-x/time_trial", **PROBLEM}])

    def test_a_quiet_sweep_keeps_the_old_summary(self):
        _, summary, _ = self.sweep(Client(), lambda target, challenge_id, **k: COMPLETE)
        self.assertEqual(set(summary), {"mode", "challenges", "wall_seconds"})


class RunFastReportTests(unittest.TestCase):
    """The problems daily shows come from run_fast's own report, filled by the watchdog."""

    def setUp(self):
        from test_watchdog import STOP, release_hangs
        STOP.clear()
        self.addCleanup(release_hangs)

    def test_a_killed_solver_and_a_warm_up_leftout_reach_the_report(self):
        from test_fastpath import FakeClient
        from test_watchdog import Answers, Hangs, HangsOnRealInput, race

        report = {}
        result, _, _ = race(FakeClient(StringIO()), (Hangs(), HangsOnRealInput(), Answers()), report=report)
        self.assertEqual(result, COMPLETE)
        found = {(p["stage"], p["solver"], p["status"]) for p in report["solver_problems"]}
        self.assertEqual(found, {("warm-up", "hangs", "timeout"), ("race", "hangs-on-real-input", "timeout")})
        self.assertTrue(all(isinstance(p["seconds"], float) for p in report["solver_problems"]))

    def test_a_clean_run_reports_no_problems(self):
        from test_fastpath import FakeClient
        from test_watchdog import Answers, race

        report = {}
        race(FakeClient(StringIO()), (Answers(),), report=report)
        self.assertNotIn("solver_problems", report)


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "release_report.py"


@unittest.skipUnless(SCRIPT.exists(), "scripts/release_report.py is not deployed here")
class ReleaseReportTests(unittest.TestCase):
    def test_the_report_prints_the_safe_mode_block(self):
        lines = runpy.run_path(str(SCRIPT))["safe_mode_lines"]({"safe_mode": {
            "load_errors": ["solvers.script: SyntaxError: bad input"],
            "solver_problems": [{"challenge": "binary-day-30-x", **PROBLEM}],
            "held_back": [{"challenge": "binary-day-30-x/time_trial", "reason": "binary-day-30-x is not solved yet"}],
        }})
        self.assertEqual(lines, [
            "solver module not loaded: solvers.script: SyntaxError: bad input",
            "binary-day-30-x: race: binary-static-facts timeout after 90.0 s (killed)",
            "binary-day-30-x/time_trial held back: binary-day-30-x is not solved yet",
        ])
        self.assertEqual(runpy.run_path(str(SCRIPT))["safe_mode_lines"]({"challenges": []}), [])


if __name__ == "__main__":
    unittest.main()
