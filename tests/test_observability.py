"""Observability (ROBUSTNESS.md workstream 5): per-solver timings in every route, the day's
slowest solvers in the sweep summary, and a replay that fails when a solver got much slower
than in the previous replay or broke on an entry it ran fine on.

Synthetic solvers only: one sleeps, one is slow only the first time (a busy machine), one raises.
"""

from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import runpy
import tempfile
import time
import unittest
from unittest.mock import patch

from huntress_ctf import corpus
from huntress_ctf.autopilot import COMPLETE
from huntress_ctf.daily import run_daily
from test_corpus import assignment, evidence
from test_safe_mode import Client

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


class Sleeps:
    def __init__(self, name, seconds):
        self.name, self.seconds = name, seconds

    def solve(self, context):
        time.sleep(self.seconds)
        return []


class SlowOnce:
    """Slow on its first call only. The mark is a file: each call runs in a forked child."""

    name = "slow-once"

    def __init__(self, mark):
        self.mark = mark

    def solve(self, context):
        if not self.mark.exists():
            self.mark.write_text("seen")
            time.sleep(0.6)
        return []


class Crashes:
    name = "crashes"

    def solve(self, context):
        raise ValueError("a never-seen header")


class CorpusBudgetTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        challenge, attempt = assignment()
        self.entry = corpus.record(challenge["id"], challenge, attempt, evidence(), (), {"roster-size-bytes": "19"},
                                   root=self.root)

    def replay(self, solvers, previous=None, keep=True):
        if previous is not None:
            (self.entry / "last_timing.json").write_text(json.dumps(previous))
        with patch("huntress_ctf.solvers.SOLVERS", tuple(solvers)), redirect_stdout(StringIO()):
            return corpus.replay(self.entry, keep=keep)

    def test_each_solver_is_timed_and_the_timing_kept_for_the_next_replay(self):
        report = self.replay([Sleeps("quick", 0.0), Sleeps("steady", 0.05)])
        self.assertEqual(set(report["seconds"]), {"quick", "steady"})
        self.assertGreaterEqual(report["seconds"]["steady"], 0.05)
        self.assertEqual(set(json.loads((self.entry / "last_timing.json").read_text())), {"quick", "steady"})
        self.assertEqual((report["slower"], report["broke"]), ({}, []))  # No previous timing: nothing to compare.

    def test_a_solver_much_slower_than_in_the_previous_replay_is_over_its_budget(self):
        report = self.replay([Sleeps("slowpoke", 0.4), Sleeps("steady", 0.0)], previous={"slowpoke": 0.05, "steady": 0.01})
        self.assertEqual(set(report["slower"]), {"slowpoke"})
        slower = report["slower"]["slowpoke"]
        self.assertEqual((slower["previous"], slower["budget"]), (0.05, corpus.SLOW_FLOOR_S))
        self.assertGreater(slower["seconds"], corpus.SLOW_FLOOR_S)

    def test_slower_but_within_twice_or_the_floor_is_fine(self):
        report = self.replay([Sleeps("small", 0.1), Sleeps("big", 0.3)], previous={"small": 0.01, "big": 0.2})
        self.assertEqual(report["slower"], {})  # small: under the 0.25 s floor; big: under 2 x 0.2 s.

    def test_a_one_off_slow_measurement_is_timed_again_before_it_counts(self):
        mark = self.root / "seen"
        report = self.replay([SlowOnce(mark)], previous={"slow-once": 0.01})
        self.assertTrue(mark.exists())
        self.assertEqual(report["slower"], {})
        self.assertLess(json.loads((self.entry / "last_timing.json").read_text())["slow-once"], 0.3)  # The faster one.

    def test_a_solver_that_ran_fine_last_time_and_now_crashes_broke(self):
        report = self.replay([Crashes()], previous={"crashes": 0.01})
        self.assertEqual(len(report["broke"]), 1)
        self.assertIn("watchdog: crashes crashed", report["broke"][0])
        # One that never ran fine on this entry is reported, but nothing it did before broke.
        (self.entry / "last_timing.json").unlink()
        self.assertEqual(self.replay([Crashes()])["broke"], [])

    def test_a_dry_replay_compares_but_keeps_the_previous_timing(self):
        self.replay([Sleeps("slowpoke", 0.4)], previous={"slowpoke": 0.05}, keep=False)
        self.assertEqual(json.loads((self.entry / "last_timing.json").read_text()), {"slowpoke": 0.05})


@unittest.skipUnless((SCRIPTS / "replay.py").exists(), "scripts/replay.py is not deployed here")
class ReplayScriptTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        challenge, attempt = assignment()
        self.entry = corpus.record(challenge["id"], challenge, attempt, evidence(), (), {"roster-size-bytes": "19"},
                                   root=self.root)
        (self.entry / "last_timing.json").write_text(json.dumps({"slowpoke": 0.05}))

    def main(self, *argv, env=None):
        output = StringIO()
        with patch("huntress_ctf.solvers.SOLVERS", (Sleeps("slowpoke", 0.4),)), redirect_stdout(output), \
                patch.dict(os.environ, env or {}):
            code = runpy.run_path(str(SCRIPTS / "replay.py"))["main"](["--corpus", str(self.root), "--dry", *argv])
        return code, output.getvalue()

    def test_a_slower_solver_fails_the_replay_unless_allowed(self):
        code, output = self.main()
        self.assertEqual(code, 1)
        self.assertIn("SLOWER", output)
        self.assertIn("slower: slowpoke", output)
        self.assertIn("slowest solvers: slowpoke", output)
        self.assertEqual(self.main("--allow-slower")[0], 0)
        self.assertEqual(self.main(env={"HUNTRESS_ALLOW_SLOWER": "1"})[0], 0)  # As homebase.sh deploy passes it.


class SweepTimingTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def test_run_fast_reports_every_solver_time(self):
        from test_fastpath import FakeClient
        from test_watchdog import Answers, race

        report = {}
        result, output, _ = race(FakeClient(StringIO()), (Sleeps("steady", 0.05), Answers()), report=report)
        self.assertEqual(result, COMPLETE)
        self.assertEqual(set(report["solver_ms"]), {"steady", "answers"})
        self.assertGreaterEqual(report["solver_ms"]["steady"], 50)
        self.assertIn('"solver_ms"', output)  # In the route's printed timings_ms.

    def test_the_summary_names_the_slowest_solvers_of_the_day(self):
        times = {
            "warmups-day-30": {"warmup-blobs": 3.0, "layered-decode": 40.0},
            "warmups-day-30/time_trial": {"warmup-blobs": 9.0},
            "binary-day-30-x": {"binary-static-facts": 1200.0, "a": 1.0, "b": 2.0, "c": 5.0},
            "binary-day-30-x/time_trial": {"binary-static-facts": 900.0},
        }

        def fake(target, challenge_id, report=None, **kwargs):
            report["solver_ms"] = times[challenge_id]
            return COMPLETE
        with redirect_stdout(StringIO()) as output, patch("huntress_ctf.daily.run_fast", side_effect=fake):
            run_daily(Client(), day=30, artifact_dir=self.root, work_dir=self.root / "work",
                      hints_path=self.root / "hints.json")
        summary = json.loads(output.getvalue().rpartition("===== Summary =====")[2])
        # One line per solver, at its slowest route; the five slowest.
        self.assertEqual(summary["slowest_solvers"], [
            {"solver": "binary-static-facts", "ms": 1200.0, "challenge": "binary-day-30-x"},
            {"solver": "layered-decode", "ms": 40.0, "challenge": "warmups-day-30"},
            {"solver": "warmup-blobs", "ms": 9.0, "challenge": "warmups-day-30/time_trial"},
            {"solver": "c", "ms": 5.0, "challenge": "binary-day-30-x"},
            {"solver": "b", "ms": 2.0, "challenge": "binary-day-30-x"},
        ])

    @unittest.skipUnless((SCRIPTS / "release_report.py").exists(), "scripts/release_report.py is not deployed here")
    def test_the_release_report_prints_one_slowest_line(self):
        line = runpy.run_path(str(SCRIPTS / "release_report.py"))["slowest_line"]({"slowest_solvers": [
            {"solver": "binary-static-facts", "ms": 1200.0, "challenge": "binary-day-30-x"},
            {"solver": "layered-decode", "ms": 40.0, "challenge": "warmups-day-30"},
        ]})
        self.assertEqual(line, "slowest solvers: binary-static-facts 1200 ms (binary-day-30-x), "
                               "layered-decode 40 ms (warmups-day-30)")
        self.assertIsNone(runpy.run_path(str(SCRIPTS / "release_report.py"))["slowest_line"]({}))


if __name__ == "__main__":
    unittest.main()
