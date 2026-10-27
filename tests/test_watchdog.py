"""The watchdog (ROBUSTNESS.md workstream 1): a hanging or crashing solver never stops the others.

Synthetic solvers only: one hangs forever, one raises, one answers. The acceptance test runs a
whole timed race through run_fast with the hanging solver registered and checks that the good
answer is still submitted.
"""

from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
from itertools import count
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from huntress_ctf import watchdog
from huntress_ctf.autopilot import COMPLETE
from huntress_ctf.solvers import AnswerCandidate

STOP = threading.Event()  # Lets an abandoned thread-mode hang end when its test is done.


def release_hangs():
    """Test cleanup: end every abandoned hang before the next test clears STOP again (otherwise
    an old thread that had not yet seen STOP keeps hanging into later tests)."""
    STOP.set()
    for thread in threading.enumerate():
        if thread.name.startswith("solver-"):
            thread.join(5)


class Hangs:
    name = "hangs"

    def solve(self, context):
        STOP.wait()  # Hangs without burning a core: busy loops starved the parent on a 4-vCPU VM.
        return []


class HangsOnRealInput:
    """Fine on warm-up's dummy, loops forever on a real artifact: the case only the race can catch."""

    name = "hangs-on-real-input"

    def solve(self, context):
        if context.challenge_id == "warm-up":
            return []
        STOP.wait()  # Hangs without burning a core: busy loops starved the parent on a 4-vCPU VM.
        return []


class Counts:
    """Counts its calls in this process: shows warm-up still runs here."""

    name = "counts"
    calls = 0

    def solve(self, context):
        Counts.calls += 1
        return []


class Crashes:
    name = "crashes"

    def solve(self, context):
        raise ValueError("a never-seen header")


class Answers:
    def __init__(self, answer_id="a", answer="hello", name="answers"):
        self.answer_id, self.answer, self.name = answer_id, answer, name

    def solve(self, context):
        return [AnswerCandidate(self.answer_id, self.answer, self.name, "synthetic")]


def statuses(outcomes):
    return {outcome.solver: outcome.status for outcome in outcomes}


@unittest.skipUnless("fork" in __import__("multiprocessing").get_all_start_methods(), "needs fork")
class ForkedWatchdogTests(unittest.TestCase):
    def setUp(self):
        STOP.clear()  # A child inherits STOP as it is at the fork: set, a hang would just return.
        self.addCleanup(release_hangs)

    def test_a_hang_is_killed_after_its_budget_and_the_others_still_answer(self):
        began = time.monotonic()
        found, outcomes = watchdog.run_solvers(
            [Answers("a", "one", "first"), Hangs(), Answers("b", "two", "last")], None, budget=0.5, mode="fork")
        self.assertLess(time.monotonic() - began, 5)
        self.assertEqual([(c.answer_id, c.answer) for c in found], [("a", "one"), ("b", "two")])  # Solver order.
        self.assertEqual(statuses(outcomes), {"first": "ok", "hangs": "timeout", "last": "ok"})
        self.assertIn("killed", next(o for o in outcomes if o.solver == "hangs").detail)

    def test_a_crash_is_reported_not_raised(self):
        found, outcomes = watchdog.run_solvers([Crashes(), Answers()], None, budget=5, mode="fork")
        self.assertEqual([c.answer for c in found], ["hello"])
        crash = next(o for o in outcomes if o.solver == "crashes")
        self.assertEqual(crash.status, "crashed")
        self.assertIn("ValueError: a never-seen header", crash.detail)

    def test_the_race_deadline_caps_every_solver_and_skips_what_cannot_start(self):
        began = time.monotonic()
        found, outcomes = watchdog.run_solvers(
            [Hangs(), Hangs(), Answers()], None, budget=60, deadline=time.monotonic() + 0.6, mode="fork", parallel=2)
        self.assertLess(time.monotonic() - began, 5)  # Not 60 s: the deadline wins.
        self.assertEqual(found, [])
        self.assertEqual([o.status for o in outcomes], ["timeout", "timeout", "skipped"])

    def test_a_child_that_lingers_after_answering_is_reaped(self):
        class Lingers:
            name = "lingers"

            def solve(self, context):
                threading.Thread(target=time.sleep, args=(30,)).start()  # Non-daemon: holds its process open.
                return [AnswerCandidate("a", "kept", self.name, "synthetic")]
        began = time.monotonic()
        found, outcomes = watchdog.run_solvers([Lingers()], None, budget=10, mode="fork")
        self.assertLess(time.monotonic() - began, 5)
        self.assertEqual([c.answer for c in found], ["kept"])
        self.assertEqual(statuses(outcomes), {"lingers": "ok"})
        self.assertEqual(__import__("multiprocessing").active_children(), [])  # No process left behind.

    def test_children_run_in_parallel(self):
        class Sleeps:
            def __init__(self, name):
                self.name = name

            def solve(self, context):
                time.sleep(0.4)
                return []
        began = time.monotonic()
        watchdog.run_solvers([Sleeps(f"s{i}") for i in range(4)], None, budget=5, mode="fork", parallel=4)
        self.assertLess(time.monotonic() - began, 1.2)  # Four 0.4 s solvers, not 1.6 s in a row.


class ThreadAndOffModeTests(unittest.TestCase):
    def setUp(self):
        STOP.clear()
        self.addCleanup(release_hangs)

    def test_thread_mode_abandons_a_hang_and_reports_a_crash(self):
        began = time.monotonic()
        found, outcomes = watchdog.run_solvers([Hangs(), Crashes(), Answers()], None, budget=0.3, mode="thread")
        self.assertLess(time.monotonic() - began, 3)
        self.assertEqual([c.answer for c in found], ["hello"])
        self.assertEqual(statuses(outcomes), {"hangs": "timeout", "crashes": "crashed", "answers": "ok"})

    def test_off_mode_still_isolates_a_crash(self):
        found, outcomes = watchdog.run_solvers([Crashes(), Answers()], None, mode="off")
        self.assertEqual([c.answer for c in found], ["hello"])
        self.assertEqual(statuses(outcomes), {"crashes": "crashed", "answers": "ok"})

    def test_budget_comes_from_the_environment(self):
        with patch.dict(os.environ, {"HUNTRESS_SOLVER_BUDGET": "2.5"}):
            self.assertEqual(watchdog.default_budget(), 2.5)
        with patch.dict(os.environ, {"HUNTRESS_SOLVER_BUDGET": "soon"}):
            self.assertEqual(watchdog.default_budget(), watchdog.SOLVER_BUDGET_S)


class RaceDeadlineTests(unittest.TestCase):
    def test_a_future_deadline_keeps_the_submit_margin(self):
        ends = datetime.now(timezone.utc) + timedelta(seconds=30)
        cap = watchdog.race_deadline(ends.isoformat().replace("+00:00", "Z"))
        self.assertAlmostEqual(cap - time.monotonic(), 30 - watchdog.SUBMIT_MARGIN_S, delta=1)

    def test_no_usable_deadline_means_the_plain_budget(self):
        past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        for value in (None, "", "tomorrow", past, "2099-01-01T00:00:00Z"):
            self.assertIsNone(watchdog.race_deadline(value), value)


def race(client, solvers, **extra):
    """One timed run_fast on a FakeClient with these solvers registered: (result, output, seconds)."""
    from huntress_ctf.fastpath import run_fast

    output = StringIO()
    client.stdout = output
    ticks = count()
    with tempfile.TemporaryDirectory() as directory, redirect_stdout(output), \
            patch.dict(os.environ, {"HUNTRESS_SOLVER_BUDGET": "0.5"}), \
            patch("huntress_ctf.fastpath.WARM_UP_BUDGET_S", 0.3), \
            patch("huntress_ctf.fastpath.SOLVERS", tuple(solvers)):
        root = Path(directory)
        began = time.monotonic()
        result = run_fast(client, "c", timed=True, artifact_dir=root, work_dir=root / "work",
                          hints_path=root / "hints.json", clock=lambda: next(ticks) / 1000,
                          **{"ntp": lambda: None, **extra})
    return result, output.getvalue(), time.monotonic() - began


class RaceAcceptanceTests(unittest.TestCase):
    """ROBUSTNESS.md: a solver that loops forever is abandoned, the race finishes and submits."""

    def setUp(self):
        STOP.clear()
        self.addCleanup(release_hangs)

    def client(self):
        from test_fastpath import FakeClient
        return FakeClient(StringIO())

    def test_a_solver_that_hangs_on_the_real_artifact_is_killed_and_the_race_submits(self):
        client = self.client()
        result, output, seconds = race(client, (HangsOnRealInput(), Crashes(), Answers()))
        self.assertLess(seconds, 10)
        self.assertEqual(result, COMPLETE)
        self.assertIn(("submit_many", {"a": "hello"}), client.calls)
        self.assertIn("watchdog: hangs-on-real-input timeout", output)
        self.assertIn("watchdog: crashes crashed", output)

    def test_a_solver_that_hangs_on_warm_up_is_left_out_before_the_clock(self):
        client = self.client()
        result, output, seconds = race(client, (Hangs(), Answers()))
        self.assertEqual(result, COMPLETE)
        self.assertIn(("submit_many", {"a": "hello"}), client.calls)
        self.assertIn("warm-up: watchdog: hangs timeout", output)
        self.assertIn("left out of this run", output)
        self.assertNotIn("watchdog: hangs timeout after 0.5", output)  # Never raced, so no race budget spent.

    def test_the_race_deadline_uses_the_ntp_corrected_clock(self):
        # This machine's clock runs 20 s fast (ntp() says so). The server's deadline is 60 s away in
        # true time, so the race may solve for 60 - SUBMIT_MARGIN_S s, not 40 - SUBMIT_MARGIN_S.
        client = self.client()
        client.assignment["deadline"] = datetime.fromtimestamp(time.time() - 20 + 60, timezone.utc) \
            .isoformat().replace("+00:00", "Z")
        seen = []
        real = watchdog.run_solvers

        def spy(solvers, context, **kwargs):
            if "deadline" in kwargs:
                seen.append(kwargs["deadline"] - time.monotonic())
            return real(solvers, context, **kwargs)
        with patch("huntress_ctf.fastpath.run_solvers", spy):
            result, _, _ = race(client, (Answers(),), ntp=lambda: 20.0)
        self.assertEqual(result, COMPLETE)
        self.assertTrue(seen)
        self.assertAlmostEqual(seen[0], 60 - watchdog.SUBMIT_MARGIN_S, delta=3)


class WarmUpTests(unittest.TestCase):
    def setUp(self):
        STOP.clear()
        self.addCleanup(release_hangs)
        Counts.calls = 0

    def test_warm_up_leaves_out_only_a_hang_and_still_warms_this_process(self):
        from huntress_ctf.fastpath import warm_up

        output = StringIO()
        began = time.monotonic()
        with redirect_stdout(output), patch("huntress_ctf.fastpath.WARM_UP_BUDGET_S", 0.3):
            fit = warm_up((Hangs(), Crashes(), Counts()))
        self.assertLess(time.monotonic() - began, 3)
        # A crash on the dummy input was always fine (many solvers reject it); only the hang goes.
        self.assertEqual([watchdog.solver_name(s) for s in fit], ["crashes", "counts"])
        self.assertIn("left out of this run", output.getvalue())
        self.assertGreaterEqual(Counts.calls, 1)  # Warmed here, so the race's children inherit it.
        if "fork" in __import__("multiprocessing").get_all_start_methods():
            # The hang was caught in a child and killed: nothing keeps spinning in this process.
            self.assertFalse([t for t in threading.enumerate() if t.name == "solver-hangs" and t.is_alive()])


if __name__ == "__main__":
    unittest.main()
