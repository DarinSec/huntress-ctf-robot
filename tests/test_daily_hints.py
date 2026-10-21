from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from huntress_ctf import solvers
from huntress_ctf.autopilot import COMPLETE, UNRESOLVED
from huntress_ctf.client import GameMasterError
from huntress_ctf.daily import eligibility, families, run_daily, wait_for_release
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
        with patch("huntress_ctf.daily.run_fast", return_value=COMPLETE) as fast:
            code, output = self.run_daily()
        self.assertEqual([call.args[1] for call in fast.call_args_list], ["single", "upgraded"])
        self.assertEqual({call.kwargs["timed"] for call in fast.call_args_list}, {False})
        # The record from daily's own list is reused instead of listing again per challenge.
        self.assertEqual(fast.call_args_list[0].kwargs["challenge"], CHALLENGES["challenges"][0])
        self.assertEqual(code, COMPLETE)
        self.assertIn("an ordinary start may begin a timer", output)

    def test_timed_races_only_proven_supported_challenges(self):
        record_hint("upgraded", [AnswerCandidate("a", "x", "s", "e")], self.root / "hints.json")
        record_hint("single", [AnswerCandidate("a", "x", "s", "e")], self.root / "hints.json")
        with patch("huntress_ctf.daily.run_fast", return_value=UNRESOLVED) as fast:
            code, output = self.run_daily(timed=True)
        self.assertEqual([call.args[1] for call in fast.call_args_list], ["upgraded"])
        self.assertTrue(fast.call_args_list[0].kwargs["timed"])
        self.assertEqual(code, UNRESOLVED)
        self.assertIn("this route has no timed mode", output)
        # An older Time Trial route is timed by default, so a proven one races too.
        legacy = {"id": "w/time_trial", "mode": "time_trial", "run_for_time_supported": False}
        self.assertIsNone(eligibility(legacy, True, {"w/time_trial": {}}))
        # A new day: the proven Single Solve of a course lane lets its timed routes race.
        new_day = {"id": "warmups-day-20/mastery", "lane": "warmups", "mode": "mastery"}
        self.assertIsNone(eligibility(new_day, True, {"warmups-day-20": {}}))
        self.assertIsNotNone(eligibility(new_day, True, {}))
        other_lane = {"id": "binary-day-20-x/mastery", "lane": "binary-reverse-engineering", "mode": "mastery"}
        self.assertIsNotNone(eligibility(other_lane, True, {"binary-day-20-x": {}}))

    def test_eligibility_reasons(self):
        self.assertEqual(eligibility({"id": "x", "run_for_time_supported": True}, True, {}),
                         "no proven solver yet; solve it untimed first")
        self.assertIsNone(eligibility({"id": "x", "mode": "Single Solve"}, False, {}))
        self.assertEqual(eligibility({}, False, {}), "no usable challenge ID")
        solved = {"id": "x", "mode": "single_solve", "solved": True}
        self.assertEqual(eligibility(solved, False, {}), "already solved")
        # A timed race of a solved challenge is the point of a proven solver.
        self.assertIsNone(eligibility({**solved, "run_for_time_supported": True}, True, {"x": {}}))


DAY = {"challenges": [
    {"id": "binary-day-21-x/mastery", "lane": "binary", "run_for_time_supported": True},
    {"id": "warmups-day-21", "lane": "warmups", "mode": "single_solve"},
    {"id": "binary-day-21-x", "lane": "binary", "mode": "single_solve"},
    {"id": "warmups-day-21/time_trial", "lane": "warmups", "run_for_time_supported": True},
    {"id": "binary-day-21-x/time_trial", "lane": "binary", "run_for_time_supported": True},
    {"id": "web-exploitation-day-21-y", "lane": "web-exploitation", "mode": "single_solve"},
]}


class DayClient:
    token = None

    def __init__(self, released_after=0):
        self.lists = []
        self.released_after = released_after
        self.clones = 0

    def list_challenges(self, day=None, lane=None):
        self.lists.append((day, lane))
        if len(self.lists) <= self.released_after:
            return {"challenges": []}
        return {"challenges": [
            c for c in DAY["challenges"]
            if (lane is None or c["lane"] == lane) and (day is None or f"-day-{day:02d}" in c["id"])
        ]}

    def clone(self):
        self.clones += 1
        return self

    def close(self):
        pass


class ReleaseDayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.hints = self.root / "hints.json"

    def run_daily(self, client, **kwargs):
        with redirect_stdout(StringIO()) as output:
            code = run_daily(client, artifact_dir=self.root, work_dir=self.root / "work",
                             hints_path=self.hints, sleep=lambda seconds: None, **kwargs)
        return code, output.getvalue()

    def test_families_run_in_parallel_with_their_output_kept_together(self):
        def fake(target, challenge_id, **kwargs):
            print(f"begin {challenge_id}")
            time.sleep(0.02)  # Lets the other family's thread interleave if it could.
            print(f"end {challenge_id}")
            return COMPLETE if challenge_id.startswith("warmups") else UNRESOLVED
        client = DayClient()
        with patch("huntress_ctf.daily.run_fast", side_effect=fake):
            code, output = self.run_daily(client, day=21)
        lines = [line for line in output.splitlines() if line.startswith(("begin", "end"))]
        for index in range(0, len(lines), 2):  # Each begin is followed by its own end.
            self.assertEqual(lines[index].split()[1], lines[index + 1].split()[1])
        self.assertEqual(client.clones, 3)  # One connection per family (web too, skipped).
        summary = {entry["challenge"]: entry for entry in
                   json.loads(output.split("===== Summary =====")[1])["challenges"]}
        # The summary keeps the list order; the family ran Single Solve first.
        self.assertEqual(list(summary), [c["id"] for c in DAY["challenges"]])
        self.assertEqual(summary["warmups-day-21/time_trial"]["outcome"], "complete")
        self.assertEqual(summary["binary-day-21-x"]["outcome"], "unresolved")
        for blocked in ("binary-day-21-x/time_trial", "binary-day-21-x/mastery"):
            self.assertEqual(summary[blocked]["reason"], "its Single Solve is not solved yet")
        self.assertIn("no Web solver yet", summary["web-exploitation-day-21-y"]["reason"])
        self.assertEqual(code, UNRESOLVED)

    def test_web_routes_start_only_when_asked_for(self):
        web = DAY["challenges"][-1]
        self.assertIsNotNone(eligibility(web, False, {}))
        self.assertIsNone(eligibility(web, False, {}, lane="web-exploitation"))

    def test_a_route_races_once_and_its_best_time_is_kept(self):
        record_hint("warmups-day-21/time_trial", [AnswerCandidate("a", "x", "s", "e")], self.hints)

        def race(target, challenge_id, report, **kwargs):
            report["server_clock_ms"] = {"from": 280}
            return COMPLETE
        client = DayClient()
        with patch("huntress_ctf.daily.run_fast", side_effect=race) as fast:
            self.run_daily(client, day=21, timed=True)
            _, output = self.run_daily(client, day=21, timed=True)
            self.assertEqual(fast.call_count, 1)
            self.assertIn("already raced (best 280 ms", output)
            self.run_daily(client, day=21, timed=True, rerace=True)
            self.assertEqual(fast.call_count, 2)
        hint = get_hint("warmups-day-21/time_trial", self.hints)
        self.assertEqual((hint["races"], hint["best_on_clock_ms"], hint["solvers"]), (2, 280, ["s"]))
        # A later CORRECT keeps the race record.
        record_hint("warmups-day-21/time_trial", [AnswerCandidate("a", "x", "t", "e")], self.hints)
        self.assertEqual(get_hint("warmups-day-21/time_trial", self.hints)["races"], 2)

    def test_several_days_race_their_proven_routes_with_a_reserve(self):
        record_hint("warmups-day-21/time_trial", [AnswerCandidate("a", "x", "s", "e")], self.hints)
        client = DayClient()
        with patch("huntress_ctf.daily.run_fast", return_value=COMPLETE) as fast:
            self.run_daily(client, days=[19, 20, 21], lane="warmups", timed=True, reserve=8)
        self.assertEqual(client.lists, [(19, "warmups"), (20, "warmups"), (21, "warmups")])
        self.assertEqual([call.args[1] for call in fast.call_args_list], ["warmups-day-21/time_trial"])
        self.assertEqual(fast.call_args_list[0].kwargs["reserve"], 8)

    def test_lanes_keep_the_run_to_our_own(self):
        client = DayClient(released_after=1)
        with patch("huntress_ctf.daily.run_fast", return_value=COMPLETE) as fast:
            _, output = self.run_daily(client, day=21, lanes=("warmups", "metadata-forensics"), wait_release=60)
        # The probes alternate between our lanes; a lane the probe did not list is listed once
        # more after the release (this day has no Metadata); never the whole day.
        self.assertEqual(client.lists, [(21, "warmups"), (21, "metadata-forensics"), (21, "warmups"),
                                        (21, "metadata-forensics")])
        self.assertEqual(sorted(call.args[1] for call in fast.call_args_list),
                         ["warmups-day-21", "warmups-day-21/time_trial"])
        self.assertNotIn("binary-day-21", output.split("===== Summary =====")[1])

    def test_waiting_for_the_release_polls_one_lane(self):
        client = DayClient(released_after=3)
        with patch("huntress_ctf.daily.run_fast", return_value=COMPLETE):
            _, output = self.run_daily(client, day=21, wait_release=60)
        self.assertEqual(client.lists, [(21, "warmups")] * 4 + [(21, None)])
        self.assertIn("Day 21 is released", output)

    def test_release_probes_each_of_several_lanes(self):
        class NoWarmups(DayClient):
            def list_challenges(self, day=None, lane=None):
                self.lists.append((day, lane))
                records = [c for c in DAY["challenges"] if c["lane"] == lane and lane != "warmups"]
                return {"challenges": records}
        client = NoWarmups()
        with redirect_stdout(StringIO()):
            found = wait_for_release(client, 21, ("warmups", "binary"), 5, sleep=lambda seconds: None)
        self.assertEqual(client.lists, [(21, "warmups"), (21, "binary")])
        self.assertTrue(found["challenges"])

    def test_release_wait_gives_up(self):
        ticks = iter(range(100))
        with redirect_stdout(StringIO()), self.assertRaisesRegex(GameMasterError, "not released"):
            wait_for_release(DayClient(released_after=99), 21, None, 5,
                             clock=lambda: next(ticks), sleep=lambda seconds: None)

    def test_family_order(self):
        grouped = families(DAY["challenges"])
        self.assertEqual([[c["id"] for c in group] for group in grouped], [
            ["binary-day-21-x", "binary-day-21-x/time_trial", "binary-day-21-x/mastery"],
            ["warmups-day-21", "warmups-day-21/time_trial"],
            ["web-exploitation-day-21-y"],
        ])


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
