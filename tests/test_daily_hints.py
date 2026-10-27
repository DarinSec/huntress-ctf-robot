from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from huntress_ctf import solvers
from huntress_ctf.autopilot import COMPLETE, INCORRECT, UNRESOLVED
from huntress_ctf.client import GameMasterError
from huntress_ctf.daily import eligibility, families, needs_proof, run_daily, seconds_until, wait_for_release
from huntress_ctf.hints import get_hint, load_hints, record_hint, record_outcome
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

    def test_prove_runs_solved_unproven_timed_routes_once_untimed(self):
        # Day 26: Binary's Single Solve was finished by hand, so its Time Trial and Mastery
        # had no proven solver and `daily --timed` never raced them.
        lane = "binary-reverse-engineering"
        family = [
            {"id": "binary-day-26-x", "lane": lane, "mode": "single_solve", "solved": True},
            {"id": "binary-day-26-x/time_trial", "lane": lane, "mode": "time_trial", "solved": True,
             "run_for_time_supported": True},
            {"id": "binary-day-26-x/mastery", "lane": lane, "mode": "mastery", "solved": True,
             "run_for_time_supported": True},
        ]

        class FamilyClient(ListOnlyClient):
            def list_challenges(self, day=None, lane=None):
                return {"challenges": family}

        def daily(**kwargs):
            with redirect_stdout(StringIO()) as output:
                run_daily(FamilyClient(), artifact_dir=self.root, work_dir=self.root / "work",
                          hints_path=self.root / "hints.json", **kwargs)
            return output.getvalue()

        with patch("huntress_ctf.daily.run_fast", return_value=COMPLETE) as fast:
            self.assertIn("already solved", daily())
        fast.assert_not_called()  # Opt-in only: a proof spends a regular variant.
        # A failed proof of the Time Trial does not hold the Mastery (both are open already).
        with patch("huntress_ctf.daily.run_fast", side_effect=[UNRESOLVED, COMPLETE]) as fast:
            output = daily(prove=True)
        self.assertEqual([call.args[1] for call in fast.call_args_list],
                         ["binary-day-26-x/time_trial", "binary-day-26-x/mastery"])
        self.assertTrue(all(call.kwargs.get("prove") and not call.kwargs["timed"] for call in fast.call_args_list))
        self.assertIn('"proof": true', output)
        with patch("huntress_ctf.daily.run_fast", return_value=COMPLETE) as fast:
            daily(prove=True, timed=True)
        self.assertNotIn("prove", fast.call_args_list[0].kwargs if fast.call_args_list else {})

    def test_a_timed_attempt_met_untimed_is_waited_out_then_retried(self):
        # Day 27 13:04:53: someone started Metadata's Time Trial timed; the untimed sweep 8 s
        # later reconnected to it, answered 31/32 by the race's rules and turned the route down.
        lane = "metadata-forensics"
        family = [
            {"id": "m-day-27", "lane": lane, "mode": "single_solve", "solved": True},
            {"id": "m-day-27/time_trial", "lane": lane, "mode": "time_trial", "run_for_time_supported": True},
            {"id": "m-day-27/mastery", "lane": lane, "mode": "mastery", "run_for_time_supported": True},
        ]

        class FamilyClient(ListOnlyClient):
            def list_challenges(self, day=None, lane=None):
                return {"challenges": family}

        deadline = "2026-10-27T13:05:43Z"
        started = 1793106300.0  # 13:05:00 UTC, 43 s before the deadline.
        hints = self.root / "hints.json"

        def daily(fake):
            waits = []
            with patch("huntress_ctf.daily.run_fast", side_effect=fake) as fast, \
                    redirect_stdout(StringIO()) as output:
                run_daily(FamilyClient(), artifact_dir=self.root, work_dir=self.root / "work",
                          hints_path=hints, sleep=waits.append, now=lambda: started)
            return fast.call_args_list, waits, output.getvalue().split("===== Summary =====")[1]

        def met_then(code_after, still_running=False):
            def fake(target, challenge_id, **kwargs):
                if challenge_id == "m-day-27/time_trial" and (not kwargs.get("prove") or still_running):
                    kwargs["report"]["timed_attempt"] = {"attempt_id": "someones", "deadline": deadline}
                    return UNRESOLVED
                return code_after
            return fake

        calls, waits, summary = daily(met_then(COMPLETE))
        self.assertEqual([(c.args[1], bool(c.kwargs.get("prove"))) for c in calls],
                         [("m-day-27/time_trial", False), ("m-day-27/time_trial", True), ("m-day-27/mastery", False)])
        self.assertFalse(any(c.kwargs.get("timed") for c in calls))  # Never run_for_time.
        self.assertEqual(waits, [46.0])  # Until the deadline, plus the margin.
        self.assertIn('"after_timed_attempt": "someones"', summary)
        self.assertNotIn("turned_down", load_hints(hints).get("m-day-27/time_trial", {}))
        # Still running after the wait: an error (day.sh sweeps again), never turned down,
        # and the Mastery waits for its Time Trial.
        calls, _, summary = daily(met_then(UNRESOLVED, still_running=True))
        self.assertEqual(len(calls), 2)
        self.assertIn("a timed attempt is still running", summary)
        self.assertIn('"outcome": "error"', summary)
        self.assertNotIn("turned_down", load_hints(hints).get("m-day-27/time_trial", {}))
        # The regular variant's own verdict counts as usual.
        daily(met_then(UNRESOLVED))
        self.assertEqual(load_hints(hints)["m-day-27/time_trial"]["turned_down"], "unresolved")

    def test_a_solver_killed_by_its_machine_is_tried_again_not_turned_down(self):
        # Day 27: Binary Mastery's solver was killed (-9, out of memory on a 1.9 GB Homebase)
        # 12.9 s in; the route was turned down and the robot stopped trying it for the day.
        route = {"id": "b-day-27-x/mastery", "lane": "binary-reverse-engineering", "mode": "mastery",
                 "run_for_time_supported": True}

        class OneRoute(ListOnlyClient):
            def list_challenges(self, day=None, lane=None):
                return {"challenges": [route]}

        hints = self.root / "hints.json"
        for status, detail, outcome in (
            ("crashed", "the solver process exited with code -9", "error"),
            ("timeout", "killed", "unresolved"),  # A hang repeats: the watchdog's verdict stands.
            ("crashed", "ValueError: bad offset", "unresolved"),  # A bug on these bytes: a verdict.
        ):
            with self.subTest(detail=detail):
                hints.unlink(missing_ok=True)

                def fake(target, challenge_id, **kwargs):
                    kwargs["report"]["solver_problems"] = [{"stage": "race", "solver": "binary-static-facts",
                                                            "status": status, "seconds": 12.9, "detail": detail}]
                    return UNRESOLVED
                with patch("huntress_ctf.daily.run_fast", side_effect=fake), redirect_stdout(StringIO()) as output:
                    run_daily(OneRoute(), artifact_dir=self.root, work_dir=self.root / "work", hints_path=hints)
                summary = output.getvalue().split("===== Summary =====")[1]
                self.assertIn(f'"outcome": "{outcome}"', summary)
                self.assertEqual("turned_down" in load_hints(hints).get(route["id"], {}), outcome == "unresolved")

    def test_seconds_until_a_deadline(self):
        noon = 1793102400.0  # 2026-10-27T12:00:00Z
        self.assertEqual(seconds_until("2026-10-27T12:00:50Z", noon), 53.0)
        self.assertEqual(seconds_until("2026-10-27T12:00:50.500+00:00", noon), 53.5)
        self.assertEqual(seconds_until("2026-10-27T11:00:00Z", noon), 0.0)  # Ended already.
        self.assertEqual(seconds_until("2026-10-28T12:00:00Z", noon), 900.0)  # Capped.
        self.assertEqual(seconds_until("soon", noon), 0.0)

    def test_which_routes_need_a_proof(self):
        route = {"id": "b-day-26-x/mastery", "lane": "binary-reverse-engineering", "mode": "mastery",
                 "solved": True, "run_for_time_supported": True}
        self.assertTrue(needs_proof(route, {}))
        self.assertTrue(needs_proof(route, {route["id"]: {"turned_down": "unresolved", "turned_down_at": "x"}}))
        self.assertFalse(needs_proof(route, {route["id"]: {"solvers": ["s"]}}))  # Proven.
        self.assertFalse(needs_proof(route, {route["id"]: {"raced_at": "x"}}))
        self.assertFalse(needs_proof({**route, "solved": False}, {}))  # The ordinary sweep solves it.
        self.assertFalse(needs_proof({**route, "run_for_time_supported": False}, {}))
        self.assertFalse(needs_proof({**route, "id": "b-day-26-x", "mode": "single_solve"}, {}))
        self.assertFalse(needs_proof({**route, "lane": "web-exploitation"}, {}))
        course = {**route, "lane": "metadata-forensics"}
        self.assertTrue(needs_proof(course, {}))
        self.assertFalse(needs_proof(course, {"b-day-26-x": {"solvers": ["s"]}}))  # Races on the Single Solve.

    def test_a_route_the_service_turned_down_untimed_is_not_raced(self):
        # Day 23: the Metadata Time Trial was rejected untimed and raced twice anyway,
        # spending a ranked variant each time on the same answer.
        hints = self.root / "hints.json"
        route = {"id": "metadata-day-23-x/time_trial", "lane": "metadata-forensics",
                 "mode": "time_trial", "run_for_time_supported": True}
        record_hint("metadata-day-23-x/time_trial", [AnswerCandidate("a", "x", "s", "e")], hints)
        self.assertIsNone(eligibility(route, True, load_hints(hints)))
        self.assertIsNone(record_outcome("metadata-day-23-x/time_trial", "incorrect", path=hints))
        reason = eligibility(route, True, load_hints(hints))
        self.assertIn("a race would spend a ranked variant on it again", reason)
        self.assertIn("incorrect", reason)
        self.assertIsNone(eligibility(route, True, load_hints(hints), rerace=True))  # --rerace still races.
        # A solver that scores on the route after the mark clears it by itself (`learn`
        # healing a spelling records the hint without ending the run "complete").
        healed = load_hints(hints)
        healed[route["id"]]["recorded_at"] = "2099-01-01T00:00:00+00:00"
        self.assertIsNone(eligibility(route, True, healed))
        # So does the first run that completes the route.
        record_outcome("metadata-day-23-x/time_trial", "complete", path=hints)
        self.assertIsNone(eligibility(route, True, load_hints(hints)))
        # A mark on a route with no proven solver does not make it look proven.
        record_outcome("binary-day-23-y", "unresolved", path=hints)
        self.assertEqual(eligibility({"id": "binary-day-23-y", "run_for_time_supported": True},
                                     True, load_hints(hints), rerace=True),
                         "no proven solver yet; solve it untimed first")
        # A timed run marks only a rejected submission: its "unresolved" is also what a
        # gate skip and a reserve stop return, and neither of those spends a variant.
        self.assertIsNone(record_outcome("warmups-day-23/mastery", "unresolved", timed=True, path=hints))
        self.assertIsNone(load_hints(hints).get("warmups-day-23/mastery"))
        record_outcome("warmups-day-23/mastery", "incorrect", timed=True, path=hints)
        self.assertEqual(load_hints(hints)["warmups-day-23/mastery"]["turned_down"], "incorrect (timed)")

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
            self.assertEqual(summary[blocked]["reason"], "binary-day-21-x is not solved yet")
        self.assertIn("live targets[]", summary["web-exploitation-day-21-y"]["reason"])
        self.assertEqual(code, UNRESOLVED)

    def test_a_time_trial_that_does_not_score_blocks_its_mastery(self):
        # Day 23: the Single Solves were solved, three Time Trials were not, and asking
        # for their Masteries anyway returned HTTP 409 reported as "error" - ten sweeps.
        def fake(target, challenge_id, **kwargs):
            asked.append(challenge_id)
            return UNRESOLVED if challenge_id.endswith("/time_trial") else COMPLETE
        for workers in (4, 1):  # Families in parallel, then the sequential (timed) path.
            asked: list[str] = []
            with patch("huntress_ctf.daily.run_fast", side_effect=fake):
                _, output = self.run_daily(DayClient(), day=21, workers=workers)
            summary = {entry["challenge"]: entry for entry in
                       json.loads(output.split("===== Summary =====")[1])["challenges"]}
            self.assertEqual(summary["binary-day-21-x/mastery"]["outcome"], "skipped")
            self.assertEqual(summary["binary-day-21-x/mastery"]["reason"],
                             "binary-day-21-x/time_trial is not solved yet")
            self.assertNotIn("binary-day-21-x/mastery", asked)

    def test_a_turned_down_route_also_blocks_the_modes_after_it(self):
        # Gating the Time Trial alone moved the waste one step: day 23 skipped the two
        # Time Trials and raced their Masteries, which ask the same question kinds.
        record_hint("binary-day-21-x", [AnswerCandidate("a", "x", "s", "e")], self.hints)
        record_hint("binary-day-21-x/time_trial", [AnswerCandidate("a", "x", "s", "e")], self.hints)
        record_hint("binary-day-21-x/mastery", [AnswerCandidate("a", "x", "s", "e")], self.hints)
        record_outcome("binary-day-21-x/time_trial", "incorrect", path=self.hints)
        asked: list[str] = []
        with patch("huntress_ctf.daily.run_fast", side_effect=lambda t, i, **k: asked.append(i) or COMPLETE):
            _, output = self.run_daily(DayClient(), day=21, timed=True)
        summary = {entry["challenge"]: entry for entry in
                   json.loads(output.split("===== Summary =====")[1])["challenges"]}
        self.assertIn("turned down as incorrect", summary["binary-day-21-x/time_trial"]["reason"])
        self.assertEqual(summary["binary-day-21-x/mastery"]["reason"],
                         "binary-day-21-x/time_trial is not solved yet")
        self.assertNotIn("binary-day-21-x/mastery", asked)

    def test_web_routes_start_only_when_asked_for(self):
        web = DAY["challenges"][-1]
        self.assertIsNotNone(eligibility(web, False, {}))
        self.assertIsNone(eligibility(web, False, {}, lane="web-exploitation"))
        # The cron sweep asks with --lanes (plural); web in that set is an explicit request.
        self.assertIsNone(eligibility(web, False, {}, requested_lanes=("warmups", "web-exploitation")))
        self.assertIsNotNone(eligibility(web, False, {}, requested_lanes=("warmups",)))

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

    def test_an_untimed_incorrect_is_resent_kind_by_kind(self):
        client = DayClient()
        with patch("huntress_ctf.daily.run_fast", return_value=INCORRECT), \
                patch("huntress_ctf.daily.run_learn", return_value=COMPLETE) as learn:
            _, output = self.run_daily(client, day=21, lanes=("binary",))
        # The Single Solve completes that way, which unlocks its Time Trial and Mastery.
        self.assertEqual([call.args[1] for call in learn.call_args_list],
                         ["binary-day-21-x", "binary-day-21-x/time_trial", "binary-day-21-x/mastery"])
        self.assertTrue(all(call.kwargs["open_only"] for call in learn.call_args_list))
        self.assertIn('"outcome": "complete"', output.split("===== Summary =====")[1])
        record_hint("binary-day-21-x/time_trial", [AnswerCandidate("a", "x", "s", "e")], self.hints)
        with patch("huntress_ctf.daily.run_fast", return_value=INCORRECT), \
                patch("huntress_ctf.daily.run_learn") as learn:
            self.run_daily(client, day=21, lanes=("binary",), timed=True)
        learn.assert_not_called()  # A race is never resent.

    def test_a_lane_the_server_cannot_filter_comes_from_the_day_list(self):
        class NoBinaryFilter(DayClient):
            def list_challenges(self, day=None, lane=None):
                if lane == "binary":
                    self.lists.append((day, lane))
                    raise GameMasterError("HTTP 400 invalid_lane")
                return super().list_challenges(day, lane)
        client = NoBinaryFilter()
        with patch("huntress_ctf.daily.run_fast", return_value=COMPLETE) as fast:
            _, output = self.run_daily(client, day=21, lanes=("warmups", "binary"))
        self.assertEqual(client.lists, [(21, "warmups"), (21, "binary"), (21, None)])
        self.assertIn("binary-day-21-x", [call.args[1] for call in fast.call_args_list])
        self.assertNotIn("web-exploitation-day-21-y", output.split("===== Summary =====")[1])
        # The night's Hall of Fame lists by day and lane too.
        client = NoBinaryFilter()
        with patch("huntress_ctf.daily.run_fast", return_value=COMPLETE):
            _, output = self.run_daily(client, days=[21], lane="binary", timed=True)
        self.assertEqual(client.lists, [(21, "binary"), (21, None)])
        self.assertIn("binary-day-21-x/time_trial", output.split("===== Summary =====")[1])

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

    def test_a_lane_that_fails_to_list_stops_being_a_release_probe(self):
        class BinaryFails(DayClient):
            def list_challenges(self, day=None, lane=None):
                if lane == "binary":
                    self.lists.append((day, lane))
                    raise GameMasterError("HTTP 400 invalid_lane")
                return super().list_challenges(day, lane)
        client = BinaryFails(released_after=3)
        with redirect_stdout(StringIO()):
            wait_for_release(client, 21, ("binary", "warmups"), 60, sleep=lambda seconds: None)
        self.assertEqual(client.lists, [(21, "binary")] + [(21, "warmups")] * 3)

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
