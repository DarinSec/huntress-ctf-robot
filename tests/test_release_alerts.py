"""Release-day alerts: one notification per route the robot left behind, quiet once it is solved."""
from datetime import datetime, timedelta
from pathlib import Path
import runpy
import unittest
from zoneinfo import ZoneInfo

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "release_alerts.py"
if not SCRIPT.exists():  # A Homebase deploy copies src/ and tests/ only.
    raise unittest.SkipTest("scripts/release_alerts.py is not deployed here")
ALERTS = runpy.run_path(str(SCRIPT))

RELEASE = datetime(2026, 10, 28, 9, 0, tzinfo=ZoneInfo("America/New_York"))
META = "metadata-forensics-day-28-new-format"


def poll(routes=(), listed=None, safe=()):
    data = {"day": 28, "untimed": {"log": "day28-1300-untimed.log", "running": False,
                                   "routes": list(routes), "safe_mode": list(safe)}}
    if listed is not None:
        data["listed"] = listed
    return data


def record(challenge, solved=False, minute=1.0):
    at = (RELEASE + timedelta(minutes=minute)).astimezone(ZoneInfo("UTC")).isoformat().replace("+00:00", "Z")
    return {"id": challenge, "solved": solved, "solved_by": {"name": "Darin", "at": at} if solved else None}


class ReleaseAlertTests(unittest.TestCase):
    def events(self, data, state, after_s=30):
        return ALERTS["events"](data, state, RELEASE + timedelta(seconds=after_s), RELEASE, 180)

    def test_an_unresolved_route_alerts_once_with_its_blocker(self):
        state = {}
        route = {"challenge": f"{META}/time_trial", "outcome": "unresolved", "reason": None,
                 "blockers": ["1 questions still open: d28-x-pcap-link-type"]}
        found = self.events(poll([route]), state)
        self.assertEqual(found, [("Metadata TT (new-format): unresolved",
                                  "1 questions still open: d28-x-pcap-link-type", f"{META}/time_trial")])
        self.assertEqual(self.events(poll([route]), state), [])  # The next poll repeats nothing.

    def test_a_solved_route_and_ordinary_skips_stay_quiet(self):
        routes = [{"challenge": META, "outcome": "unresolved"},
                  {"challenge": "warmups-day-28", "outcome": "skipped", "reason": "already solved"},
                  {"challenge": "warmups-day-28/mastery", "outcome": "skipped", "reason": "warmups-day-28 is not solved yet"}]
        self.assertEqual(self.events(poll(routes, [record(META, True), record("warmups-day-28")]), {}), [])

    def test_a_turned_down_route_and_a_crashed_solver_alert(self):
        routes = [{"challenge": f"{META}/mastery", "outcome": "skipped", "reason": "turned down as incorrect"}]
        titles = [title for title, _, _ in self.events(poll(routes, safe=["x: race: binary crashed after 12.9 s"]), {})]
        self.assertEqual(titles, ["Metadata M (new-format): skipped", "Robot safe mode"])

    def test_an_open_route_alerts_after_the_stale_limit_only(self):
        listed = [record(META), record("warmups-day-28", True)]
        self.assertEqual(self.events(poll(listed=listed), {}, after_s=170), [])
        found = self.events(poll(listed=listed), {}, after_s=190)
        self.assertEqual([title for title, _, _ in found], ["Metadata SS (new-format): still unsolved"])

    def test_all_solved_names_the_last_flag(self):
        listed = [record(META, True, 2.5), record("warmups-day-28", True, 0.2)]
        self.assertEqual(self.events(poll(listed=listed), {}),
                         [("Day 28: all 2 routes solved", "last flag 2.5 min after the release", None)])


if __name__ == "__main__":
    unittest.main()
