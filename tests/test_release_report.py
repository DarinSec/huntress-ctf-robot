"""The release report names each route's blocker, read from the day's own log."""
from pathlib import Path
import runpy
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "release_report.py"
if not SCRIPT.exists():  # A Homebase deploy copies src/ and tests/ only.
    raise unittest.SkipTest("scripts/release_report.py is not deployed here")
REPORT = runpy.run_path(str(SCRIPT))

# As the robot writes it: the kind-by-kind resend of an untimed "incorrect" (day 23
# Binary, where one of fifteen machine answers was wrong).
LOG = """
===== android-day-23-y/time_trial (untimed) =====
{
  "completion": "unconfirmed",
  "unresolved_answer_ids": [
    "answer"
  ],
  "server_remaining": 1
}

===== binary-day-23-x (untimed) =====
Submission result:
{
  "result": "incorrect"
}

===== binary-day-23-x (incorrect: resending kind by kind) =====
{
  "conflict": false,
  "kinds": {
    "d#_analysis_format": {
      "answers": 19,
      "remaining": 15,
      "result": "accepted"
    },
    "d#_analysis_machine": {
      "accepted_by_splitting": 14,
      "answers": 15,
      "rejected_answer_ids": [
        "d01_analysis_machine"
      ],
      "remaining": null,
      "result": "incorrect"
    }
  },
  "no_answer_from_the_robot": [
    "host",
    "token"
  ],
  "rejected_answer_ids": [
    "d01_analysis_machine"
  ]
}

===== Summary =====
"""


class BlockerTests(unittest.TestCase):
    def test_the_rejected_kind_and_answer_are_named(self):
        found = REPORT["blockers"](LOG)
        self.assertEqual(sorted(found), ["android-day-23-y/time_trial", "binary-day-23-x"])
        self.assertEqual(found["binary-day-23-x"], [
            "kind rejected: d#_analysis_machine",
            "wrong answers: d01_analysis_machine",
            "no answer from the robot: host, token",
        ])
        # A route that answered nothing names the questions that are still open.
        self.assertEqual(found["android-day-23-y/time_trial"], ["1 questions still open: answer"])

    def test_a_healed_spelling_is_named_instead_of_a_wrong_answer(self):
        healed = LOG.replace('"rejected_answer_ids": [\n    "d01_analysis_machine"\n  ]',
                             '"alternatives": {"d01_analysis_machine": {"accepted": "x86_64"}}')
        self.assertIn('spelling accepted for d01_analysis_machine: {"accepted": "x86_64"}',
                      REPORT["blockers"](healed)["binary-day-23-x"])

    def test_a_log_without_a_resend_or_with_a_truncated_one_reports_nothing(self):
        self.assertEqual(REPORT["blockers"]("===== binary-day-23-x (untimed) =====\n{}\n"), {})
        cut = LOG.split('"kinds"')[0]  # A sweep killed mid-report: no readable JSON.
        self.assertNotIn("binary-day-23-x", REPORT["blockers"](cut))


class StatusTests(unittest.TestCase):
    """`--json` for scripts/release_alerts.py: the latest sweep's verdicts, read from its log."""

    def test_verdicts_and_blockers_of_the_latest_sweep(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as home:
            summary = {"challenges": [{"challenge": "binary-day-23-x", "outcome": "incorrect"}],
                       "safe_mode": {"held_back": [{"challenge": "binary-day-23-x/mastery", "reason": "a mode before it"}]}}
            Path(home, "day23-1300-untimed.log").write_text(LOG + "\n===== Summary =====\n" + json.dumps(summary))
            names = REPORT["status"].__globals__  # run_path returned a copy of them.
            saved, names["HOME"] = names["HOME"], home
            try:
                status = REPORT["status"](23)
            finally:
                names["HOME"] = saved
        route = status["untimed"]["routes"][0]
        self.assertEqual((route["outcome"], status["untimed"]["running"]), ("incorrect", False))
        self.assertIn("kind rejected: d#_analysis_machine", route["blockers"])
        self.assertEqual(status["untimed"]["safe_mode"], ["binary-day-23-x/mastery held back: a mode before it"])
        self.assertEqual(status["timed"], {"log": None, "running": False})


if __name__ == "__main__":
    unittest.main()
