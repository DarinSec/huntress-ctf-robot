"""The release at a glance, run on the Homebase: python3 -I release_report.py [day]

Each route's outcome from the day's latest untimed and timed logs, then, for every
unresolved Warmups or Metadata route, the questions from its triage.md with the field
suggestions: a new question type is in sight in one call (scripts/homebase.sh report).
"""

from __future__ import annotations

from datetime import datetime
import glob
import json
import os
import re
import sys
from zoneinfo import ZoneInfo

OWN_LANES = ("warmups", "metadata-forensics")
HOME = os.path.expanduser("~")


def latest(day: int, kind: str) -> tuple[str | None, dict | None, str]:
    logs = sorted(glob.glob(f"{HOME}/day{day}-*-{kind}.log"), key=os.path.getmtime)
    if not logs:
        return None, None, ""
    text = open(logs[-1], encoding="utf-8", errors="replace").read()
    try:
        return logs[-1], json.loads(text.rpartition("===== Summary =====")[2]), text
    except ValueError:
        return logs[-1], None, text  # Still running.


def questions(challenge_id: str) -> list[str]:
    folder = re.sub(r"[^A-Za-z0-9_-]", "_", challenge_id)[:64]
    try:
        text = open(f"{HOME}/work/{folder}/triage.md", encoding="utf-8").read()
    except OSError:
        return [f"  (no work/{folder}/triage.md yet)"]
    section = text.partition("## Questions")[2].split("\n## ", 1)[0]
    return ["  ## Questions" + line if index == 0 else "  " + line
            for index, line in enumerate(section.splitlines()[:60])]


def main() -> None:
    day = int(sys.argv[1]) if len(sys.argv) > 1 else datetime.now(ZoneInfo("America/New_York")).day
    for kind in ("untimed", "timed"):
        path, summary, text = latest(day, kind)
        if path is None:
            print(f"== {kind}: no log for day {day} yet")
            continue
        released = re.search(r"Day \d+ is released: listed after [\d.]+ s of waiting", text)
        print(f"== {kind}: {os.path.basename(path)}" + (f" ({released[0]})" if released else ""))
        if summary is None:
            print("   still running")
            continue
        print(f"   wall_seconds {summary.get('wall_seconds')}")
        for entry in summary["challenges"]:
            if entry["outcome"] == "skipped" and not str(entry["challenge"]).startswith(OWN_LANES):
                continue
            extra = entry.get("on_clock_ms") or entry.get("reason") or ""
            print(f"   {entry['outcome']:10} {entry['challenge']}  {entry.get('wall_seconds', '')} {extra}")
        if kind == "untimed":
            stuck = [entry["challenge"] for entry in summary["challenges"]
                     if str(entry["challenge"]).startswith(OWN_LANES)
                     and entry["outcome"] not in ("complete", "skipped")]
            for challenge_id in stuck:
                print(f"\n== UNRESOLVED {challenge_id}")
                print("\n".join(questions(challenge_id)))


if __name__ == "__main__":
    main()
