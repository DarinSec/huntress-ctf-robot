"""Release-day alerts on the player's Mac: a notification the moment the robot leaves a route behind.

    python3 scripts/release_alerts.py [day] [--interval 15] [--stale 180] [--once]

Start it any time before the release (09:00 New York: 14:00 in Sweden until 1 Nov, then 15:00);
it waits, then every `interval` seconds reads the Homebase over scripts/homebase.sh (the CTF VPN
must be up): the latest untimed sweep's verdicts (scripts/release_report.py --json) and, every
other poll, the day's list (who solved what, read-only, never a flag). It notifies once per:
  - route the robot left unresolved, incorrect, in conflict or errored, or turned down;
  - solver crash or watchdog timeout, or a lane module that did not load;
  - route still unsolved `stale` seconds after the release, whatever the robot says;
  - Homebase unreachable (VPN, VM off);
and finally "all solved" with the minute of the last flag. A route someone has solved is quiet.

Day 27 the team stepped in after 5 minutes by rule, and Ilse's pop-ups ran on her machine only;
the last flag came at 11.9 min while every known type was done in about 1.5.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import json
from pathlib import Path
import subprocess
import sys
import time
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
NEW_YORK = ZoneInfo("America/New_York")
LANES = {"warmups": "Warmups", "metadata-forensics": "Metadata", "script-analysis": "Script",
         "binary-reverse-engineering": "Binary", "mobile-android": "Mobile", "web-exploitation": "Web"}
MODES = {"time_trial": "TT", "mastery": "M"}
QUIET = {"complete"}  # Verdicts that need nobody; "skipped" is quiet unless it was turned down.


def short(challenge_id: str) -> str:
    """'metadata-forensics-day-27-packet-loss-prevention/time_trial' -> 'Metadata TT (packet-loss-prevention)'."""
    route, _, mode = str(challenge_id).partition("/")
    lane = next((name for prefix, name in LANES.items() if route.startswith(prefix + "-")), route)
    slug = route.split("-day-", 1)[-1].partition("-")[2] if "-day-" in route else ""
    return f"{lane} {MODES.get(mode, 'SS')}" + (f" ({slug})" if slug else "")


def minutes(stamp: str | None, release: datetime) -> float | None:
    try:
        return (datetime.fromisoformat(str(stamp).replace("Z", "+00:00")) - release).total_seconds() / 60
    except ValueError:
        return None


def events(data: dict, state: dict, now: datetime, release: datetime, stale: float) -> list[tuple[str, str, str | None]]:
    """(title, message, route or None) for everything new in one poll; `state` remembers what was said and solved."""
    said, solved = state.setdefault("said", set()), state.setdefault("solved", {})
    found = []
    listed = data.get("listed")
    if listed is not None:
        for record in listed:
            if record.get("solved") and record.get("id") not in solved:
                by = record.get("solved_by") or {}
                solved[record["id"]] = (by.get("name"), minutes(by.get("at"), release))
    untimed = data.get("untimed") or {}
    for route in untimed.get("routes") or ():
        challenge, outcome = str(route.get("challenge")), str(route.get("outcome"))
        reason = str(route.get("reason") or "")
        if challenge in solved or outcome in QUIET or (outcome == "skipped" and "turned down" not in reason):
            continue
        key = f"{challenge}|{outcome}|{reason}"
        if key not in said:
            said.add(key)
            detail = (route.get("blockers") or [reason or outcome])[0]
            found.append((f"{short(challenge)}: {outcome}", detail[:180], challenge))
    for line in untimed.get("safe_mode") or ():
        if f"safe|{line}" not in said:
            said.add(f"safe|{line}")
            found.append(("Robot safe mode", line[:180], None))
    if listed:
        open_routes = [record["id"] for record in listed if not record.get("solved")]
        if not open_routes and "done" not in said:
            said.add("done")
            last = max((at for _, at in solved.values() if at is not None), default=None)
            found.append((f"Day {data.get('day')}: all {len(listed)} routes solved",
                          f"last flag {last:.1f} min after the release" if last is not None else "all solved", None))
        elif (now - release).total_seconds() >= stale:
            for challenge in open_routes:
                if f"stale|{challenge}" not in said:
                    said.add(f"stale|{challenge}")
                    found.append((f"{short(challenge)}: still unsolved", f"{stale / 60:.0f} min after the release",
                                  challenge))
    return found


def notify(title: str, message: str) -> None:
    print(f"\a{datetime.now():%H:%M:%S}  ** {title}: {message}", flush=True)
    script = ['on run argv', 'display notification (item 2 of argv) with title (item 1 of argv) sound name "Glass"',
              'end run']
    try:  # argv, not string interpolation: route names and reasons come from the service and logs.
        subprocess.run(["osascript", *sum((["-e", line] for line in script), []), title, message],
                       timeout=10, check=False, capture_output=True)
    except (OSError, subprocess.SubprocessError):
        pass


def fetch(day: int, listed: bool) -> dict:
    command = f"python3 -I - --json {'--list ' if listed else ''}{day}"
    with open(ROOT / "scripts" / "release_report.py", "rb") as report:
        done = subprocess.run([str(ROOT / "scripts" / "homebase.sh"), "run", command], stdin=report,
                              capture_output=True, timeout=120, check=False)
    lines = done.stdout.decode("utf-8", "replace").strip().splitlines()
    if done.returncode or not lines:
        raise RuntimeError((done.stderr.decode("utf-8", "replace").strip() or f"exit {done.returncode}")[-200:])
    return json.loads(lines[-1])


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("day", nargs="?", type=int, default=datetime.now(NEW_YORK).day)
    parser.add_argument("--interval", type=float, default=15.0)
    parser.add_argument("--stale", type=float, default=180.0, help="seconds after the release")
    parser.add_argument("--hours", type=float, default=4.0, help="give up after this long")
    parser.add_argument("--once", action="store_true", help="one poll now, no waiting (a check)")
    args = parser.parse_args(argv)
    today = datetime.now(NEW_YORK)
    release = today.replace(day=args.day, hour=9, minute=0, second=0, microsecond=0)
    print(f"Day {args.day}: release {release.astimezone():%Y-%m-%d %H:%M} local time; "
          f"polling every {args.interval:.0f} s, stale after {args.stale / 60:.0f} min.", flush=True)
    if not args.once:
        while (wait := (release - timedelta(seconds=10) - datetime.now(NEW_YORK)).total_seconds()) > 0:
            if wait > 60:
                print(f"{datetime.now():%H:%M:%S}  {wait / 60:.0f} min to the release", flush=True)
            time.sleep(min(wait, 300))
    state: dict = {}
    unreachable, polls, until = False, 0, time.monotonic() + args.hours * 3600
    while time.monotonic() < until:
        try:
            data = fetch(args.day, listed=args.once or polls % 2 == 1)
        except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as exc:
            if not unreachable:
                notify("Homebase unreachable", f"{exc}"[:180] or "no answer")
            unreachable = True
        else:
            if unreachable:
                print(f"{datetime.now():%H:%M:%S}  Homebase answers again", flush=True)
            unreachable = False
            before = dict(state.get("solved", {}))
            for title, message, challenge in events(data, state, datetime.now(NEW_YORK), release, args.stale):
                notify(title, message)
                if challenge:
                    print(f"           scripts/homebase.sh gaps '{challenge}'   (report: all routes; pull: the files)",
                          flush=True)
            for challenge, (name, at) in state.get("solved", {}).items():
                if challenge not in before:
                    when = f"{at:5.1f} min" if at is not None else "   ?"
                    print(f"{datetime.now():%H:%M:%S}  solved {when}  {short(challenge)}  ({name})", flush=True)
            untimed = data.get("untimed") or {}
            if polls == 0 or untimed.get("running"):
                print(f"{datetime.now():%H:%M:%S}  sweep {untimed.get('log') or 'not started'}"
                      + (" (running)" if untimed.get("running") else ""), flush=True)
            if "done" in state.get("said", ()):
                return 0
        polls += 1
        if args.once:
            return 0
        time.sleep(args.interval)
    notify("Release alerts stopped", f"after {args.hours:g} h; routes may still be open")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
