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


def blockers(text: str) -> dict[str, list[str]]:
    """Per route, the one thing standing between it and its flag, from the day's log.

    After an untimed "incorrect" the robot resends kind by kind and splits a rejected
    kind until the refused answers are named, then prints that report under
    "===== <id> (incorrect: resending kind by kind) =====". A route that submitted only
    some of its answers prints `unresolved_answer_ids` in its own section instead.
    Reading both here saves searching a log of several MB for the one question a lane
    owner has to fix.
    """
    found: dict[str, list[str]] = {}
    for section in text.split("\n===== ")[1:]:
        header, _, body = section.partition("\n")
        challenge_id = header.partition(" (")[0]
        lines = found.setdefault(challenge_id, [])
        if "(incorrect: resending kind by kind)" in header:
            try:
                report, _ = json.JSONDecoder().raw_decode(body.lstrip())
            except ValueError:
                continue
            kinds = report.get("kinds") if isinstance(report.get("kinds"), dict) else {}
            lines += [f"kind rejected: {name}" for name, entry in sorted(kinds.items())
                      if isinstance(entry, dict) and str(entry.get("result")).casefold() == "incorrect"]
            for answer_id, healed in sorted((report.get("alternatives") or {}).items()):
                lines.append(f"spelling accepted for {answer_id}: {json.dumps(healed)}")
            if report.get("rejected_answer_ids"):
                lines.append("wrong answers: " + ", ".join(report["rejected_answer_ids"][:12]))
            if report.get("no_answer_from_the_robot"):
                lines.append("no answer from the robot: " + ", ".join(report["no_answer_from_the_robot"][:12]))
            continue
        open_ids = re.search(r'"unresolved_answer_ids":\s*(\[[^]]*\])', body)
        if open_ids:
            try:
                still_open = json.loads(open_ids[1])
            except ValueError:
                continue
            if still_open:
                lines.append(f"{len(still_open)} questions still open: "
                             + ", ".join(str(item) for item in still_open[:12]))
    return {challenge_id: lines for challenge_id, lines in found.items() if lines}


def questions(challenge_id: str) -> list[str]:
    folder = re.sub(r"[^A-Za-z0-9_-]", "_", challenge_id)[:64]
    try:
        text = open(f"{HOME}/work/{folder}/triage.md", encoding="utf-8").read()
    except OSError:
        return [f"  (no work/{folder}/triage.md yet)"]
    section = text.partition("## Questions")[2].split("\n## ", 1)[0]
    return ["  ## Questions" + line if index == 0 else "  " + line
            for index, line in enumerate(section.splitlines()[:60])]


def safe_mode_lines(summary: dict) -> list[str]:
    """The sweep's safe-mode block: lane modules not loaded, solvers the watchdog left out,
    and routes held back (an error, or a mode before them). Other lanes' skips are hidden
    above, so a blocked Binary Mastery is only seen here."""
    block = summary.get("safe_mode") or {}
    lines = [f"solver module not loaded: {error}" for error in block.get("load_errors", ())]
    for problem in block.get("solver_problems", ()):
        detail = f" ({problem['detail']})" if problem.get("detail") else ""
        lines.append(f"{problem['challenge']}: {problem['stage']}: {problem['solver']} "
                     f"{problem['status']} after {problem['seconds']} s{detail}")
    lines += [f"{held['challenge']} held back: {held['reason']}" for held in block.get("held_back", ())]
    return lines


def slowest_line(summary: dict) -> str | None:
    """The sweep's slowest solvers on one line: a creeping solver shows before it freezes."""
    slowest = summary.get("slowest_solvers") or []
    if not slowest:
        return None
    return "slowest solvers: " + ", ".join(
        f"{item['solver']} {item['ms']:.0f} ms ({item['challenge']})" for item in slowest)


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
        blocked = blockers(text)
        for entry in summary["challenges"]:
            if entry["outcome"] == "skipped" and not str(entry["challenge"]).startswith(OWN_LANES):
                continue
            extra = entry.get("on_clock_ms") or entry.get("reason") or ""
            print(f"   {entry['outcome']:10} {entry['challenge']}  {entry.get('wall_seconds', '')} {extra}")
            for line in blocked.get(str(entry["challenge"]), ()):
                print(f"              {line}")
        slowest = slowest_line(summary)
        if slowest:
            print(f"   {slowest}")
        safe = safe_mode_lines(summary)
        if safe:
            print("   safe mode:")
            print("\n".join(f"     {line}" for line in safe))
        if kind == "untimed":
            stuck = [entry["challenge"] for entry in summary["challenges"]
                     if str(entry["challenge"]).startswith(OWN_LANES)
                     and entry["outcome"] not in ("complete", "skipped")]
            for challenge_id in stuck:
                print(f"\n== UNRESOLVED {challenge_id}")
                print("\n".join(questions(challenge_id)))


if __name__ == "__main__":
    main()
