"""Replay corpus: completed assignments with the answers the service accepted.

Day 23 broke three lanes in ways no synthetic test showed (a member limit, a machine-field
spelling, a sort order); every one was visible offline the moment a past assignment was
re-solved and compared with what the service had accepted. So the robot records each
assignment it scores (`record`, called from fastpath after the submission, off the clock),
and `scripts/replay.py` re-solves them all with the current solvers (`replay`).

Layout (git-ignored, in the state directory next to hints.json):
  corpus/<challenge-id>/<attempt>/assignment.json   {"challenge": ..., "attempt": ...}
                                  deliveries/<N>-<filename>
                                  accepted.json     {answer_id: accepted answer}
                                  last_replay.json  the previous replay's answers
                                  last_timing.json  the previous replay's seconds per solver
An answer that differs from the accepted one is not by itself wrong (several spellings are
often accepted). A regression is an answer that equalled the accepted one in the previous
replay and no longer does, or that is no longer answered.

Time is compared the same way (ROBUSTNESS.md workstream 5): a solver is over its budget when
it takes more than SLOW_FACTOR times its previous replay of that entry, and more than
SLOW_FLOOR_S; it broke when it ran fine there before and now crashes or hangs. Deploy replays
the new code --dry against the deployed code's last timings, so a slowdown stops the PR's
deploy instead of showing up on the clock. A fixed limit would not do: solvers range from
milliseconds to ~25 s (Day 22 Binary Mastery), so no one number catches a 3x slowdown in both.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from .containers import Member
from .display import safe_value
from .hints import default_path

MAX_ENTRIES_PER_ROUTE = 2   # Two variants per route are enough to catch a regression.
MAX_ENTRY_BYTES = 512 * 1024 * 1024  # Binary Mastery: 7 x 35 MB deliveries.
SLOW_FACTOR = 2.0    # Over budget: slower than this many times the previous replay ...
SLOW_FLOOR_S = 0.25  # ... and than this (3 ms -> 8 ms is noise, not a regression).


def budget(previous: float) -> float:
    """A solver's time budget on an entry, from its time there in the previous replay."""
    return max(SLOW_FLOOR_S, SLOW_FACTOR * previous)


def corpus_root() -> Path:
    return default_path().parent / "corpus"


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:96].strip("._") or "unknown"


def record(
    challenge_id: str, challenge: Any, attempt: Any, artifact: bytes,
    deliveries: tuple[Member, ...], accepted: dict[str, str], secrets: tuple[str, ...] = (),
    root: Path | None = None,
) -> Path | None:
    """Save one scored assignment; returns its directory, or None when nothing was kept."""
    if not accepted or not isinstance(attempt, dict):
        return None
    files = list(deliveries) or [Member("delivery 1: artifact.bin", artifact)]
    if sum(len(member.data) for member in files) > MAX_ENTRY_BYTES:
        return None
    route = (root or corpus_root()) / _safe(challenge_id)
    attempt_id = str(attempt.get("attempt_id") or attempt.get("id") or "attempt")
    entry = route / _safe(attempt_id)
    if not entry.exists():
        existing = [path for path in route.iterdir() if path.is_dir()] if route.exists() else []
        if len(existing) >= MAX_ENTRIES_PER_ROUTE:
            return None
        (entry / "deliveries").mkdir(parents=True)
        (entry / "assignment.json").write_text(json.dumps(
            safe_value({"challenge": challenge, "attempt": attempt}, secrets), indent=1, sort_keys=True,
        ), encoding="utf-8")
        for index, member in enumerate(files, 1):
            name = re.sub(r"^delivery \d+:\s*", "", member.name)
            (entry / "deliveries" / f"{index}-{_safe(name)}").write_bytes(member.data)
    known = _read(entry / "accepted.json")
    known.update(accepted)  # A later partial or learn run adds the kinds it got accepted.
    (entry / "accepted.json").write_text(json.dumps(known, indent=1, sort_keys=True), encoding="utf-8")
    return entry


def _read(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def entries(root: Path | None = None, only: str = "") -> list[Path]:
    base = root or corpus_root()
    found = sorted(path.parent for path in base.glob("*/*/assignment.json"))
    return [path for path in found if only in str(path.relative_to(base))]


def solve_entry(
    entry: Path, previous: dict[str, float] | None = None,
) -> tuple[dict[str, str], tuple[str, ...], dict[str, float], list[Any]]:
    """The current solvers' selected answers for a saved assignment, fully offline, with the
    seconds of each solver that ran fine and the watchdog Outcomes of those that did not.

    A solver over its budget against `previous` is timed once more on its own and the faster
    time counts: a busy machine (a sweep running beside a deploy) must not stop a deploy.
    """
    from .autopilot import build_context, select_candidates
    from .solvers import SOLVERS
    from .watchdog import run_solvers, solver_name
    from .state import AttemptState

    saved = _read(entry / "assignment.json")
    challenge, attempt = saved.get("challenge") or {}, saved.get("attempt") or {}
    files = sorted((entry / "deliveries").iterdir(), key=lambda path: int(path.name.split("-", 1)[0]))
    members = tuple(Member(f"delivery {path.name.split('-', 1)[0]}: {path.name.split('-', 1)[1]}", path.read_bytes())
                    for path in files)
    answer_ids = AttemptState.parse(attempt).answer_ids
    extra = members if len(members) > 1 else ()
    context, _ = build_context(str(challenge.get("id") or entry.parent.name), challenge, attempt,
                               members[0].data, files[0], answer_ids, None, extra)
    candidates, outcomes = run_solvers(SOLVERS, context)
    failed = [outcome for outcome in outcomes if outcome.status != "ok"]
    for outcome in failed:  # One lane's crash or hang is a finding, not the end of the replay.
        print(f"  {outcome.note()}")
    seconds = {outcome.solver: outcome.seconds for outcome in outcomes if outcome.status == "ok"}
    for solver in SOLVERS:
        name = solver_name(solver)
        if name in seconds and name in (previous or {}) and seconds[name] > budget(previous[name]):
            _, again = run_solvers([solver], context)
            if again and again[0].status == "ok":
                seconds[name] = min(seconds[name], again[0].seconds)
    selected, _ = select_candidates(candidates, answer_ids, [])
    return {candidate.answer_id: candidate.answer for candidate in selected}, answer_ids, seconds, failed


def _timing(entry: Path) -> dict[str, float]:
    return {name: float(value) for name, value in _read(entry / "last_timing.json").items()
            if isinstance(value, (int, float)) and not isinstance(value, bool)}


def replay(entry: Path, keep: bool = True) -> dict[str, Any]:
    """Re-solve one entry; compare with the accepted answers and with the previous replay.

    `slower` names each solver over its budget, `broke` the watchdog notes of solvers that
    ran fine in the previous replay and now crash or hang.
    """
    timing = _timing(entry)
    answers, answer_ids, seconds, failed = solve_entry(entry, timing)
    accepted = _read(entry / "accepted.json")
    previous = _read(entry / "last_replay.json")
    equal = [key for key, value in accepted.items() if answers.get(key) == value]
    differs = {key: (answers[key], value) for key, value in accepted.items() if key in answers and answers[key] != value}
    regressions = sorted(
        key for key in previous
        if (previous[key] == accepted.get(key) and answers.get(key) != previous[key]) or key not in answers
    )
    slower = {name: {"seconds": round(value, 3), "previous": timing[name], "budget": round(budget(timing[name]), 3)}
              for name, value in seconds.items() if name in timing and value > budget(timing[name])}
    broke = [outcome.note() for outcome in failed if outcome.solver in timing]
    if keep:
        (entry / "last_replay.json").write_text(json.dumps(answers, indent=1, sort_keys=True), encoding="utf-8")
        (entry / "last_timing.json").write_text(json.dumps(
            {name: round(value, 4) for name, value in seconds.items()}, indent=1, sort_keys=True), encoding="utf-8")
    return {"entry": entry, "questions": len(answer_ids), "answered": len(answers), "accepted": len(accepted),
            "equal": len(equal), "differs": differs, "regressions": regressions,
            "missing": sorted(set(answer_ids) - set(answers)), "seconds": seconds, "slower": slower, "broke": broke}


def import_entry(
    challenge_id: str, lane: str, start_json: Path, artifact_files: list[Path],
    submit_logs: list[Path], root: Path | None = None,
) -> Path | None:
    """Add older material (a saved start/status JSON, its files and JSONL submit logs)."""
    attempt = _read(start_json)
    accepted: dict[str, str] = {}
    for log in submit_logs:
        for line in log.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if str(row.get("result", "")).casefold() in ("accepted", "correct") and isinstance(row.get("answers"), dict):
                accepted.update(row["answers"])
    attempt.setdefault("answer_ids", [q["id"] for q in attempt.get("questions", []) if isinstance(q, dict)])
    if len(artifact_files) > 1 and not attempt.get("artifacts"):
        attempt["artifacts"] = [{"filename": path.name} for path in artifact_files]
    deliveries = tuple(Member(f"delivery {index}: {path.name}", path.read_bytes())
                       for index, path in enumerate(artifact_files, 1))
    challenge = {"id": challenge_id, "lane": lane, "day": int(re.search(r"day-(\d+)", challenge_id)[1])
                 if re.search(r"day-(\d+)", challenge_id) else None}
    return record(challenge_id, challenge, attempt, deliveries[0].data, deliveries, accepted, root=root)
