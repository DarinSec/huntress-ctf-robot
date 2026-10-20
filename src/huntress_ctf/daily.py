"""Run every available challenge in one go: untimed solves, or races for proven solvers."""

from __future__ import annotations

from pathlib import Path
import time
from typing import Any, Callable

from .autopilot import COMPLETE, CONFLICT, EXPIRED, INCORRECT, PENDING, UNRESOLVED
from .client import GameMasterClient, GameMasterError
from .display import print_result
from .fastpath import run_fast
from .hints import load_hints
from .state import AttemptState, mode_name

# Lanes whose solver answers every variant of a day once its Single Solve scored
# (warmups learns the day's line chain from that hint; metadata parses any variant).
COURSE_LANES = {"warmups", "metadata-forensics"}

OUTCOMES = {
    COMPLETE: "complete", UNRESOLVED: "unresolved", INCORRECT: "incorrect",
    EXPIRED: "expired", CONFLICT: "conflict", PENDING: "pending",
}


def _records(response: Any) -> list[dict[str, Any]]:
    records = response.get("challenges", response.get("items")) if isinstance(response, dict) else response
    if not isinstance(records, list):
        raise GameMasterError("The challenge list has an unsupported structure.")
    return [record for record in records if isinstance(record, dict)]


def eligibility(record: dict[str, Any], timed: bool, hints: dict[str, Any]) -> str | None:
    """None when the challenge may run; otherwise the reason it is skipped."""
    challenge_id = record.get("id", record.get("challenge_id"))
    if not isinstance(challenge_id, str) or not challenge_id.strip():
        return "no usable challenge ID"
    supports_timed = record.get("run_for_time_supported") is True
    mode = mode_name(record, AttemptState())
    if timed:
        # Older Time Trial and Mastery routes are timed by default: a plain retry races.
        if not supports_timed and mode not in ("Time Trial", "Mastery Mode"):
            return "this route has no timed mode"
        if challenge_id in hints:
            return None
        # A new day: its Single Solve scored with a lane solver that handles every
        # variant of the course, so its Time Trial and Mastery may race straight away.
        single = challenge_id.split("/", 1)[0]
        if single != challenge_id and single in hints and record.get("lane") in COURSE_LANES:
            return None
        return "no proven solver yet; solve it untimed first"
    if record.get("solved") is True:
        # The list says so; a start would only reconnect, at ~0.7 s per request.
        return "already solved"
    if supports_timed or mode == "Single Solve":
        return None
    # On older routes an ordinary start is timed, so a batch must not open one.
    return "an ordinary start may begin a timer on this route"


def run_daily(
    client: GameMasterClient, *, day: int | None = None, lane: str | None = None,
    timed: bool = False, artifact_dir: Path = Path("artifacts"), work_dir: Path = Path("work"),
    hints_path: Path | None = None, capture_dir: Path | None = None,
    clock: Callable[[], float] = time.perf_counter, pipeline: bool = True,
    repeat: int = 1, gate_ms: float | None = None, gate_wait: float = 600.0,
) -> int:
    """`repeat` (timed) races each challenge that many times: Hall of Fame keeps the best.

    The summary's `on_clock_ms` is the server-clock estimate per race (started_at ->
    submit sent); `wall_seconds` is the whole command, which also covers free parts.
    """
    records = _records(client.list_challenges(day, lane))
    hints = load_hints(hints_path)
    summary: list[dict[str, Any]] = []
    for record in records:
        challenge_id = record.get("id", record.get("challenge_id"))
        reason = eligibility(record, timed, hints)
        if reason is not None:
            summary.append({"challenge": challenge_id, "outcome": "skipped", "reason": reason})
            continue
        began = clock()
        on_clock: list[float] = []
        try:
            for number in range(1, (max(repeat, 1) if timed else 1) + 1):
                print(f"\n===== {challenge_id} ({'timed race ' + str(number) if timed else 'untimed'}) =====")
                report: dict[str, Any] = {}
                # The record from this list is passed on, so no run fetches the list again.
                code = run_fast(
                    client, challenge_id, timed=timed, challenge=record,
                    artifact_dir=artifact_dir, work_dir=work_dir, hints_path=hints_path,
                    capture_dir=capture_dir, clock=clock, pipeline=pipeline,
                    gate_ms=gate_ms, gate_wait=gate_wait, report=report,
                )
                measured = (report.get("server_clock_ms") or {}).get("from")
                if measured is not None:
                    on_clock.append(measured)
                if code != COMPLETE:
                    break
            entry = {"challenge": challenge_id, "outcome": OUTCOMES.get(code, str(code))}
        except GameMasterError as exc:
            entry = {"challenge": challenge_id, "outcome": "error", "reason": str(exc)}
        if on_clock:
            entry["on_clock_ms"] = on_clock
            entry["best_on_clock_ms"] = min(on_clock)
        entry["wall_seconds"] = round(clock() - began, 3)
        summary.append(entry)
    print("\n===== Summary =====")
    print_result({"mode": "timed" if timed else "untimed", "challenges": summary})
    ran = [entry for entry in summary if entry["outcome"] != "skipped"]
    return COMPLETE if all(entry["outcome"] == "complete" for entry in ran) else UNRESOLVED
