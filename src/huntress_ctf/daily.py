"""Run every available challenge in one go: untimed solves, or races for proven solvers."""

from __future__ import annotations

from pathlib import Path
import time
from typing import Any, Callable

from .autopilot import COMPLETE, CONFLICT, EXPIRED, INCORRECT, PENDING, UNRESOLVED, run_autopilot
from .client import GameMasterClient, GameMasterError
from .display import print_result
from .fastpath import run_timed_fast
from .hints import load_hints
from .state import AttemptState, mode_name

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
    if timed:
        if not supports_timed:
            return "the route does not advertise run_for_time_supported"
        if challenge_id not in hints:
            return "no proven solver yet; solve it untimed first"
        return None
    if supports_timed or mode_name(record, AttemptState()) == "Single Solve":
        return None
    # On older routes an ordinary start is timed, so a batch must not open one.
    return "an ordinary start may begin a timer on this route"


def run_daily(
    client: GameMasterClient, *, day: int | None = None, lane: str | None = None,
    timed: bool = False, artifact_dir: Path = Path("artifacts"), work_dir: Path = Path("work"),
    hints_path: Path | None = None, capture_dir: Path | None = None,
    clock: Callable[[], float] = time.perf_counter,
) -> int:
    records = _records(client.list_challenges(day, lane))
    hints = load_hints(hints_path)
    summary: list[dict[str, Any]] = []
    for record in records:
        challenge_id = record.get("id", record.get("challenge_id"))
        reason = eligibility(record, timed, hints)
        if reason is not None:
            summary.append({"challenge": challenge_id, "outcome": "skipped", "reason": reason})
            continue
        print(f"\n===== {challenge_id} ({'timed' if timed else 'untimed'}) =====")
        began = clock()
        try:
            if timed:
                code = run_timed_fast(
                    client, challenge_id, artifact_dir=artifact_dir, work_dir=work_dir,
                    hints_path=hints_path, capture_dir=capture_dir, clock=clock,
                )
            else:
                code = run_autopilot(
                    client, challenge_id, artifact_dir=artifact_dir, work_dir=work_dir,
                    hints_path=hints_path, capture_dir=capture_dir,
                )
            entry = {"challenge": challenge_id, "outcome": OUTCOMES.get(code, str(code))}
        except GameMasterError as exc:
            entry = {"challenge": challenge_id, "outcome": "error", "reason": str(exc)}
        entry["seconds"] = round(clock() - began, 3)
        summary.append(entry)
    print("\n===== Summary =====")
    print_result({"mode": "timed" if timed else "untimed", "challenges": summary})
    ran = [entry for entry in summary if entry["outcome"] != "skipped"]
    return COMPLETE if all(entry["outcome"] == "complete" for entry in ran) else UNRESOLVED
