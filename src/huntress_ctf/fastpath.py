"""Timed attempts: only start, download, solve, and one submission run on the server clock.

The server clock starts when the timed attempt is created and stops when a correct
answer arrives. Everything that does not depend on the new attempt (listing, status,
route choice, solver warm-up, connection setup) happens before the clock; all output,
file writes, and the final status check happen after the submission response.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import gc
import hashlib
import json
from pathlib import Path
import time
from typing import Any, Callable

from .artifacts import artifact_path, artifact_summary, save_artifact
from .autopilot import (
    COMPLETE, CONFLICT, INCORRECT, PENDING, UNRESOLVED, build_context, find_challenge,
    select_candidates, terminal_result,
)
from .capture import save_capture
from .client import GameMasterClient, GameMasterError
from .containers import Member
from .display import print_result
from .hints import get_hint, record_hint
from .solvers import LOAD_ERRORS, SOLVERS, AnswerCandidate, Solver, SolveContext
from .state import AttemptState, current_fields, mode_name, remember_identity
from .workspace import write_workspace

KNOWN_OUTCOMES = {"correct", "accepted", "incorrect", "expired"}
REMAINING_FIELDS = ("ranked_attempts_remaining", "unique_attempts_remaining")


@dataclass
class TimedRun:
    route: str = "start"
    marks: dict[str, float] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    attempt: Any = None
    started: AttemptState | None = None
    artifact: bytes | None = None
    members: tuple[Member, ...] = ()
    unpack_notes: tuple[str, ...] = ()
    selected: list[AnswerCandidate] = field(default_factory=list)
    conflict: bool = False
    submitted: dict[str, str] = field(default_factory=dict)
    result: Any = None


def plan_route(before: Any, challenge: dict[str, Any]) -> tuple[str, str | None]:
    """Choose 'start' or 'retry', or 'pending'/'stop' with a reason, before the clock starts.

    `start` only reconnects to the current attempt and never changes its mode, so a new
    timed run after a completed or expired attempt needs `retry` with run_for_time.
    """
    try:
        state = AttemptState.parse(before)
        fields = current_fields(before)
    except GameMasterError:
        return "start", None
    remaining = next((
        source[name] for source in (fields, challenge) for name in REMAINING_FIELDS
        if type(source.get(name)) is int
    ), None)
    if state.pending:
        return "pending", "CourseStack scoring is still pending; keep this attempt until it is confirmed."
    if state.complete or state.expired:
        if remaining == 0:
            return "stop", "No fresh timed variant remains for this challenge."
        return "retry", None
    active = not state.inactive and (state.attempt_id is not None or bool(state.answer_ids))
    if active and not state.deadline:
        return "stop", "A regular untimed attempt is active. Finish it first with `solve <id>`, then race."
    return "start", None


def warm_up(solvers: tuple[Solver, ...]) -> None:
    """Run every code path once before the clock: imports, regex caches, allocations."""
    dummy = SolveContext(
        "warm-up", {}, {"answer_ids": ["warm-up"]}, b"d2FybS11cA==", Path("warm-up"), ("warm-up",),
    )
    for solver in solvers:
        try:
            solver.solve(dummy)
        except Exception:
            pass
    hashlib.sha256(b"warm-up").hexdigest()
    json.loads(json.dumps({"warm": "up"}))


def _workable(state: AttemptState) -> bool:
    return bool(state.answer_ids) and not (
        state.expired or state.pending or state.complete or state.inactive
    )


def _race(
    client: GameMasterClient, challenge_id: str, challenge: dict[str, Any],
    run: TimedRun, artifact_dir: Path, hint: dict[str, Any] | None,
    clock: Callable[[], float],
) -> None:
    """The on-clock critical path. No output, no disk, no extra requests."""
    begin = client.retry if run.route == "retry" else client.start
    run.marks["start sent"] = clock()
    run.attempt = begin(challenge_id, timed=True)
    run.marks["start received"] = clock()
    run.started = AttemptState.parse(run.attempt)
    if not _workable(run.started):
        return
    run.artifact = client.artifact(challenge_id)
    run.marks["artifact received"] = clock()
    digest = hashlib.sha256(run.artifact).hexdigest()
    if run.started.artifact_sha256 and run.started.artifact_sha256 != digest:
        raise GameMasterError("Downloaded bytes do not match the assigned artifact SHA-256.")
    answer_ids = run.started.answer_ids
    context, run.unpack_notes = build_context(
        challenge_id, challenge, run.attempt, run.artifact,
        artifact_path(challenge_id, digest, artifact_dir), answer_ids, hint,
    )
    run.members = context.members
    needed = set(answer_ids) - run.started.accepted_ids
    proven_names = set((hint or {}).get("solvers") or ())
    proven = tuple(s for s in SOLVERS if getattr(s, "name", None) in proven_names)
    others = tuple(s for s in SOLVERS if getattr(s, "name", None) not in proven_names)
    candidates = [candidate for solver in proven for candidate in solver.solve(context)]
    run.selected, run.conflict = select_candidates(candidates, answer_ids, run.notes)
    if proven and not run.conflict and needed <= {c.answer_id for c in run.selected}:
        run.notes.append("The proven solver answered every open question; other solvers were skipped.")
    else:
        candidates += [candidate for solver in others for candidate in solver.solve(context)]
        run.notes.clear()
        run.selected, run.conflict = select_candidates(candidates, answer_ids, run.notes)
    run.submitted = {
        candidate.answer_id: candidate.answer for candidate in run.selected
        if candidate.answer_id in needed
    }
    run.marks["solved"] = clock()
    if run.submitted:
        run.result = client.submit_many(challenge_id, run.submitted)
        run.marks["submit received"] = clock()


def _timings(marks: dict[str, float]) -> dict[str, float]:
    spans = (
        ("start_round_trip", "start sent", "start received"),
        ("artifact_download", "start received", "artifact received"),
        ("solve", "artifact received", "solved"),
        ("submit_round_trip", "solved", "submit received"),
        ("start_response_to_submit_response", "start received", "submit received"),
    )
    return {
        name: round((marks[end] - marks[begin]) * 1000, 1)
        for name, begin, end in spans if begin in marks and end in marks
    }


def _report(
    client: GameMasterClient, challenge_id: str, challenge: dict[str, Any],
    before: Any, run: TimedRun, hint: dict[str, Any] | None, artifact_dir: Path,
    work_dir: Path, responses: dict[str, Any], secrets: tuple[str, ...],
) -> None:
    print("Challenge:")
    print_result(challenge, secrets)
    print("Status before start:")
    print_result(before, secrets)
    print(f"Route: {run.route}" + (" (new timed variant after the previous attempt ended)" if run.route == "retry" else ""))
    if hint:
        print(f"Proven solver: {json.dumps(hint.get('solvers'))}, chain {json.dumps(hint.get('chain'))}")
    for error in LOAD_ERRORS:
        print(f"Solver module not loaded: {error}")
    if run.attempt is not None:
        print("Assignment:")
        print_result(run.attempt, secrets)
    if run.started is not None:
        print(f"Mode: {json.dumps(mode_name(challenge, run.started), ensure_ascii=True)}")
        print(
            f"Server deadline: {json.dumps(run.started.deadline)} (timed attempt; the server clock is running)"
            if run.started.deadline else "The start response reports no deadline."
        )
        if challenge.get("run_for_time_supported") is not True:
            print("This route does not advertise run_for_time_supported; it may be timed by default.")
    if run.artifact is not None:
        try:
            path, digest = save_artifact(run.artifact, challenge_id, artifact_dir)
            print(f"Artifact: {json.dumps(str(path))}")
        except (GameMasterError, OSError) as exc:
            digest = hashlib.sha256(run.artifact).hexdigest()
            print(f"Artifact could not be saved: {exc}")
        print(f"SHA-256: {digest}")
        for line in artifact_summary(run.artifact):
            print(line)
        for note in run.unpack_notes:
            print(f"Unpack: {note}")
        if run.members:
            print(f"Unpacked {len(run.members)} member(s) in memory.")
    for note in run.notes:
        print(note)
    for candidate in run.selected:
        print_result({
            "answer_id": candidate.answer_id, "solver": candidate.solver,
            "evidence": candidate.evidence,
            "submitted": candidate.answer_id in run.submitted,
        }, secrets)
    if run.result is not None:
        print("Submission result:")
        print_result(run.result, secrets)
    outcome = run.result.get("result") if isinstance(run.result, dict) else None
    if run.artifact is not None and (run.result is None or str(outcome).casefold() == "incorrect"):
        try:
            directory = write_workspace(
                work_dir, challenge_id, challenge=challenge, attempt=run.attempt,
                artifact=run.artifact, members=run.members, notes=run.unpack_notes, secrets=secrets,
            )
            print(f"Workspace for analysis: {json.dumps(str(directory))} (start with triage.md)")
        except OSError as exc:
            print(f"Workspace could not be written: {exc}")
    if run.attempt is not None:
        try:
            responses["after"] = current = client.status(challenge_id)
            print("Current status:")
            print_result(current, secrets)
        except GameMasterError as exc:
            print(f"Status after the run is unavailable: {exc}")
    print_result({"timings_ms": _timings(run.marks)})


def _outcome(run: TimedRun, challenge_id: str, hints_path: Path | None) -> int:
    started = run.started
    if started is None:
        raise GameMasterError("The timed start did not complete.")
    terminal = terminal_result(started)
    if terminal is not None:
        return terminal
    answer_ids = started.answer_ids
    if not answer_ids:
        print("No answer_ids were issued by start. This route needs additional instructions or a CourseStack submission.")
        return UNRESOLVED
    if run.result is None:
        print("No unambiguous supported solution. The current attempt is preserved; its clock keeps running.")
        return CONFLICT if run.conflict else UNRESOLVED
    result = run.result
    if not isinstance(result, dict) or not isinstance(result.get("result"), str):
        raise GameMasterError("Submission returned no recognized result.")
    outcome = result["result"].casefold()
    if outcome not in KNOWN_OUTCOMES:
        raise GameMasterError("Submission returned an unknown result; completion is unconfirmed.")
    state = AttemptState.parse(result)
    remember_identity(started, state)
    if not state.accepted_ids.issubset(answer_ids):
        raise GameMasterError("Submission contains accepted IDs outside this assignment.")
    terminal = terminal_result(state)
    if terminal is not None:
        if outcome == "correct" and terminal in (COMPLETE, PENDING):
            note = record_hint(
                challenge_id, [c for c in run.selected if c.answer_id in run.submitted], hints_path,
            )
            if note:
                print(note)
        return terminal
    if outcome == "incorrect":
        print("Answer rejected. It will not be resubmitted in this run.")
        return INCORRECT
    accepted = set(started.accepted_ids | state.accepted_ids)
    if outcome == "accepted" and not state.accepted_ids:
        accepted.update(run.submitted)
    print_result({
        "completion": "unconfirmed",
        "unresolved_answer_ids": [item for item in answer_ids if item not in accepted],
        "server_remaining": state.remaining,
    })
    return CONFLICT if run.conflict else UNRESOLVED


def run_timed_fast(
    client: GameMasterClient, challenge_id: str, *,
    artifact_dir: Path = Path("artifacts"), work_dir: Path = Path("work"),
    hints_path: Path | None = None, capture_dir: Path | None = None,
    clock: Callable[[], float] = time.perf_counter,
) -> int:
    secrets = (client.token,) if client.token else ()
    responses: dict[str, Any] = {}
    # Before the clock. These requests also leave the connection warm for start.
    responses["list"] = listing = client.list_challenges()
    challenge = find_challenge(listing, challenge_id)
    try:
        responses["before"] = before = client.status(challenge_id)
    except GameMasterError as exc:
        before = {"unavailable": str(exc)}
    run = TimedRun()
    run.route, reason = plan_route(before, challenge)
    if run.route in ("pending", "stop"):
        print("Challenge:")
        print_result(challenge, secrets)
        print("Status before start:")
        print_result(before, secrets)
        print(f"No timed run was started: {reason}")
        return PENDING if run.route == "pending" else UNRESOLVED
    hint = get_hint(challenge_id, hints_path)
    warm_up(SOLVERS)
    collecting = gc.isenabled()
    gc.disable()  # No collector pauses on the clock; the race allocates little.
    try:
        _race(client, challenge_id, challenge, run, artifact_dir, hint, clock)
    finally:
        if collecting:
            gc.enable()
        responses["attempt"], responses["result"] = run.attempt, run.result
        _report(client, challenge_id, challenge, before, run, hint, artifact_dir, work_dir, responses, secrets)
        if capture_dir is not None:
            responses = {key: value for key, value in responses.items() if value is not None}
            print(f"Capture: {json.dumps(str(save_capture(capture_dir, 'timed', responses, secrets)))}")
    return _outcome(run, challenge_id, hints_path)
