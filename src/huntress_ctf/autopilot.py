"""Run one current attempt and distinguish completion from partial or failed work."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from typing import Any

from .artifacts import artifact_summary, save_artifact
from .capture import save_capture
from .client import GameMasterClient, GameMasterError
from .containers import passwords_from, unwrap
from .display import print_result
from .hints import get_hint, record_hint
from .solvers import LOAD_ERRORS, SOLVERS, AnswerCandidate, SolveContext, instruction_text
from .state import AttemptState, mode_name, remember_identity
from .workspace import write_workspace

COMPLETE = 0
UNRESOLVED = 3
INCORRECT = 4
EXPIRED = 5
CONFLICT = 6
PENDING = 7


def find_challenge(response: Any, challenge_id: str) -> dict[str, Any]:
    records = response
    if isinstance(response, dict):
        records = response.get("challenges", response.get("items"))
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise GameMasterError("The challenge list has an unsupported structure.")
    matches = [
        record for record in records
        if record.get("id", record.get("challenge_id")) == challenge_id
    ]
    if len(matches) != 1:
        raise GameMasterError("The selected challenge was not uniquely found in the live list.")
    return matches[0]


def terminal_result(state: AttemptState) -> int | None:
    if state.expired:
        print("The server reports an expired attempt. No retry was requested.")
        return EXPIRED
    if state.pending:
        print("CourseStack scoring is pending. Keep this attempt until scoring is confirmed.")
        return PENDING
    if state.complete:
        print("The Game Master reports completion. CourseStack remains the official points ledger.")
        return COMPLETE
    if state.inactive:
        print("This attempt is locked, unavailable, or not started.")
        return UNRESOLVED
    return None


def select_candidates(
    candidates: list[AnswerCandidate], answer_ids: tuple[str, ...],
    notes: list[str] | None = None,
) -> tuple[list[AnswerCandidate], bool]:
    """Pick one agreed candidate per ID. Messages go to `notes` when given, else stdout."""
    report = print if notes is None else notes.append
    groups: dict[str, list[AnswerCandidate]] = {}
    conflict = False
    for candidate in candidates:
        if (
            not isinstance(candidate, AnswerCandidate)
            or candidate.answer_id not in answer_ids
            or not isinstance(candidate.answer, str)
            or not candidate.answer
        ):
            report("A solver returned an invalid candidate; it will not be submitted.")
            conflict = True
            continue
        groups.setdefault(candidate.answer_id, []).append(candidate)
    selected = []
    for answer_id in answer_ids:
        options = groups.get(answer_id, [])
        if len({candidate.answer for candidate in options}) > 1:
            report(f"Solvers disagree about {json.dumps(answer_id)}; no answer will be guessed.")
            conflict = True
        elif options:
            selected.append(options[0])
    return selected, conflict


def build_context(
    challenge_id: str, challenge: dict[str, Any], attempt: Any, artifact: bytes,
    artifact_path: Path, answer_ids: tuple[str, ...], hint: dict[str, Any] | None,
) -> tuple[SolveContext, tuple[str, ...]]:
    """Solver input with archive members unpacked in memory; also returns unpack notes."""
    context = SolveContext(
        challenge_id, challenge, attempt, artifact, artifact_path, answer_ids, hint=hint,
    )
    unwrapped = unwrap(artifact, passwords_from(instruction_text(context)))
    return replace(context, members=unwrapped.members), unwrapped.notes


def run_autopilot(
    client: GameMasterClient, challenge_id: str, *,
    timed: bool = False, artifact_dir: Path = Path("artifacts"),
    work_dir: Path = Path("work"), hints_path: Path | None = None,
    capture_dir: Path | None = None,
) -> int:
    responses: dict[str, Any] = {}
    secrets = (client.token,) if client.token else ()
    try:
        return _run_autopilot(
            client, challenge_id, timed, artifact_dir, work_dir, hints_path, responses, secrets,
        )
    finally:
        if capture_dir is not None and responses:
            print(f"Capture: {json.dumps(str(save_capture(capture_dir, 'solve', responses, secrets)))}")


def _run_autopilot(
    client: GameMasterClient, challenge_id: str, timed: bool, artifact_dir: Path,
    work_dir: Path, hints_path: Path | None, responses: dict[str, Any],
    secrets: tuple[str, ...],
) -> int:
    responses["list"] = listing = client.list_challenges()
    challenge = find_challenge(listing, challenge_id)
    responses["start"] = attempt_response = client.start(challenge_id, timed=timed)
    started = AttemptState.parse(attempt_response)
    print("Challenge:")
    print_result(challenge, secrets)
    print("Assignment:")
    print_result(attempt_response, secrets)

    responses["status"] = current_response = client.status(challenge_id)
    current = AttemptState.parse(current_response)
    identity = remember_identity(started, current)
    print("Current status:")
    print_result(current_response, secrets)
    reported = current if current.mode is not None else started
    print(f"Mode: {json.dumps(mode_name(challenge, reported), ensure_ascii=True)}")
    deadline = current.deadline or started.deadline
    print(
        f"Server deadline: {json.dumps(deadline)}"
        if deadline else "The current response reports no deadline."
    )
    terminal = terminal_result(current)
    if terminal is not None:
        return terminal
    terminal = terminal_result(started)
    if terminal is not None:
        return terminal

    # The documented start response defines IDs. Never stringify or infer them.
    answer_ids = started.answer_ids
    if not answer_ids:
        print("No answer_ids were issued by start. This route needs additional instructions or a CourseStack submission.")
        return UNRESOLVED
    accepted_ids = set(started.accepted_ids | current.accepted_ids)
    if not accepted_ids.issubset(answer_ids):
        raise GameMasterError("Status contains accepted IDs outside this assignment.")

    artifact = client.artifact(challenge_id)
    digest = hashlib.sha256(artifact).hexdigest()
    for state in (started, current):
        if state.artifact_sha256 and state.artifact_sha256 != digest:
            raise GameMasterError("Downloaded bytes do not match the assigned artifact SHA-256.")
    artifact_path, _ = save_artifact(artifact, challenge_id, artifact_dir)
    print(f"Artifact: {json.dumps(str(artifact_path))}")
    print(f"SHA-256: {digest}")
    for line in artifact_summary(artifact):
        print(line)

    context, unpack_notes = build_context(
        challenge_id, challenge, attempt_response, artifact, artifact_path, answer_ids,
        get_hint(challenge_id, hints_path),
    )
    for note in unpack_notes:
        print(f"Unpack: {note}")
    if context.members:
        print(f"Unpacked {len(context.members)} member(s) in memory.")
    for error in LOAD_ERRORS:
        print(f"Solver module not loaded: {error}")
    candidates = [candidate for solver in SOLVERS for candidate in solver.solve(context)]
    selected, conflict = select_candidates(candidates, answer_ids)

    def save_workspace() -> None:
        try:
            directory = write_workspace(
                work_dir, challenge_id, challenge=challenge, attempt=attempt_response,
                artifact=artifact, members=context.members, notes=unpack_notes, secrets=secrets,
            )
            print(f"Workspace for analysis: {json.dumps(str(directory))} (start with triage.md)")
        except OSError as exc:
            print(f"Workspace could not be written: {exc}")

    if not selected:
        print("No unambiguous supported solution. The current attempt is preserved.")
        save_workspace()
        return CONFLICT if conflict else UNRESOLVED

    rejected = False
    scored: list[AnswerCandidate] = []

    def finish(code: int) -> int:
        # Remember the solvers that scored, so later and timed runs go straight to them.
        if code in (COMPLETE, PENDING) and scored:
            note = record_hint(challenge_id, scored, hints_path)
            if note:
                print(note)
        return code

    def refresh() -> AttemptState:
        nonlocal current, identity
        response = client.status(challenge_id)
        latest = AttemptState.parse(response)
        identity = remember_identity(identity, latest)
        if latest.artifact_sha256 and latest.artifact_sha256 != digest:
            raise GameMasterError("The assigned artifact changed during analysis.")
        if not latest.accepted_ids.issubset(answer_ids):
            raise GameMasterError("Status contains accepted IDs outside this assignment.")
        current = latest
        accepted_ids.update(latest.accepted_ids)
        return latest

    for candidate in selected:
        latest = refresh()
        terminal = terminal_result(latest)
        if terminal is not None:
            return finish(terminal)
        if candidate.answer_id in accepted_ids:
            continue
        if not latest.artifact_sha256:
            # Older responses may omit identity/hash fields. Re-read the assigned
            # bytes so a changed team variant cannot silently receive an old answer.
            if hashlib.sha256(client.artifact(challenge_id)).hexdigest() != digest:
                raise GameMasterError("The assigned artifact changed before submission.")
            latest = refresh()
            terminal = terminal_result(latest)
            if terminal is not None:
                return finish(terminal)
            if candidate.answer_id in accepted_ids:
                continue

        print_result({
            "submitting_answer_id": candidate.answer_id,
            "solver": candidate.solver, "evidence": candidate.evidence,
        }, secrets)
        result = client.submit(challenge_id, candidate.answer_id, candidate.answer)
        responses.setdefault("submissions", []).append(result)
        print("Submission result:")
        print_result(result, secrets)
        if not isinstance(result, dict) or not isinstance(result.get("result"), str):
            raise GameMasterError("Submission returned no recognized result.")
        outcome = result["result"].casefold()
        if outcome not in {"correct", "accepted", "incorrect", "expired"}:
            raise GameMasterError("Submission returned an unknown result; completion is unconfirmed.")
        result_state = AttemptState.parse(result)
        identity = remember_identity(identity, result_state)
        if not result_state.accepted_ids.issubset(answer_ids):
            raise GameMasterError("Submission contains accepted IDs outside this assignment.")
        accepted_ids.update(result_state.accepted_ids)
        if outcome in ("correct", "accepted"):
            scored.append(candidate)
        terminal = terminal_result(result_state)
        if terminal is not None:
            return finish(terminal)
        if outcome == "incorrect":
            rejected = True
            print("Answer rejected. This candidate will not be resubmitted in this run.")
        elif outcome == "accepted":
            accepted_ids.add(candidate.answer_id)
            print(f"Partial progress accepted; remaining: {result_state.remaining!r}.")
            latest = refresh()
            terminal = terminal_result(latest)
            if terminal is not None:
                return finish(terminal)

    print_result({
        "completion": "unconfirmed",
        "unresolved_answer_ids": [item for item in answer_ids if item not in accepted_ids],
        "server_remaining": current.remaining,
    })
    save_workspace()
    if rejected:
        return INCORRECT
    return CONFLICT if conflict else UNRESOLVED

