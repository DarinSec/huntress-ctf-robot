"""Find out which of the robot's answer conventions the service accepts, kind by kind.

A Mastery request is accepted only when every answer in it is right (19 Oct 2026), so a
single wrong convention hides behind "incorrect" for the whole bundle. `learn` sends the
robot's one answer per question again grouped by question kind, one request per kind,
in a single attempt, and prints which kinds the service accepts. Nothing is guessed:
each question gets the answer a race would send, and no request is ever repeated.
It spends one variant (or reconnects to an active attempt), so it is opt-in.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
from typing import Any

from .autopilot import COMPLETE, UNRESOLVED, build_context, lookup_challenge, select_candidates
from .client import GameMasterClient, GameMasterError
from .containers import Member
from .display import print_result
from .hints import record_hint
from .solvers import SOLVERS
from .state import AttemptState, deliveries


def kind_of(answer_id: str) -> str:
    """The question kind an answer ID names: "set3.d04-jpeg-001-jpeg-sof-..." -> "d#-jpeg-#-jpeg-sof-..."."""
    return re.sub(r"\d+", "#", re.sub(r"^set\d+\.", "", answer_id))


def run_learn(client: GameMasterClient, challenge_id: str, *, hints_path: Path | None = None) -> int:
    challenge, _ = lookup_challenge(client, challenge_id)
    before = AttemptState.parse(client.status(challenge_id))
    if before.pending:
        print("CourseStack scoring is pending; nothing was started.")
        return UNRESOLVED
    if before.complete or before.expired:
        attempt = client.retry(challenge_id, timed=challenge.get("run_for_time_supported") is True)
    else:
        attempt = client.start(challenge_id)  # Reconnects: no new variant.
    state = AttemptState.parse(attempt)
    if not state.answer_ids:
        print("The assignment issued no answer_ids.")
        return UNRESOLVED
    listed = deliveries(attempt)
    extra: tuple[Member, ...] = ()
    if len(listed) > 1:
        extra = tuple(
            Member(f"delivery {number}: {item['filename']}", client.artifact(challenge_id, delivery=item["index"]))
            for number, item in enumerate(listed, 1)
        )
        artifact = extra[0].data
    else:
        artifact = client.artifact(challenge_id)
    context, _ = build_context(
        challenge_id, challenge, attempt, artifact, Path("memory"), state.answer_ids, None, extra,
    )
    selected, conflict = select_candidates(
        [candidate for solver in SOLVERS for candidate in solver.solve(context)], state.answer_ids, [],
    )
    open_ids = set(state.answer_ids) - state.accepted_ids
    groups: dict[str, dict[str, str]] = defaultdict(dict)
    for candidate in selected:
        if candidate.answer_id in open_ids:
            groups[kind_of(candidate.answer_id)][candidate.answer_id] = candidate.answer
    unanswered = sorted({kind_of(answer_id) for answer_id in open_ids} - set(groups))
    report: dict[str, Any] = {"deadline": state.deadline, "conflict": conflict, "kinds": {}}
    final = None
    for kind in sorted(groups):
        try:
            result = client.submit_many(challenge_id, groups[kind])
        except GameMasterError as exc:
            report["kinds"][kind] = f"error: {exc}"
            break
        outcome = str(result.get("result")) if isinstance(result, dict) else "unknown"
        report["kinds"][kind] = {"answers": len(groups[kind]), "result": outcome, "remaining": result.get("remaining")}
        final = outcome.casefold()
        if final in ("correct", "expired"):
            break
    report["no_answer_from_the_robot"] = unanswered
    print_result(report)
    if final == "correct":
        note = record_hint(challenge_id, selected, hints_path)
        if note:
            print(note)
        return COMPLETE
    return UNRESOLVED
