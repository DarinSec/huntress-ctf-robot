"""Check a new solver against the live service before the robot relies on it.

Run on the playing Homebase (it holds the robot lock and talks to the Game Master):

    PYTHONPATH=~/src python3 scripts/verify_fields.py <challenge-id> <lane> [solver-name ...]

It uses an UNTIMED attempt only (reconnects, or an untimed retry after a completed one;
it stops if a timed attempt is active), solves it with the named solvers (default: all),
groups the answers by question text (digits ignored) and submits one request per group.
A request is all-or-nothing, so "accepted" means every answer in that group was right
and "incorrect" means at least one was wrong: keep only the accepted kinds. Correct
answers stay accepted, so this also pre-fills the attempt for whoever finishes it.
Set EXCLUDE to a regex of question texts to leave out (kinds known to be wrong).
Best used on an older day's Time Trial or Mastery (same question kinds, no clock).
"""

from __future__ import annotations

import collections
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, os.environ.get("DEV_SRC", str(Path(__file__).resolve().parents[1] / "src")))

from huntress_ctf.autopilot import build_context, select_candidates  # noqa: E402
from huntress_ctf.client import GameMasterClient, GameMasterError  # noqa: E402
from huntress_ctf.lock import robot_lock  # noqa: E402
from huntress_ctf.solvers import SOLVERS  # noqa: E402
from huntress_ctf.state import AttemptState, current_fields, deliveries  # noqa: E402
from huntress_ctf.containers import Member  # noqa: E402


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    challenge_id, lane, *names = sys.argv[1:]
    exclude = re.compile(os.environ["EXCLUDE"]) if os.environ.get("EXCLUDE") else None
    client = GameMasterClient()
    with robot_lock(f"verify_fields {challenge_id}", wait=300):
        try:
            before = AttemptState.parse(client.status(challenge_id))
        except GameMasterError:  # HTTP 409 start_required: no attempt yet.
            before = AttemptState()
        attempt = client.retry(challenge_id) if before.complete or before.expired else client.start(challenge_id)
        state = AttemptState.parse(attempt)
        if state.deadline:
            print("A timed attempt is active; not verifying on the clock.")
            return 1
        listed = deliveries(attempt)
        extra = tuple(
            Member(f"delivery {number}: {item['filename']}", client.artifact(challenge_id, delivery=item["index"]))
            for number, item in enumerate(listed, 1)
        ) if len(listed) > 1 else ()
        artifact = extra[0].data if extra else client.artifact(challenge_id)
        context, _ = build_context(challenge_id, {"lane": lane}, attempt, artifact, Path("memory"),
                                   state.answer_ids, None, extra)
        candidates = [c for s in SOLVERS if not names or s.name in names for c in s.solve(context)]
        selected, conflict = select_candidates(candidates, state.answer_ids, [])
        print(f"{len(state.answer_ids)} questions, {len(selected)} answered, conflict={conflict}")
        texts = {q.get("id"): q.get("question", "") for q in current_fields(attempt).get("questions") or []}
        groups: dict[tuple[str, str], dict[str, str]] = collections.defaultdict(dict)
        for candidate in selected:
            if candidate.answer_id in state.accepted_ids:
                continue
            kind = re.sub(r"\d+", "N", texts.get(candidate.answer_id, candidate.answer_id))[:70]
            if exclude and exclude.search(kind):
                continue
            groups[(candidate.solver, kind)][candidate.answer_id] = candidate.answer
        for (solver, kind), answers in sorted(groups.items()):
            result = client.submit_many(challenge_id, answers)
            outcome = str(result.get("result")) if isinstance(result, dict) else str(result)
            print(f"{outcome:10} {len(answers):5} {solver:22} {kind}")
            if outcome.casefold() in ("correct", "already_solved"):
                break
    return 0


if __name__ == "__main__":
    sys.exit(main())
