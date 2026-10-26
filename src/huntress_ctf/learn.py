"""Find out which of the robot's answer conventions the service accepts, kind by kind.

A Mastery request is accepted only when every answer in it is right (19 Oct 2026), so a
single wrong convention hides behind "incorrect" for the whole bundle. `learn` sends the
robot's one answer per question again grouped by question kind, one request per kind,
in a single attempt, and prints which kinds the service accepts. Nothing is guessed:
each question gets the answer a race would send, and no request is ever repeated.
It spends one variant (or reconnects to an active attempt), so it is opt-in.

A rejected kind is then split in halves until the refused answers are named
(`rejected_answer_ids`): one wrong answer among fifteen no longer holds the other
fourteen open, and the lane owner is pointed at the one question to fix.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
from typing import Any, Callable

from .autopilot import COMPLETE, UNRESOLVED, build_context, lookup_challenge, select_candidates
from .client import GameMasterClient, GameMasterError
from .containers import Member
from .display import print_result
from .hints import record_hint
from .solvers import SOLVERS
from .watchdog import run_solvers
from .state import AttemptState, deliveries


def kind_of(answer_id: str) -> str:
    """The question kind an answer ID names: "set3.d04-jpeg-001-jpeg-sof-..." -> "d#-jpeg-#-jpeg-sof-..."."""
    return re.sub(r"\d+", "#", re.sub(r"^set\d+\.", "", answer_id))


def field_of(answer_id: str) -> str:
    """A coarser kind for IDs that name one question each: "resource-attack" -> "attack"."""
    base = re.sub(r"^set\d+\.", "", answer_id)
    return re.sub(r"\d+", "#", base.rsplit("-", 1)[-1])


# Script Analysis IDs carry no digits ("resource-attack"), so kind_of makes one kind per
# question: 1,373 requests on day 21. Past this many kinds, group by field instead.
MAX_KIND_REQUESTS = 80

# A rejected kind is split to find the answers the service actually refuses, and those
# answers are then offered the solver's other spellings: this many requests each at most
# (~0.3 s per request from the Homebase).
MAX_SPLIT_REQUESTS = 24
MAX_ALTERNATIVE_REQUESTS = 24


def _rejected_ids(
    send: Callable[[dict[str, str]], str], answers: dict[str, str], budget: list[int],
) -> list[str]:
    """The answer IDs a rejected all-or-nothing group owes its rejection to.

    One request says only whether a whole set is right, so each half goes back on its
    own: an accepted half stays accepted and is dropped, a rejected half is split again.
    One wrong answer among 15 takes about eight requests, and the other 14 are banked on
    the way. Returns the smallest set the budget could pin the rejection to.
    """
    ids = sorted(answers)
    if len(ids) < 2:
        return ids
    middle = len(ids) // 2
    rejected: list[str] = []
    for half in (ids[:middle], ids[middle:]):
        if budget[0] < 1:
            rejected += half  # Out of requests: this half is not localized further.
            continue
        budget[0] -= 1
        part = {answer_id: answers[answer_id] for answer_id in half}
        outcome = send(part)
        if outcome == "incorrect":
            rejected += _rejected_ids(send, part, budget)
        elif outcome in ("correct", "expired"):
            budget[0] = 0  # The attempt ended; stop asking.
    return rejected or ids  # Every half accepted: the kind is only rejected as a whole.


def run_learn(
    client: GameMasterClient, challenge_id: str, *, hints_path: Path | None = None,
    challenge: dict[str, Any] | None = None, open_only: bool = False,
) -> int:
    """`open_only` (after an untimed "incorrect"): only the open attempt, never a new one."""
    if challenge is None:
        challenge, _ = lookup_challenge(client, challenge_id)
    before = AttemptState.parse(client.status(challenge_id))
    if before.pending:
        print("CourseStack scoring is pending; nothing was started.")
        return UNRESOLVED
    if open_only and (before.complete or before.expired):
        print("The attempt is no longer open; nothing was resent.")
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
    found, outcomes = run_solvers(SOLVERS, context)
    for outcome in outcomes:
        if outcome.status != "ok":
            print(outcome.note())
    selected, conflict = select_candidates(found, state.answer_ids, [])
    open_ids = set(state.answer_ids) - state.accepted_ids
    kind = kind_of
    if len({kind_of(c.answer_id) for c in selected if c.answer_id in open_ids}) > MAX_KIND_REQUESTS:
        kind = field_of
    groups: dict[str, dict[str, str]] = defaultdict(dict)
    for candidate in selected:
        if candidate.answer_id in open_ids:
            groups[kind(candidate.answer_id)][candidate.answer_id] = candidate.answer
    # Nothing to gain from resending one answer of one kind unchanged - unless its solver
    # offers another spelling, which is exactly the case of a single open question whose
    # convention the service refuses (day 23 Metadata: one of 28).
    spellings_left = any(candidate.alternatives for candidate in selected if candidate.answer_id in open_ids)
    if open_only and len(groups) < 2 and not spellings_left \
            and all(len(answers) < 2 for answers in groups.values()):
        print("One kind with one answer and no other spelling: resending it would change nothing.")
        return UNRESOLVED
    unanswered = sorted({kind(answer_id) for answer_id in open_ids} - set(groups))
    report: dict[str, Any] = {"deadline": state.deadline, "conflict": conflict, "kinds": {}}
    final = None
    budget = [MAX_SPLIT_REQUESTS]
    rejected: list[str] = []

    def send(answers: dict[str, str]) -> str:
        """One request of a split, as the per-kind loop sends one of a kind."""
        nonlocal final
        result = client.submit_many(challenge_id, answers)
        final = (str(result.get("result")) if isinstance(result, dict) else "unknown").casefold()
        return final

    for kind in sorted(groups):
        try:
            result = client.submit_many(challenge_id, groups[kind])
        except GameMasterError as exc:
            report["kinds"][kind] = f"error: {exc}"
            break
        outcome = str(result.get("result")) if isinstance(result, dict) else "unknown"
        entry: dict[str, Any] = {
            "answers": len(groups[kind]), "result": outcome, "remaining": result.get("remaining"),
        }
        report["kinds"][kind] = entry
        final = outcome.casefold()
        # A rejected kind hides which of its answers is wrong, and the right ones stay
        # unaccepted with it. Splitting banks those and names the rest for the lane owner.
        if final == "incorrect" and len(groups[kind]) > 1 and budget[0] > 0:
            try:
                wrong = _rejected_ids(send, groups[kind], budget)
            except GameMasterError as exc:
                entry["split"] = f"error: {exc}"
            else:
                entry["rejected_answer_ids"] = wrong
                entry["accepted_by_splitting"] = len(groups[kind]) - len(wrong)
                rejected += wrong
        elif final == "incorrect" and len(groups[kind]) == 1:
            rejected += list(groups[kind])
        if final in ("correct", "expired"):
            break
    # A rejected answer whose solver offers other spellings of the same evidence (a
    # machine field as a label, a decimal or a hex code: which one the grader takes is
    # not in the bytes) gets them one request each, so the day is not lost to a spelling.
    spellings = [MAX_ALTERNATIVE_REQUESTS]
    for candidate in selected:
        if candidate.answer_id not in rejected or not candidate.alternatives or final in ("correct", "expired"):
            continue
        for spelling in candidate.alternatives:
            if spellings[0] < 1:
                break
            spellings[0] -= 1
            try:
                outcome = send({candidate.answer_id: spelling})
            except GameMasterError as exc:
                report.setdefault("alternatives", {})[candidate.answer_id] = f"error: {exc}"
                break
            if outcome != "incorrect":
                report.setdefault("alternatives", {})[candidate.answer_id] = {
                    "accepted": spelling, "instead_of": candidate.answer, "solver": candidate.solver,
                }
                rejected.remove(candidate.answer_id)
                break
    if rejected:
        report["rejected_answer_ids"] = sorted(rejected)
    report["no_answer_from_the_robot"] = unanswered
    print_result(report)
    if final == "correct":
        note = record_hint(challenge_id, selected, hints_path)
        if note:
            print(note)
        return COMPLETE
    return UNRESOLVED
