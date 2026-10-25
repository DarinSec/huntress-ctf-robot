"""Shared attempt helpers: outcome codes, challenge lookup, and candidate selection.

The solve flow itself (untimed and timed) lives in fastpath.py.
"""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import re
from typing import Any

from .client import GameMasterError
from .containers import LazyMembers, Member, passwords_from
from .solvers import AnswerCandidate, SolveContext, instruction_text
from .state import AttemptState

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


# Live IDs name their lane and day: "warmups-day-01", "script-analysis-day-01-native-signals/mastery".
_ID_LANE_DAY = re.compile(r"^(?P<lane>[a-z0-9]+(?:-[a-z0-9]+)*?)-day-(?P<day>\d{1,2})(?=$|[-/])")


def list_filters(challenge_id: str) -> tuple[int | None, str | None]:
    """(day, lane) the ID states, or (None, None) for IDs such as "welcome-robots"."""
    match = _ID_LANE_DAY.match(challenge_id)
    if not match or not 1 <= int(match["day"]) <= 31:
        return None, None
    return int(match["day"]), match["lane"]


def lookup_challenge(client: Any, challenge_id: str) -> tuple[dict[str, Any], Any]:
    """(record, listing) from the smallest list that holds the challenge.

    The server's list time grows with its size: about 1 s for one day and lane, 4 s for a
    day, 80 s for every day. So ask for the ID's own day and lane first, widening only when
    a narrower list does not hold it.

    Web Exploitation challenges are not listed under their calendar `day-NN` filter (day 1
    of the web lane comes back empty, and the day's full list has no web lane at all), yet
    they do turn up in a lane-wide listing. So fall back lane-only, then day-only, and only
    as a last resort the whole catalogue -- a day-ful lane the day filter hides still
    resolves instead of failing "not uniquely found". An ID without a day needs the full
    list straight away.
    """
    day, lane = list_filters(challenge_id)
    if day is not None:
        # Cheapest first; later entries only run when an earlier one does not hold it.
        # The lane-only fallback also resolves a web challenge the day filter hides,
        # so the web lane needs no special case here.
        tries = [{"day": day, "lane": lane}, {"lane": lane}, {"day": day}, {}]
    else:
        tries = [{}]
    for filters in tries[:-1]:
        try:
            listing = client.list_challenges(**filters)
            return find_challenge(listing, challenge_id), listing
        except GameMasterError:
            # Either the filter is empty/does not hold it, or the server rejects it (a lane
            # named differently from the ID -- "binary-reverse-engineering" lists as
            # "binary" -- answers HTTP 400 invalid_lane). Widen and try the next listing.
            continue
    listing = client.list_challenges(**tries[-1])
    return find_challenge(listing, challenge_id), listing


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
    extra_members: tuple[Member, ...] = (),
) -> tuple[SolveContext, LazyMembers]:
    """Solver input whose archive members unpack in memory on first use.

    Returns the members object too; its `notes` (unpacking notes) are read after the
    race. `extra_members` are separate deliveries of a multi-delivery assignment, named
    the way its questions refer to them ("delivery 2: blob.txt").
    """
    context = SolveContext(
        challenge_id, challenge, attempt, artifact, artifact_path, answer_ids, hint=hint,
    )
    members = LazyMembers(artifact, passwords_from(instruction_text(context)), extra_members)
    return replace(context, members=members), members
