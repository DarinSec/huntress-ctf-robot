"""The one solve engine: start, download, solve, and one submission, then the report.

The server clock of a timed attempt starts when the attempt is created and stops when a
correct answer arrives. Everything that does not depend on the new attempt (listing,
status, route choice, solver warm-up, connection setup) happens before the clock; all
output, file writes, and the final status check happen after the submission response.
Untimed solves run the same path, so `solve <id>` verifies exactly the code that races,
and an ordinary start on an older timed-by-default route is just as fast.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
import gc
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import time
from typing import Any, Callable

from .artifacts import artifact_path, artifact_summary, save_artifact
from .autopilot import (
    COMPLETE, CONFLICT, INCORRECT, PENDING, UNRESOLVED, build_context, lookup_challenge,
    select_candidates, terminal_result,
)
from .capture import save_capture
from .client import GameMasterClient, GameMasterError
from .containers import Member, passwords_from, prepare_tools, unwrap
from .decoders import clear_cache
from .display import print_result
from .hints import get_hint, record_hint
from . import corpus, network
from .solvers import LOAD_ERRORS, SOLVERS, AnswerCandidate, Solver, SolveContext
from .solvers.base import question_items
from .state import AttemptState, current_fields, deliveries, mode_name, remember_identity
from .watchdog import race_deadline, run_solvers
from .workspace import write_workspace

KNOWN_OUTCOMES = {"correct", "accepted", "incorrect", "expired"}
REMAINING_FIELDS = ("ranked_attempts_remaining", "unique_attempts_remaining")
# Lanes whose start returns live `targets[]` instead of a file to download.
TARGET_LANES = {"web-exploitation"}


def lane_of(challenge: dict[str, Any], challenge_id: str) -> str:
    return challenge.get("lane") or challenge_id.split("-day-")[0]


@dataclass
class Run:
    timed: bool = False
    # Only routes advertising run_for_time_supported accept the flag; on older timed
    # routes a plain start or retry is timed already, and the flag would be rejected.
    run_for_time: bool = False
    route: str = "start"
    deliveries: tuple[Member, ...] = ()
    unpacked: Any = None  # The lazy members; their notes are read after the clock.
    # Wall-clock stamps and the NTP offset place the server's started_at on our timeline.
    wall: dict[str, float] = field(default_factory=dict)
    clock_offset: float | None = None
    # The connection whose download won carries the submit; the slower GET may still run.
    submitter: Any = None
    straggler: Future | None = None
    # Extra kept-alive connections for parallel delivery downloads, warmed before the clock.
    helpers: list[Any] = field(default_factory=list)
    # Start and artifact share one write (saves a round trip) where the probe passed.
    pipelined: bool = False
    pipeline_failure: str | None = None
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
    # The solvers warm-up found fit to race (None: all of them); a warm-up hang is left out.
    solvers: tuple[Solver, ...] | None = None
    result: Any = None
    targets: list[Any] = field(default_factory=list)  # Web: live sites, no artifact.


def plan_route(before: Any, challenge: dict[str, Any], reserve: int = 0) -> tuple[str, str | None]:
    """Choose 'start' or 'retry', or 'pending'/'stop' with a reason, before the clock starts.

    `start` only reconnects to the current attempt and never changes its mode, so a new
    timed run after a completed or expired attempt needs `retry` with run_for_time.
    `reserve` keeps that many fresh timed variants unspent (Hall of Fame re-races); with
    a reserve, an unknown remaining count stops the run too.
    """
    try:
        state = AttemptState.parse(before)
        fields = current_fields(before)
    except GameMasterError:
        return ("stop", "The remaining timed variants are unknown, and a reserve is set.") if reserve else ("start", None)
    remaining = next((
        source[name] for source in (fields, challenge) for name in REMAINING_FIELDS
        if type(source.get(name)) is int
    ), None)
    if state.pending:
        return "pending", "CourseStack scoring is still pending; keep this attempt until it is confirmed."
    if state.complete or state.expired:
        if remaining == 0:
            return "stop", "No fresh timed variant remains for this challenge."
        if reserve and (remaining is None or remaining <= reserve):
            return "stop", f"{remaining} fresh timed variants remain; {reserve} are kept in reserve."
        return "retry", None
    active = not state.inactive and (state.attempt_id is not None or bool(state.answer_ids))
    if active and not state.deadline:
        return "stop", "A regular untimed attempt is active. Finish it first with `solve <id>`, then race."
    return "start", None


def warm_up(solvers: tuple[Solver, ...]) -> tuple[Solver, ...]:
    """Run every code path once before the clock: imports, regex caches, allocations.

    Returns the solvers fit to race. Each warm-up is tried first in a forked child the
    watchdog can kill: a solver that hangs even on this tiny dummy is broken, not slow, so it
    is reported and left out of this run (a crash on the dummy was always fine: many solvers
    reject it). The rest then warm up here, in this process, because the race's solver
    children inherit what this process has warmed. Without fork, a watched thread does both.
    """
    dummy = SolveContext(
        "warm-up", {}, {"answer_ids": ["warm-up"]}, b"d2FybS11cA==", Path("warm-up"), ("warm-up",),
    )
    setting = os.environ.get("HUNTRESS_WATCHDOG")
    if setting == "off":
        run_solvers(solvers, dummy, mode="off")
        fit = tuple(solvers)
    else:
        hung = []
        if setting != "thread" and "fork" in multiprocessing.get_all_start_methods():
            _, probed = run_solvers(solvers, dummy, budget=WARM_UP_BUDGET_S, mode="fork")
            hung = [(s, o) for s, o in zip(solvers, probed) if o.status == "timeout"]
        fit = tuple(s for s in solvers if all(s is not h for h, _ in hung))
        _, warmed = run_solvers(fit, dummy, budget=WARM_UP_BUDGET_S, mode="thread")
        stuck = [(s, o) for s, o in zip(fit, warmed) if o.status == "timeout"]
        fit = tuple(s for s in fit if all(s is not h for h, _ in stuck))
        for _, outcome in hung + stuck:
            print(f"warm-up: {outcome.note()}; left out of this run")
    prepare_tools()
    hashlib.sha256(b"warm-up").hexdigest()
    json.loads(json.dumps({"warm": "up"}))
    return fit


def solver_timings(
    artifact: bytes, question: str = "", passwords: tuple[str, ...] = (), repeat: int = 5,
) -> dict[str, Any]:
    """Offline: what unpacking and each solver cost on the clock for one local file.

    Median milliseconds over `repeat` cold runs (caches cleared, warm-up done first, as
    before a race), plus the candidates a race would submit for a single answer ID.
    """
    warm_up(SOLVERS)
    challenge = {"instructions": question} if question else {}
    answer_ids = ("answer",)
    keys = tuple(dict.fromkeys([*passwords, *passwords_from(question)]))
    samples: dict[str, list[float]] = {}
    candidates: list[AnswerCandidate] = []

    def timed(name: str, began: float) -> None:
        samples.setdefault(name, []).append((time.perf_counter() - began) * 1000)

    for round_ in range(max(1, repeat)):
        clear_cache()
        total = time.perf_counter()
        began = time.perf_counter()
        members = unwrap(artifact, keys).members
        timed("unpack", began)
        context = SolveContext(
            "local", challenge, {"answer_ids": list(answer_ids)}, artifact, Path("local"),
            answer_ids, members=members,
        )
        for solver in SOLVERS:
            began = time.perf_counter()
            found = solver.solve(context)
            timed(getattr(solver, "name", type(solver).__name__), began)
            if round_ == 0:
                candidates.extend(found)
        timed("total", total)
    notes: list[str] = []
    selected, conflict = select_candidates(candidates, answer_ids, notes)
    return {
        "bytes": len(artifact),
        "members": len(members),
        "median_ms": {name: round(sorted(values)[len(values) // 2], 2) for name, values in samples.items()},
        "would_submit": [
            {"solver": candidate.solver, "answer": candidate.answer} for candidate in selected
        ],
        "conflict": conflict,
        "notes": notes,
    }


DELIVERY_CONNECTIONS = 6
# A warm-up solve on the tiny dummy input takes milliseconds; this only ends a hang.
WARM_UP_BUDGET_S = 5.0


def _helpers(client: GameMasterClient, count: int) -> list[Any]:
    """Up to DELIVERY_CONNECTIONS - 1 extra connections; none for clients that cannot clone."""
    clone = getattr(client, "clone", None)
    return [clone() for _ in range(min(count, DELIVERY_CONNECTIONS) - 1)] if clone else []


def _fetch_deliveries(
    client: GameMasterClient, challenge_id: str, listed: list[dict[str, Any]], helpers: list[Any],
) -> tuple[Member, ...]:
    """Every delivery, SHA-checked, downloaded over several kept-alive connections at once.

    One at a time, 28 deliveries took ~20 s from Sweden against a 30 s Mastery deadline.
    Each is op=artifact&delivery=<index>; a listed capability link is the fallback.
    """
    workers = [client, *(helpers or _helpers(client, len(listed)))]
    blobs: list[bytes | None] = [None] * len(listed)

    def fetch(worker: Any, share: range) -> None:
        for index in share:
            try:
                blobs[index] = worker.artifact(challenge_id, delivery=listed[index]["index"])
            except GameMasterError:
                if not listed[index]["capability"]:
                    raise
                blobs[index] = worker.download(listed[index]["capability"])

    shares = [range(start, len(listed), len(workers)) for start in range(len(workers))]
    if len(workers) == 1:
        fetch(client, shares[0])
    else:
        with ThreadPoolExecutor(max_workers=len(workers)) as pool:
            for future in [pool.submit(fetch, worker, share) for worker, share in zip(workers, shares)]:
                future.result()  # Re-raises a failed download.
    members = []
    for number, (item, blob) in enumerate(zip(listed, blobs), 1):
        if item["sha256"] and hashlib.sha256(blob).hexdigest() != item["sha256"]:
            raise GameMasterError(f"Delivery {number} does not match its listed SHA-256.")
        members.append(Member(f"delivery {number}: {item['filename']}", blob))
    return tuple(members)


def _hedged_download(
    workers: list[Any], challenge_id: str, capability: str | None,
) -> tuple[bytes, Any, Future | None]:
    """The artifact from whichever warm connection answers first: (bytes, client, straggler).

    The server's answer time swings (0.5 s, then 3.6 s minutes later, 19 Oct 2026), so the
    same GET goes out on two warm connections and the first answer wins. GET may be
    repeated; never more than two go out, and a POST is never hedged. The winner's
    connection is idle again, so it carries the submit.
    """
    def fetch(worker: Any) -> bytes:
        if capability:
            try:
                return worker.download(capability)  # ~200 ms faster than op=artifact
            except GameMasterError:
                pass
        return worker.artifact(challenge_id)

    if len(workers) == 1:
        return fetch(workers[0]), workers[0], None
    pool = ThreadPoolExecutor(max_workers=len(workers))
    futures = {pool.submit(fetch, worker): worker for worker in workers}
    pool.shutdown(wait=False)
    failure: GameMasterError | None = None
    for future in as_completed(futures):
        try:
            data = future.result()
        except GameMasterError as exc:
            failure = exc
            continue
        others = [other for other in futures if other is not future and not other.done()]
        return data, futures[future], others[0] if others else None
    raise failure or GameMasterError("The artifact download failed.")


GATE_SAMPLES = 3
GATE_PAUSE_SECONDS = 30.0

# A web start answers before its live target is up: it reports `preparing`, with targets[]
# listed but no answer_ids and no deadline yet (AGENTS guidance). Polling status until the
# target is ready is read-only (no variant) and happens before the clock, like the gate.
TARGET_READY_BUDGET_S = 120.0
TARGET_POLL_INTERVAL_S = 1.0


def _target_not_ready(attempt: Any) -> bool:
    """True while a web start reports its target is still being prepared.

    Signalled by a `preparing` status/state, or by targets[] with no answer_ids yet: in
    either case a handler has nothing to read, so the run would report unresolved at once.
    """
    fields = current_fields(attempt)
    labels = {str(fields.get(key)).casefold() for key in ("status", "state", "result", "target_status")}
    if "preparing" in labels or fields.get("preparing") is True:
        return True
    targets = fields.get("targets")
    return bool(isinstance(targets, list) and targets) and not fields.get("answer_ids")


def _await_target_ready(
    client: GameMasterClient, challenge_id: str, run: Run, sleep: Callable[[float], None],
    *, budget_s: float = TARGET_READY_BUDGET_S, interval_s: float = TARGET_POLL_INTERVAL_S,
) -> None:
    """Poll status until the web target is prepared or the budget runs out (read-only).

    The clock has not started yet (no deadline while preparing), so this is free the way
    the gate is. A poll also counts as activity, which keeps the untimed attempt alive.
    """
    waited = 0.0
    while _target_not_ready(run.attempt) and waited < budget_s:
        sleep(interval_s)
        waited += interval_s
        try:
            run.attempt = client.status(challenge_id)
        except GameMasterError:
            break
        run.started = AttemptState.parse(run.attempt)
        fresh = current_fields(run.attempt).get("targets")
        if isinstance(fresh, list) and fresh:
            run.targets = fresh
    run.notes.append(
        f"Web target ready after ~{waited:.0f} s of polling." if not _target_not_ready(run.attempt)
        else f"Web target still preparing after {waited:.0f} s; nothing was submitted."
    )
HEDGE_MAX_BYTES = 4 * 1024 * 1024
GATE_BYTES_PER_MS = 4000  # ~4 MB/s through the Homebase proxy.


def _gate(
    client: GameMasterClient, challenge_id: str, gate_ms: float, max_wait: float,
    clock: Callable[[], float], sleep: Callable[[float], None],
) -> tuple[bool, float]:
    """Wait (before the clock) until the server answers status within gate_ms.

    The race time is almost all server answer time, and it swings by seconds within
    minutes. A variant spent while the server is slow is a wasted Hall of Fame chance.
    Returns (ready, median ms of the last probe). A large status body is transfer, not a
    slow server: the limit grows by its size at GATE_BYTES_PER_MS (day 22 Script Mastery's
    ~4.5 MB status took 1.3 s, so the 600 ms gate never let it race).
    """
    waited = 0.0
    limit = None
    while True:
        samples = []
        for _ in range(GATE_SAMPLES):
            began = clock()
            response = client.status(challenge_id)
            samples.append((clock() - began) * 1000)
        if limit is None:
            limit = gate_ms + len(json.dumps(response, separators=(",", ":"))) / GATE_BYTES_PER_MS
        median = sorted(samples)[len(samples) // 2]
        if median <= limit:
            print(f"Gate: status answered in {median:.0f} ms (median of {GATE_SAMPLES}, limit {limit:.0f} ms); racing.")
            return True, median
        if waited >= max_wait:
            return False, median
        print(f"Gate: status answered in {median:.0f} ms, over {limit:.0f} ms; waiting {GATE_PAUSE_SECONDS:.0f} s.")
        sleep(GATE_PAUSE_SECONDS)
        waited += GATE_PAUSE_SECONDS


def _workable(state: AttemptState) -> bool:
    return bool(state.answer_ids) and not (
        state.expired or state.pending or state.complete or state.inactive
    )


def _race(
    client: GameMasterClient, challenge_id: str, challenge: dict[str, Any],
    run: Run, artifact_dir: Path, hint: dict[str, Any] | None,
    clock: Callable[[], float], sleep: Callable[[float], None] = time.sleep,
) -> None:
    """The on-clock critical path. No output, no disk, no extra requests.

    The one exception is a web target still `preparing`: status is polled until it is
    ready, which happens before the clock (there is no deadline yet), like the gate.
    """
    retry = run.route == "retry"
    early: Any = None
    run.wall["start sent"] = time.time()
    run.marks["start sent"] = clock()
    if run.pipelined:
        run.attempt, early = client.start_with_artifact(challenge_id, timed=run.run_for_time, retry=retry)
    else:
        run.attempt = (client.retry if retry else client.start)(challenge_id, timed=run.run_for_time)
    run.marks["start received"] = clock()
    run.wall["start received"] = time.time()
    run.started = AttemptState.parse(run.attempt)
    listed = deliveries(run.attempt)
    targets = current_fields(run.attempt).get("targets")
    if isinstance(targets, list) and targets and not listed:
        # Web: there is no file to download. A handler reads the flag from the target.
        run.targets = targets
        if _target_not_ready(run.attempt):
            # The start came back before the target was up; wait for it (read-only).
            _await_target_ready(client, challenge_id, run, sleep)
        _solve_targets(client, challenge_id, challenge, run, clock)
        return
    if not _workable(run.started):
        return
    if len(listed) > 1:
        # Separate deliveries (Warmups Mastery Days 2-6): each question names one.
        run.deliveries = _fetch_deliveries(client, challenge_id, listed, run.helpers)
        run.artifact = run.deliveries[0].data
    elif run.pipelined:
        # Use the early bytes only when they provably belong to this new attempt.
        expected = run.started.artifact_sha256
        if isinstance(early, GameMasterError):
            run.pipeline_failure = f"pipelined artifact failed: {early}"
        elif not isinstance(early, bytes):
            run.pipeline_failure = "pipelined artifact returned no bytes"
        elif expected and hashlib.sha256(early).hexdigest() == expected:
            run.artifact = early
        elif expected:
            run.pipeline_failure = "pipelined artifact did not match the new attempt's SHA-256"
        else:
            # Unverifiable early bytes mean downloading twice on the clock: worse than no pipelining.
            run.pipeline_failure = "the start response has no artifact_sha256 to verify pipelined bytes"
    if run.artifact is None:
        # The start response's own link skips the challenge lookup (~200 ms faster than
        # op=artifact from Sweden); timed runs hedge it on a second warm connection. Not a
        # large file: two copies share the link (day 21 Binary, 33 MB: 8.9 s hedged, 7.2 s not).
        large = len(listed) == 1 and (listed[0]["size"] or 0) > HEDGE_MAX_BYTES
        workers = [client, *run.helpers[:1]] if run.timed and not large else [client]
        capability = listed[0]["capability"] if len(listed) == 1 else None
        run.artifact, run.submitter, run.straggler = _hedged_download(workers, challenge_id, capability)
    run.marks["artifact received"] = clock()
    digest = hashlib.sha256(run.artifact).hexdigest()
    if run.started.artifact_sha256 and run.started.artifact_sha256 != digest:
        raise GameMasterError("Downloaded bytes do not match the assigned artifact SHA-256.")
    answer_ids = run.started.answer_ids
    context, run.unpacked = build_context(
        challenge_id, challenge, run.attempt, run.artifact,
        artifact_path(challenge_id, digest, artifact_dir), answer_ids, hint, run.deliveries,
    )
    run.members = context.members
    needed = set(answer_ids) - run.started.accepted_ids
    proven_names = set((hint or {}).get("solvers") or ())
    racing = SOLVERS if run.solvers is None else run.solvers
    proven = tuple(s for s in racing if getattr(s, "name", None) in proven_names)
    others = tuple(s for s in racing if getattr(s, "name", None) not in proven_names)
    # Every solver runs under the watchdog: a hang is killed, a crash is reported, and on the
    # clock nothing solves past the attempt's deadline minus the submit margin.
    # The server's deadline is in true time; clock_offset (NTP, measured before the clock) is
    # how far this machine's clock runs ahead of it.
    true_now = time.time if run.clock_offset is None else (lambda: time.time() - run.clock_offset)
    deadline = race_deadline(run.started.deadline, now=true_now) if run.timed else None
    try:
        question_items(context)  # Parsed once here; the solver children inherit the cache.
    except Exception:
        pass
    candidates, outcomes = run_solvers(proven, context, deadline=deadline)
    run.selected, run.conflict = select_candidates(candidates, answer_ids, run.notes)
    if proven and not run.conflict and needed <= {c.answer_id for c in run.selected}:
        run.notes.append("The proven solver answered every open question; other solvers were skipped.")
    else:
        found, more = run_solvers(others, context, deadline=deadline)
        candidates += found
        outcomes += more
        run.notes.clear()
        run.selected, run.conflict = select_candidates(candidates, answer_ids, run.notes)
    run.notes.extend(outcome.note() for outcome in outcomes if outcome.status != "ok")
    run.submitted = {
        candidate.answer_id: candidate.answer for candidate in run.selected
        if candidate.answer_id in needed
    }
    run.marks["solved"] = clock()
    if run.submitted:
        run.wall["submit sent"] = time.time()
        run.result = (run.submitter or client).submit_many(challenge_id, run.submitted)
        run.marks["submit received"] = clock()
        run.wall["submit received"] = time.time()


def _solve_targets(
    client: GameMasterClient, challenge_id: str, challenge: dict[str, Any], run: Run,
    clock: Callable[[], float],
) -> None:
    """Web critical path: a handler reads the flag from the assigned target, then submit it.

    No handler, no flag, or disagreeing handlers leave the attempt untouched (UNRESOLVED).
    Network reaches only the hosts the Game Master listed (ScopedHttp).
    """
    from .solvers.web import WEB_SOLVERS, TargetContext, scoped_http

    if run.started is None:
        return
    answer_ids = run.started.answer_ids
    if not answer_ids or not WEB_SOLVERS:
        return
    context = TargetContext(
        challenge_id, challenge, run.attempt, answer_ids, tuple(run.targets), scoped_http(run.targets),
    )
    candidates = [candidate for solver in WEB_SOLVERS for candidate in solver.solve(context)]
    run.selected, run.conflict = select_candidates(candidates, answer_ids, run.notes)
    needed = set(answer_ids) - run.started.accepted_ids
    run.submitted = {c.answer_id: c.answer for c in run.selected if c.answer_id in needed}
    run.marks["solved"] = clock()
    if run.submitted:
        run.wall["submit sent"] = time.time()
        run.result = (run.submitter or client).submit_many(challenge_id, run.submitted)
        run.marks["submit received"] = clock()
        run.wall["submit received"] = time.time()


def _timings(run: Run) -> dict[str, Any]:
    marks = run.marks
    spans = (
        # Pipelined, the start round trip also carries the artifact download.
        ("start_round_trip", "start sent", "start received"),
        ("artifact_download", "start received", "artifact received"),
        ("solve", "artifact received", "solved"),
        ("submit_round_trip", "solved", "submit received"),
        ("start_response_to_submit_response", "start received", "submit received"),
        ("start_sent_to_submit_response", "start sent", "submit received"),
    )
    timings: dict[str, Any] = {
        name: round((marks[end] - marks[begin]) * 1000, 1)
        for name, begin, end in spans if begin in marks and end in marks
    }
    timings["pipelined"] = run.pipelined and run.pipeline_failure is None
    server_clock = _server_clock(run)
    if server_clock:
        timings["server_clock_ms"] = server_clock
    return timings


def _server_clock(run: Run) -> dict[str, float] | None:
    """Time on the server clock, bounded from started_at (set when the material is ready).

    It stops between our submit leaving and its response arriving, so the range is
    [started_at -> submit sent, started_at -> submit response], NTP-corrected. The
    start request's preparation (~2.8 s from Sweden) comes before started_at and is free.
    """
    if run.clock_offset is None or "submit received" not in run.wall or run.attempt is None:
        return None
    try:
        started = current_fields(run.attempt).get("started_at")
        started_at = datetime.fromisoformat(started.replace("Z", "+00:00")).timestamp()
    except (AttributeError, ValueError, GameMasterError):
        return None
    true = lambda name: run.wall[name] - run.clock_offset
    clock = {
        # Most likely the race time: the server almost surely stamps the answer on arrival.
        "from": round((true("submit sent") - started_at) * 1000),
        "to": round((true("submit received") - started_at) * 1000),
    }
    if "start received" in run.wall:
        # started_at -> start response here: how far this machine sits from the server.
        clock["start_tail"] = round((true("start received") - started_at) * 1000)
    return clock


def _without_repeats(value: Any, printed: set[str]) -> Any:
    """`value` with every question list already printed replaced by a short note.

    A Script Analysis Mastery holds up to 6,245 questions; printing them with the
    assignment and again with the status made a 2.2 MB log (20 Oct 2026).
    """
    if isinstance(value, dict):
        return {
            key: f"[{len(item)} questions, as in the assignment]"
            if key == "questions" and isinstance(item, list) and json.dumps(item, sort_keys=True) in printed
            else _without_repeats(item, printed)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_without_repeats(item, printed) for item in value]
    return value


def _question_lists(value: Any) -> set[str]:
    if isinstance(value, dict):
        found = {json.dumps(value["questions"], sort_keys=True)} if isinstance(value.get("questions"), list) else set()
        return found.union(*(_question_lists(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_question_lists(item) for item in value))
    return set()


def _report(
    client: GameMasterClient, challenge_id: str, challenge: dict[str, Any],
    before: Any, run: Run, hint: dict[str, Any] | None, artifact_dir: Path,
    work_dir: Path, responses: dict[str, Any], secrets: tuple[str, ...], corpus_root: Path | None = None,
) -> None:
    print("Challenge:")
    print_result(challenge, secrets)
    printed = _question_lists(run.attempt)
    if before is not None:
        print("Status before start:")
        print_result(_without_repeats(before, printed), secrets)
    if not run.timed:
        print("Route: start (untimed request; reconnects to the current attempt)")
    else:
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
    if run.targets:
        print("Live targets (no artifact to download):")
        print_result(run.targets, secrets)
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
        if run.deliveries:
            print(f"Downloaded {len(run.deliveries)} separate deliveries.")
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
    if run.artifact is not None and run.submitted and str(outcome).casefold() in ("correct", "accepted"):
        # The replay corpus (corpus.py, scripts/replay.py): what the service accepted, kept for
        # re-solving with later solver versions. Never allowed to fail the run.
        try:
            accepted_ids = set(AttemptState.parse(run.result).accepted_ids)
            accepted = {key: value for key, value in run.submitted.items()
                        if str(outcome).casefold() == "correct" or key in accepted_ids}
            saved = corpus.record(challenge_id, challenge, run.attempt, run.artifact, run.deliveries,
                                  accepted, secrets, root=corpus_root)
            if saved:
                print(f"Replay corpus: {json.dumps(str(saved))} ({len(accepted)} accepted answers)")
        except (OSError, ValueError, TypeError, GameMasterError) as exc:
            print(f"Replay corpus not written: {exc}")
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
            print_result(_without_repeats(current, printed), secrets)
        except GameMasterError as exc:
            print(f"Status after the run is unavailable: {exc}")
    print_result({"timings_ms": _timings(run)})


def _outcome(run: Run, challenge_id: str, hints_path: Path | None) -> int:
    started = run.started
    if started is None:
        raise GameMasterError("The start did not complete.")
    terminal = terminal_result(started)
    if terminal is not None:
        return terminal
    if run.targets and run.result is None:
        if run.conflict:
            print("Web handlers disagreed on the flag; nothing was submitted.")
            return CONFLICT
        print("Web route: no handler produced a flag for this target. Nothing was submitted.")
        return UNRESOLVED
    answer_ids = started.answer_ids
    if not answer_ids:
        print("No answer_ids were issued by start. This route needs additional instructions or a CourseStack submission.")
        return UNRESOLVED
    if run.result is None:
        print(
            "No unambiguous supported solution. The current attempt is preserved"
            + ("; its clock keeps running." if started.deadline else ".")
        )
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


def run_fast(
    client: GameMasterClient, challenge_id: str, *, timed: bool = False,
    challenge: dict[str, Any] | None = None,
    artifact_dir: Path = Path("artifacts"), work_dir: Path = Path("work"),
    hints_path: Path | None = None, capture_dir: Path | None = None,
    clock: Callable[[], float] = time.perf_counter, pipeline: bool = True,
    ntp: Callable[[], float | None] = network.clock_offset,
    gate_ms: float | None = None, gate_wait: float = 600.0,
    sleep: Callable[[float], None] = time.sleep, report: dict[str, Any] | None = None,
    reserve: int = 0,
) -> int:
    """Solve one challenge. `challenge` is its record from a list the caller already has.

    Untimed: an ordinary start (which only reconnects; never an automatic retry).
    Timed: status first, then start or retry with run_for_time, as `plan_route` decides.
    `pipeline=False` keeps one request at a time even where the probe passed.
    `gate_ms` (timed) waits up to `gate_wait` s for the server to answer status that fast
    before spending a variant. `report`, when given, receives the run's timings.
    `reserve` (timed) never spends the last that many fresh timed variants.
    """
    secrets = (client.token,) if client.token else ()
    responses: dict[str, Any] = {}
    if challenge is None:
        challenge, responses["list"] = lookup_challenge(client, challenge_id)
    network_path = network.default_path(hints_path)
    base_url = getattr(client, "base_url", None)
    run = Run(
        timed=timed, run_for_time=timed and challenge.get("run_for_time_supported") is True,
        # A Web start has no artifact to pair with, and its failed GET would turn pipelining off.
        pipelined=pipeline and lane_of(challenge, challenge_id) not in TARGET_LANES
        and network.pipelining_ok(base_url, network_path),
    )
    before = None
    if timed:
        # Before the clock. This request also leaves the connection warm for start.
        try:
            responses["before"] = before = client.status(challenge_id)
        except GameMasterError as exc:
            before = {"unavailable": str(exc)}
        run.route, reason = plan_route(before, challenge, reserve)
        if run.route in ("pending", "stop"):
            print("Challenge:")
            print_result(challenge, secrets)
            print("Status before start:")
            print_result(before, secrets)
            print(f"No timed run was started: {reason}")
            return PENDING if run.route == "pending" else UNRESOLVED
        if gate_ms is not None:
            ready, latency = _gate(client, challenge_id, gate_ms, gate_wait, clock, sleep)
            if not ready:
                print(
                    f"No timed run was started: the server answered status in {latency:.0f} ms, "
                    f"over the {gate_ms:.0f} ms gate, for {gate_wait:.0f} s. No variant was spent."
                )
                return UNRESOLVED
        # Extra warm connections: one hedges the download; more fetch separate deliveries
        # (the previous attempt shows how many).
        for helper in _helpers(client, max(len(deliveries(before)), 2)):
            try:
                helper.warm()
                run.helpers.append(helper)
            except GameMasterError:
                helper.close()
        run.clock_offset = ntp()
    hint = get_hint(challenge_id, hints_path)
    run.solvers = warm_up(SOLVERS)
    # No collector pauses on the clock; the race allocates little. Untimed runs leave the
    # collector alone: `daily` runs them in parallel threads, and gc is process-wide.
    collecting = timed and gc.isenabled()
    if collecting:
        gc.disable()
    try:
        _race(client, challenge_id, challenge, run, artifact_dir, hint, clock, sleep)
    finally:
        if collecting:
            gc.enable()
        if run.straggler is not None:
            # The losing GET may still hold a connection the report needs; let it finish.
            try:
                run.straggler.result(timeout=getattr(client, "timeout", 30))
            except Exception:
                pass
        for helper in run.helpers:
            helper.close()
        if run.unpacked is not None:
            run.unpack_notes = run.unpacked.notes  # Unpacks now, off the clock, if no solver did.
        responses["attempt"], responses["result"] = run.attempt, run.result
        _report(client, challenge_id, challenge, before, run, hint, artifact_dir, work_dir, responses, secrets,
                corpus_root=(hints_path.parent / "corpus") if hints_path else None)
        if report is not None:
            report.update(_timings(run))
        if run.pipeline_failure and base_url:
            # The probe passed but a real run did not: stop pipelining on this route.
            print(f"Pipelining turned off for {base_url}: {run.pipeline_failure}. Re-run `bench --pipeline` to re-check.")
            note = network.record(base_url, network_path, pipelining=False, reason=run.pipeline_failure)
            if note:
                print(note)
        if capture_dir is not None:
            responses = {key: value for key, value in responses.items() if value is not None}
            label = "timed" if timed else "solve"
            print(f"Capture: {json.dumps(str(save_capture(capture_dir, label, responses, secrets)))}")
    return _outcome(run, challenge_id, hints_path)
