"""Run every available challenge in one go: untimed solves, or races for proven solvers.

Untimed, each challenge family (a Single Solve and its Time Trial and Mastery, in that
order, since the timed routes stay locked until the Single Solve scores) runs in its own
thread on its own connection; the families' output is kept together. Races run one at a
time, so they never share bandwidth, and each route races once unless `rerace` is set.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from io import StringIO
from pathlib import Path
import sys
import threading
import time
import traceback
from typing import Any, Callable

from .autopilot import COMPLETE, CONFLICT, EXPIRED, INCORRECT, PENDING, UNRESOLVED
from .client import GameMasterClient, GameMasterError
from .display import print_result
from .fastpath import TARGET_LANES, lane_of, run_fast
from .hints import TURNED_DOWN_KEYS, load_hints, record_outcome, record_race
from .learn import run_learn
from .state import AttemptState, mode_name

# Lanes whose solver answers every variant of a day once its Single Solve scored
# (warmups learns the day's line chain from that hint; metadata parses any variant;
# mobile-android decodes each app's puzzle asset).
COURSE_LANES = {"warmups", "metadata-forensics", "mobile-android"}
WORKERS = 6
# One lane is enough to see a release: ~1 s per list instead of ~4 s for a whole day.
RELEASE_PROBE_LANE = "warmups"
RELEASE_POLL_SECONDS = 0.25  # Plus ~0.6 s per list: a release is seen within ~1 s.

OUTCOMES = {
    COMPLETE: "complete", UNRESOLVED: "unresolved", INCORRECT: "incorrect",
    EXPIRED: "expired", CONFLICT: "conflict", PENDING: "pending",
}
_MODE_ORDER = {"time_trial": 1, "mastery": 2}

# A skip that means "this route is blocked", not "there is nothing to do here": the
# later modes of the family ask the same question kinds it was turned down for.
TURNED_DOWN_REASON = "turned down as "


def _records(response: Any) -> list[dict[str, Any]]:
    records = response.get("challenges", response.get("items")) if isinstance(response, dict) else response
    if not isinstance(records, list):
        raise GameMasterError("The challenge list has an unsupported structure.")
    return [record for record in records if isinstance(record, dict)]


def _lane_records(client: GameMasterClient, day: int | None, lane: str | None) -> list[dict[str, Any]]:
    """One day's records of one lane (~1 s instead of ~4 s for the whole day)."""
    try:
        return _records(client.list_challenges(day, lane))
    except GameMasterError:
        if lane is None:
            raise
        # "binary-reverse-engineering" is not a lane filter (HTTP 400 invalid_lane, and
        # "binary" lists nothing): keep that lane's records of the whole day.
        whole = _records(client.list_challenges(day, None))
        return [record for record in whole if lane_of(record, str(_id(record))) == lane]


def _id(record: dict[str, Any]) -> Any:
    return record.get("id", record.get("challenge_id"))


def eligibility(
    record: dict[str, Any], timed: bool, hints: dict[str, Any], *,
    lane: str | None = None, requested_lanes: tuple[str, ...] = (), rerace: bool = False,
) -> str | None:
    """None when the challenge may run; otherwise the reason it is skipped.

    Only an explicit request starts a Web route (it reaches the network): the lane named by
    `--lane`, or present in the `--lanes` set (`requested_lanes`). A bare sweep skips it.
    """
    challenge_id = _id(record)
    if not isinstance(challenge_id, str) or not challenge_id.strip():
        return "no usable challenge ID"
    record_lane = lane_of(record, challenge_id)
    web_requested = lane in TARGET_LANES or record_lane in requested_lanes
    if record_lane in TARGET_LANES and not web_requested:
        return "live targets[]; `daily --lane web-exploitation` (or `--lanes ...,web-exploitation`) starts them"
    supports_timed = record.get("run_for_time_supported") is True
    mode = mode_name(record, AttemptState())
    if timed:
        # Older Time Trial and Mastery routes are timed by default: a plain retry races.
        if not supports_timed and mode not in ("Time Trial", "Mastery Mode"):
            return "this route has no timed mode"
        raced = hints.get(challenge_id) or {}
        if raced.get("raced_at") and not rerace:
            best = raced.get("best_on_clock_ms")
            return f"already raced (best {best} ms on the clock); --rerace spends another variant"
        rejected = raced.get("turned_down")
        # A solver that scored on the route after the mark (record_hint's `recorded_at`)
        # clears it by itself; ISO timestamps compare in order.
        if str(raced.get("recorded_at") or "") > str(raced.get("turned_down_at") or ""):
            rejected = None
        if rejected and not rerace:
            # One submission per race: a route the service has already turned down would
            # spend a ranked variant on the same answer (day 23 Metadata did it three times).
            return (f"{TURNED_DOWN_REASON}{rejected} ({raced.get('turned_down_at')}); a race"
                    " would spend a ranked variant on it again. --rerace races anyway")
        # An entry that holds only that mark is no proof that a solver ever scored.
        marks_only = bool(raced.keys()) and raced.keys() <= set(TURNED_DOWN_KEYS)
        if challenge_id in hints and not marks_only:
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


def families(records: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Records grouped by their Single Solve ID, each group Single, Time Trial, Mastery."""
    groups: dict[Any, list[dict[str, Any]]] = {}
    for record in records:
        challenge_id = _id(record)
        key = challenge_id.split("/", 1)[0] if isinstance(challenge_id, str) else id(record)
        groups.setdefault(key, []).append(record)
    order = lambda record: _MODE_ORDER.get(str(_id(record)).partition("/")[2], 0)
    return [sorted(group, key=order) for group in groups.values()]


class _FamilyOutput:
    """sys.stdout while families run in parallel: each thread's output stays together."""

    def __init__(self, real: Any) -> None:
        self.real = real
        self.buffers: dict[int, StringIO] = {}
        self.lock = threading.Lock()

    def write(self, text: str) -> int:
        buffer = self.buffers.get(threading.get_ident())
        if buffer is not None:
            return buffer.write(text)
        with self.lock:
            return self.real.write(text)

    def flush(self) -> None:
        with self.lock:
            self.real.flush()

    def begin(self) -> None:
        self.buffers[threading.get_ident()] = StringIO()

    def end(self) -> None:
        text = self.buffers.pop(threading.get_ident()).getvalue()
        with self.lock:
            self.real.write(text)
            self.real.flush()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.real, name)


def wait_for_release(
    client: GameMasterClient, day: int, lane: str | tuple[str, ...] | None, wait: float, *,
    clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
) -> Any:
    """Poll `day` until its challenges are listed; returns that list.

    Started just before 15:00 Swedish time (09:00 New York), this begins the day at the
    release instead of minutes later. Several lanes are probed in turn, so a day without
    one of them is still seen. Errors count as "not yet" until the deadline.
    """
    tag = f"-day-{day:02d}"
    probes = (lane,) if isinstance(lane, str) else tuple(lane or ()) or (RELEASE_PROBE_LANE,)
    began = clock()
    errors = 0
    polls = 0
    while True:
        probe = probes[polls % len(probes)]
        polls += 1
        try:
            response = client.list_challenges(day, probe)
            if any(tag in str(_id(record)) for record in _records(response)):
                print(f"Day {day} is released: listed after {clock() - began:.1f} s of waiting.", flush=True)
                return response
        except GameMasterError as exc:
            errors += 1
            if errors in (1, 10, 100):
                print(f"Waiting for day {day}: the list failed ({exc}); trying again.", flush=True)
            if len(probes) > 1:
                # Every lane is released at once, and one the server cannot filter
                # (binary-reverse-engineering: HTTP 400) would cost each round a probe.
                probes = tuple(name for name in probes if name != probe)
        if clock() - began >= wait:
            raise GameMasterError(f"Day {day} was not released within {wait:.0f} s.")
        sleep(RELEASE_POLL_SECONDS)


def run_daily(
    client: GameMasterClient, *, day: int | None = None, lane: str | None = None,
    timed: bool = False, artifact_dir: Path = Path("artifacts"), work_dir: Path = Path("work"),
    hints_path: Path | None = None, capture_dir: Path | None = None,
    clock: Callable[[], float] = time.perf_counter, pipeline: bool = True,
    repeat: int = 1, gate_ms: float | None = None, gate_wait: float = 600.0,
    rerace: bool = False, wait_release: float = 0.0, workers: int = WORKERS,
    sleep: Callable[[float], None] = time.sleep, days: list[int] | None = None,
    reserve: int = 0, lanes: tuple[str, ...] = (),
) -> int:
    """`repeat` (timed) races each challenge that many times: Hall of Fame keeps the best.

    The summary's `on_clock_ms` is the server-clock estimate per race (started_at ->
    submit sent); `wall_seconds` is the whole command, which also covers free parts.
    `wait_release` (needs `day`) polls for the day's release for up to that many seconds.
    `days` runs several days in one go (one list per day: ~1 s with a lane, ~4 s without);
    `reserve` (timed) keeps that many fresh variants per route unspent.
    `lanes` keeps the run to those lanes: teammates share attempts, and an untimed start
    of their Time Trial would block their timed race until it ends.
    """
    began_all = clock()
    if days:
        listing = {"challenges": [record for number in days for record in _lane_records(client, number, lane)]}
    elif lanes and day is not None:
        # One list per lane (~1 s each) instead of the whole day (~4 s); the release probe's
        # list is the first lane's.
        found: list[dict[str, Any]] = []
        if wait_release:
            found = _records(wait_for_release(client, day, lanes, wait_release, sleep=sleep))
        listed = {lane_of(record, str(_id(record))) for record in found}
        for name in lanes:
            if name not in listed:
                found += _lane_records(client, day, name)
        listing = {"challenges": found}
    elif wait_release and day is not None:
        released = wait_for_release(client, day, lane, wait_release, sleep=sleep)
        listing = released if lane else client.list_challenges(day, lane)
    else:
        listing = client.list_challenges(day, lane)
    records = _records(listing)
    if lanes:
        records = [record for record in records if lane_of(record, str(_id(record))) in lanes]
    hints = load_hints(hints_path)

    def run_one(target: GameMasterClient, record: dict[str, Any]) -> dict[str, Any]:
        challenge_id = _id(record)
        reason = eligibility(record, timed, hints, lane=lane, requested_lanes=lanes, rerace=rerace)
        if reason is not None:
            entry = {"challenge": challenge_id, "outcome": "skipped", "reason": reason}
            if reason.startswith(TURNED_DOWN_REASON):
                entry["blocks_family"] = True
            return entry
        began = clock()
        on_clock: list[float] = []
        try:
            for number in range(1, (max(repeat, 1) if timed else 1) + 1):
                print(f"\n===== {challenge_id} ({'timed race ' + str(number) if timed else 'untimed'}) =====")
                report: dict[str, Any] = {}
                # The record from this list is passed on, so no run fetches the list again.
                code = run_fast(
                    target, challenge_id, timed=timed, challenge=record,
                    artifact_dir=artifact_dir, work_dir=work_dir, hints_path=hints_path,
                    capture_dir=capture_dir, clock=clock, pipeline=pipeline,
                    gate_ms=gate_ms, gate_wait=gate_wait, report=report, reserve=reserve,
                )
                measured = (report.get("server_clock_ms") or {}).get("from")
                if measured is not None:
                    on_clock.append(measured)
                if timed and code == COMPLETE:
                    note = record_race(challenge_id, measured, hints_path)
                    if note:
                        print(note)
                if code != COMPLETE:
                    break
            if code == INCORRECT and not timed:
                # One wrong answer of a new type rejects every right one: send them again kind
                # by kind on the same open attempt, so the right kinds are accepted and the
                # report names the new one (day 22 Binary: found in under a minute).
                print(f"\n===== {challenge_id} (incorrect: resending kind by kind) =====")
                code = run_learn(target, challenge_id, hints_path=hints_path, challenge=record, open_only=True)
            entry = {"challenge": challenge_id, "outcome": OUTCOMES.get(code, str(code))}
            # So tonight's and tomorrow's races skip what the service turned down.
            note = record_outcome(challenge_id, entry["outcome"], timed, hints_path)
            if note:
                print(note)
        except GameMasterError as exc:
            entry = {"challenge": challenge_id, "outcome": "error", "reason": str(exc)}
        if on_clock:
            entry["on_clock_ms"] = on_clock
            entry["best_on_clock_ms"] = min(on_clock)
        entry["wall_seconds"] = round(clock() - began, 3)
        return entry

    if timed or workers <= 1 or not hasattr(client, "clone"):
        entries: dict[int, dict[str, Any]] = {}
        for group in families(records):
            _run_group(client, group, run_one, entries)
        summary = [entries[id(record)] for record in records]
    else:
        summary = _run_families(client, records, run_one, workers)
    print("\n===== Summary =====")
    print_result({
        "mode": "timed" if timed else "untimed", "challenges": summary,
        "wall_seconds": round(clock() - began_all, 3),
    })
    ran = [entry for entry in summary if entry["outcome"] != "skipped"]
    return COMPLETE if all(entry["outcome"] == "complete" for entry in ran) else UNRESOLVED


def _run_group(
    target: GameMasterClient, group: list[dict[str, Any]],
    run_one: Callable[[GameMasterClient, dict[str, Any]], dict[str, Any]],
    entries: dict[int, dict[str, Any]],
) -> None:
    """One family in mode order; a route that does not score blocks the modes after it.

    The service answers a later mode HTTP 409 until the one before it scores (day 23: an
    unresolved Time Trial locked three Masteries), so asking anyway reports an "error"
    that is really a lock, and `day.sh` spends a retry on it.
    """
    blocked = None
    for record in group:
        if blocked:
            entries[id(record)] = {"challenge": _id(record), "outcome": "skipped", "reason": blocked}
            continue
        try:
            entry = run_one(target, record)
        except Exception as exc:  # One family's crash must not stop the others.
            traceback.print_exc(file=sys.stdout)
            entry = {"challenge": _id(record), "outcome": "error", "reason": repr(exc)}
        entries[id(record)] = entry
        if entry["outcome"] not in ("complete", "skipped") or entry.get("blocks_family"):
            blocked = f"{_id(record)} is not solved yet"


def _run_families(
    client: GameMasterClient, records: list[dict[str, Any]],
    run_one: Callable[[GameMasterClient, dict[str, Any]], dict[str, Any]], workers: int,
) -> list[dict[str, Any]]:
    """Untimed: one thread and connection per family; the summary keeps the list order."""
    output = _FamilyOutput(sys.stdout)
    entries: dict[int, dict[str, Any]] = {}

    def run_family(group: list[dict[str, Any]]) -> None:
        output.begin()
        target = client.clone()
        try:
            _run_group(target, group, run_one, entries)
        finally:
            target.close()
            output.end()

    sys.stdout = output
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(run_family, families(records)))
    finally:
        sys.stdout = output.real
    return [entries[id(record)] for record in records]
