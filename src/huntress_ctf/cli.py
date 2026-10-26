"""Command-line interface for the Huntress Game Master client."""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import getpass
import json
import math
from pathlib import Path
import sys
import warnings

from .artifacts import save_artifact
from .autopilot import COMPLETE, EXPIRED, INCORRECT, PENDING, UNRESOLVED
from .client import DEFAULT_BASE_URL, PROXY_BASE_URL, GameMasterClient, GameMasterError
from .config import load_env
from .containers import DEFAULT_PASSWORDS, Member, unwrap
from .daily import run_daily
from .display import print_result, safe_value
from .diagnostics import compare_routes, probe_pipelining, run_bench, run_diagnostics
from .fastpath import run_fast, solver_timings
from .learn import run_learn
from .lock import robot_lock
from .state import AttemptState
from .suggest import suggest
from .workspace import render_triage

CAPTURE_DIR = Path("integration-data")
# Commands that can start, retry or submit: one robot per machine (lock.py).
LOCKED_COMMANDS = {"start", "retry", "solve", "learn", "daily", "submit"}


def _prepare(client: GameMasterClient, challenge_id: str, work_dir: Path, secrets: tuple[str, ...]) -> int:
    """status + every delivery -> work/<id>/ as the robot leaves it for an unresolved route.

    Read-only (status and artifact), so it never starts, retries or submits; a route nobody
    started yet has no assignment to prepare.
    """
    from .containers import Member, passwords_from, unwrap
    from .state import deliveries
    from .solvers.base import instruction_text, SolveContext
    from .workspace import write_workspace

    attempt = client.status(challenge_id)
    if not isinstance(attempt, dict) or attempt.get("error") or not attempt.get("questions"):
        print(f"No assignment to prepare: {safe_value(json.dumps(attempt)[:300], secrets)}", file=sys.stderr)
        return 1
    listed = deliveries(attempt)
    blobs = [client.artifact(challenge_id, delivery=index) for index in range(max(len(listed), 1))]
    names = [item.get("filename") or f"delivery-{index + 1}" for index, item in enumerate(listed)] or ["artifact.bin"]
    lane = challenge_id.split("-day-", 1)[0]
    challenge = {"id": challenge_id, "lane": lane}
    context = SolveContext(challenge_id, challenge, attempt, blobs[0], Path("unused"), ())
    unpacked = unwrap(blobs[0], passwords_from(instruction_text(context)))
    extra = tuple(Member(f"delivery {index}: {name}", blob) for index, (name, blob) in enumerate(zip(names, blobs), 1)) \
        if len(blobs) > 1 else ()
    directory = write_workspace(work_dir, challenge_id, challenge=challenge, attempt=attempt, artifact=blobs[0],
                                members=unpacked.members + extra, notes=unpacked.notes, secrets=secrets)
    for index, (name, blob) in enumerate(zip(names, blobs), 1):
        (directory / f"delivery-{index}-{name.replace('/', '_')}").write_bytes(blob)
    print(f"Prepared {directory} ({len(blobs)} deliveries, {len(attempt.get('questions') or [])} questions).")
    return 0


def _seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("seconds must be a number of 0 or more") from None
    if not math.isfinite(seconds) or seconds < 0:
        raise argparse.ArgumentTypeError("seconds must be a finite number of 0 or more")
    return seconds


def _positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("timeout must be a positive number") from None
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be a finite positive number")
    return timeout


def _count(value: str) -> int:
    try:
        count = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("count must be an integer from 1 to 100") from None
    if not 1 <= count <= 100:
        raise argparse.ArgumentTypeError("count must be from 1 to 100")
    return count


def _day(value: str) -> int:
    try:
        day = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("day must be an integer from 1 to 31") from None
    if not 1 <= day <= 31:
        raise argparse.ArgumentTypeError("day must be from 1 to 31")
    return day


def _days(value: str) -> list[int]:
    """Days such as "1-20", "3" or "1,5,7-9", each from 1 to 31."""
    days: list[int] = []
    try:
        for part in value.split(","):
            first, _, last = part.strip().partition("-")
            days.extend(range(int(first), int(last or first) + 1))
    except ValueError:
        raise argparse.ArgumentTypeError("days look like 1-20, 3 or 1,5,7-9") from None
    if not days or not all(1 <= day <= 31 for day in days):
        raise argparse.ArgumentTypeError("days must be from 1 to 31")
    return sorted(set(days))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="huntress-ctf", description="Interact with the Huntress CTF 2026 Game Master.",
    )
    parser.add_argument(
        "--base-url", help=f"Base URL (HUNTRESS_GM_URL or {DEFAULT_BASE_URL})",
    )
    parser.add_argument("--timeout", type=_positive_timeout, default=30, help="HTTP timeout in seconds")
    parser.add_argument("--prompt-token", action="store_true", help="Read a bearer token with hidden terminal input")
    parser.add_argument(
        "--lock-wait", type=_seconds, default=0,
        help="Seconds to wait when another robot on this machine holds the lock (default: stop at once)",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="List current challenges")
    listing.add_argument("--day", type=_day)
    listing.add_argument("--lane")
    for name, help_text, timed_help in (
        ("start", "Start or reconnect; print the assignment", "Request a timed attempt"),
        ("retry", "Explicitly request a variant after completion or expiry", "Request a timed attempt"),
        ("solve", "Analyze and automatically submit supported solutions",
         "Request a timed attempt; only start, download, solve, and one submit run on the clock"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("challenge_id")
        command.add_argument("--timed", action="store_true", help=timed_help)
        if name == "solve":
            command.add_argument("--capture", action="store_true", help=f"Save redacted responses under {CAPTURE_DIR} after the run")
            command.add_argument("--no-pipeline", action="store_true", help=NO_PIPELINE_HELP)
            _race_options(command)
    learn = commands.add_parser("learn", help="Spend one variant: submit the robot's answers per question kind and show which kinds are accepted")
    learn.add_argument("challenge_id")
    daily = commands.add_parser("daily", help="Solve every available challenge untimed, or race the proven ones")
    daily_days = daily.add_mutually_exclusive_group()
    daily_days.add_argument("--day", type=_day)
    daily_days.add_argument("--days", type=_days, help="Several days, e.g. 1-20 (Hall of Fame re-races)")
    daily.add_argument("--lane")
    daily.add_argument("--lanes", type=lambda value: tuple(part.strip() for part in value.split(",") if part.strip()),
                       default=(), help="Only these lanes, comma-separated (leave teammates' lanes alone)")
    daily.add_argument("--timed", action="store_true", help="Race only challenges whose solver already scored CORRECT")
    daily.add_argument("--rerace", action="store_true", help="With --timed: also race routes that were raced before (spends variants)")
    daily.add_argument("--prove", action="store_true",
                       help="Untimed: one untimed retry of each solved Time Trial/Mastery no solver scored (a regular variant), so --timed races it")
    daily.add_argument("--wait-release", type=_seconds, default=0, metavar="SECONDS",
                       help="With --day: poll for that day's release for up to this long, then start at once")
    daily.add_argument("--workers", type=_count, default=6, help="Untimed: challenge families solved in parallel (1-100)")
    daily.add_argument("--capture", action="store_true", help=f"Save redacted responses under {CAPTURE_DIR}")
    daily.add_argument("--no-pipeline", action="store_true", help=NO_PIPELINE_HELP)
    _race_options(daily)
    triage = commands.add_parser("triage", help="Print a one-page triage report for a local file (offline)")
    triage.add_argument("path", type=Path)
    triage.add_argument("--password", action="append", default=[], help="Archive password to try (repeatable)")
    triage.add_argument("--time", action="store_true", help="Instead, time unpacking and every solver on the file (median ms, cold caches)")
    triage.add_argument("--question", default="", help="With --time: the question text the solvers see")
    hint = commands.add_parser("suggest", help="Offline: candidate fields and answers for a property without a parser")
    hint.add_argument("property", help='e.g. macho.uuid (from "Determine macho.uuid for x.bin")')
    hint.add_argument("path", type=Path, help="The file, or an archive whose members are checked")
    status = commands.add_parser("status", help="Read current attempt status")
    status.add_argument("challenge_id")
    prepare = commands.add_parser(
        "prepare", help="Read-only: write work/<id>/ (assignment, deliveries, triage.md) for a started route")
    prepare.add_argument("challenge_id")
    prepare.add_argument("--work-dir", type=Path, default=Path("work"))
    artifact = commands.add_parser("artifact", help="Save the current assigned artifact with SHA-256")
    artifact.add_argument("challenge_id")
    artifact.add_argument("--output", type=Path, help="Explicit destination; otherwise use a hash-named file")
    artifact.add_argument("--force", action="store_true", help="Allow overwriting an explicit --output file")
    submit = commands.add_parser("submit", help="Submit one answer under its issued ID")
    submit.add_argument("challenge_id")
    submit.add_argument("answer_id")
    submit.add_argument("answer")
    commands.add_parser("api-schema", help="Fetch the Game Master OpenAPI description")
    doctor = commands.add_parser("doctor", help="Check API access and capture responses without starting attempts")
    doctor.add_argument("--challenge", action="append", default=[], metavar="ID", help="Also check this existing challenge's status; repeat for more IDs")
    doctor.add_argument("--output", type=Path, help="Save redacted responses in a new capture directory under this path")
    bench = commands.add_parser("bench", help="Measure request latency with new vs kept-alive connections (read-only)")
    bench.add_argument("--count", type=_count, default=10, help="Requests per connection mode (1-100)")
    # Required: the list is no benchmark, the server takes ~80 s to list every day.
    bench.add_argument("--challenge", metavar="ID", required=True, help="Time this challenge's status and artifact download (e.g. warmups-day-01)")
    bench.add_argument("--compare", action="store_true", help="Also bench the other route (direct HTTPS or Homebase proxy) and recommend the faster")
    bench.add_argument("--pipeline", action="store_true", help="Probe pipelining with two read-only GETs; timed runs use it only where this passed")
    return parser


NO_PIPELINE_HELP = "Send start and artifact one at a time even where `bench --pipeline` passed"


def _race_options(command: argparse.ArgumentParser) -> None:
    command.add_argument("--repeat", type=_count, default=1, help="With --timed: race this many fresh variants; Hall of Fame keeps the best (1-100)")
    command.add_argument("--gate-ms", type=_positive_timeout, help="With --timed: start only once status answers within this many ms (median of 3)")
    command.add_argument("--gate-wait", type=_positive_timeout, default=600, help="Seconds to wait for the gate before skipping without spending a variant")
    command.add_argument("--reserve", type=int, default=0, metavar="N", help="With --timed: never spend a route's last N fresh timed variants")
ROUTE_NAMES = {DEFAULT_BASE_URL: "direct", PROXY_BASE_URL: "homebase-proxy"}


def _bench(client: GameMasterClient, args: argparse.Namespace, token: str | None) -> dict:
    """Read-only: the configured route, and with --compare the other documented one."""
    def measure(target: GameMasterClient):
        def bench() -> dict:
            report = run_bench(target, count=args.count, challenge_id=args.challenge)
            if args.pipeline:
                report["pipeline_probe"] = probe_pipelining(target, challenge_id=args.challenge)
            return report
        return bench

    if not args.compare:
        return measure(client)()
    others = [
        # The bearer goes only to HTTPS; the proxy supplies identity itself.
        GameMasterClient(
            base_url=url, timeout=min(args.timeout, 3),
            token=token if url.startswith("https://") else None,
        )
        for url in (DEFAULT_BASE_URL, PROXY_BASE_URL) if url != client.base_url
    ]
    try:
        return compare_routes([
            (ROUTE_NAMES.get(target.base_url, "configured"), measure(target))
            for target in (client, *others)
        ])
    finally:
        for target in others:
            target.close()


def _prompt_token() -> str:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            token = getpass.getpass("Game Master token (hidden): ")
    except (getpass.GetPassWarning, EOFError):
        raise GameMasterError("Hidden token input needs an interactive terminal; use HUNTRESS_GM_TOKEN otherwise.") from None
    if not token:
        raise GameMasterError("No Game Master token was entered.")
    return token


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    secrets: tuple[str, ...] = ()
    client = None
    if args.command == "triage":
        # Offline: no client, no credentials, nothing executed.
        try:
            data = args.path.read_bytes()
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if args.time:
            print_result(solver_timings(data, args.question, tuple(args.password)))
            return COMPLETE
        unwrapped = unwrap(data, tuple(dict.fromkeys([*args.password, *DEFAULT_PASSWORDS])))
        print(render_triage(data, unwrapped.members, unwrapped.notes, title=args.path.name), end="")
        return COMPLETE
    if args.command == "suggest":
        # Offline, like triage: the AI's first look at a new Metadata property.
        try:
            data = args.path.read_bytes()
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        found = False
        for member in (*unwrap(data).members, Member(args.path.name, data)):
            for line in suggest(args.property, member.data):
                print(f"{member.name}: {line}")
                found = True
        if not found:
            print("No field of a known format matches; run `triage` for every field.")
        return COMPLETE
    token = None
    held = ExitStack()
    try:
        load_env()
        if args.prompt_token:
            token = _prompt_token()
            secrets = (token,)
            client = GameMasterClient(base_url=args.base_url, timeout=args.timeout, token=token)
        else:
            client = GameMasterClient(base_url=args.base_url, timeout=args.timeout)
        secrets = (client.token,) if client.token else ()
        if args.command in LOCKED_COMMANDS:
            command = " ".join(sys.argv[1:] if argv is None else argv)
            held.enter_context(robot_lock(command, wait=args.lock_wait))
        if args.command == "list":
            result = client.list_challenges(args.day, args.lane)
        elif args.command == "start":
            result = client.start(args.challenge_id, timed=args.timed)
        elif args.command == "retry":
            result = client.retry(args.challenge_id, timed=args.timed)
        elif args.command == "prepare":
            return _prepare(client, args.challenge_id, args.work_dir, secrets)
        elif args.command == "status":
            result = client.status(args.challenge_id)
        elif args.command == "solve":
            capture = CAPTURE_DIR if args.capture else None
            on_clock = []
            for _ in range(args.repeat if args.timed else 1):
                report: dict = {}
                code = run_fast(
                    client, args.challenge_id, timed=args.timed, capture_dir=capture,
                    pipeline=not args.no_pipeline, gate_ms=args.gate_ms, gate_wait=args.gate_wait,
                    report=report, reserve=args.reserve,
                )
                on_clock.append((report.get("server_clock_ms") or {}).get("from"))
                if code != COMPLETE:
                    break
            if args.timed and args.repeat > 1:
                measured = [ms for ms in on_clock if ms is not None]
                print_result({"on_clock_ms": on_clock, "best_on_clock_ms": min(measured) if measured else None})
            return code
        elif args.command == "learn":
            return run_learn(client, args.challenge_id)
        elif args.command == "daily":
            if args.wait_release and args.day is None:
                parser.error("--wait-release requires --day")
            return run_daily(
                client, day=args.day, lane=args.lane, timed=args.timed,
                capture_dir=CAPTURE_DIR if args.capture else None, pipeline=not args.no_pipeline,
                repeat=args.repeat, gate_ms=args.gate_ms, gate_wait=args.gate_wait,
                rerace=args.rerace, wait_release=args.wait_release, workers=args.workers,
                days=args.days, reserve=args.reserve, lanes=args.lanes, prove=args.prove,
            )
        elif args.command == "bench":
            print_result(_bench(client, args, token), secrets)
            return COMPLETE
        elif args.command == "doctor":
            report, code = run_diagnostics(
                client, challenge_ids=tuple(args.challenge), output_root=args.output,
            )
            print_result(report, secrets)
            return code
        elif args.command == "artifact":
            if args.force and args.output is None:
                parser.error("--force requires --output")
            content = client.artifact(args.challenge_id)
            path, digest = save_artifact(
                content, args.challenge_id, output=args.output, overwrite=args.force,
            )
            print_result({"path": str(path), "bytes": len(content), "sha256": digest})
            return COMPLETE
        elif args.command == "submit":
            result = client.submit(args.challenge_id, args.answer_id, args.answer)
            print_result(result, secrets)
            if not isinstance(result, dict):
                raise GameMasterError("Submission returned an unexpected result.")
            outcome = result.get("result")
            outcome = outcome.casefold() if isinstance(outcome, str) else ""
            if outcome not in {"correct", "accepted", "incorrect", "expired"}:
                raise GameMasterError("Submission returned an unknown result.")
            state = AttemptState.parse(result)
            if state.expired:
                return EXPIRED
            if outcome == "incorrect":
                return INCORRECT
            if state.pending:
                return PENDING
            return COMPLETE if outcome == "correct" else UNRESOLVED
        else:
            result = client.api_schema()
        print_result(result, secrets)
        return COMPLETE
    except (GameMasterError, OSError) as exc:
        # Escape untrusted control characters, and redact the configured bearer.
        print(f"error: {safe_value(str(exc), secrets)!r}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted. Check server status before repeating a POST.", file=sys.stderr)
        return 130
    finally:
        held.close()
        if client is not None:
            client.close()

