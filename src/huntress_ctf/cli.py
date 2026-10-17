"""Command-line interface for the Huntress Game Master client."""

from __future__ import annotations

import argparse
import getpass
import math
from pathlib import Path
import sys
import warnings

from .artifacts import save_artifact
from .autopilot import COMPLETE, EXPIRED, INCORRECT, PENDING, UNRESOLVED, run_autopilot
from .client import DEFAULT_BASE_URL, GameMasterClient, GameMasterError
from .config import load_env
from .containers import DEFAULT_PASSWORDS, unwrap
from .daily import run_daily
from .display import print_result, safe_value
from .diagnostics import run_bench, run_diagnostics
from .fastpath import run_timed_fast
from .state import AttemptState
from .workspace import render_triage

CAPTURE_DIR = Path("integration-data")


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="huntress-ctf", description="Interact with the Huntress CTF 2026 Game Master.",
    )
    parser.add_argument(
        "--base-url", help=f"Base URL (HUNTRESS_GM_URL or {DEFAULT_BASE_URL})",
    )
    parser.add_argument("--timeout", type=_positive_timeout, default=30, help="HTTP timeout in seconds")
    parser.add_argument("--prompt-token", action="store_true", help="Read a bearer token with hidden terminal input")
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
    daily = commands.add_parser("daily", help="Solve every available challenge untimed, or race the proven ones")
    daily.add_argument("--day", type=_day)
    daily.add_argument("--lane")
    daily.add_argument("--timed", action="store_true", help="Race only challenges whose solver already scored CORRECT")
    daily.add_argument("--capture", action="store_true", help=f"Save redacted responses under {CAPTURE_DIR}")
    triage = commands.add_parser("triage", help="Print a one-page triage report for a local file (offline)")
    triage.add_argument("path", type=Path)
    triage.add_argument("--password", action="append", default=[], help="Archive password to try (repeatable)")
    status = commands.add_parser("status", help="Read current attempt status")
    status.add_argument("challenge_id")
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
    bench.add_argument("--challenge", metavar="ID", help="Time this challenge's status instead of the list")
    return parser


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
        unwrapped = unwrap(data, tuple(dict.fromkeys([*args.password, *DEFAULT_PASSWORDS])))
        print(render_triage(data, unwrapped.members, unwrapped.notes, title=args.path.name), end="")
        return COMPLETE
    try:
        load_env()
        if args.prompt_token:
            token = _prompt_token()
            secrets = (token,)
            client = GameMasterClient(base_url=args.base_url, timeout=args.timeout, token=token)
        else:
            client = GameMasterClient(base_url=args.base_url, timeout=args.timeout)
        secrets = (client.token,) if client.token else ()
        if args.command == "list":
            result = client.list_challenges(args.day, args.lane)
        elif args.command == "start":
            result = client.start(args.challenge_id, timed=args.timed)
        elif args.command == "retry":
            result = client.retry(args.challenge_id, timed=args.timed)
        elif args.command == "status":
            result = client.status(args.challenge_id)
        elif args.command == "solve":
            capture = CAPTURE_DIR if args.capture else None
            if args.timed:
                return run_timed_fast(client, args.challenge_id, capture_dir=capture)
            return run_autopilot(client, args.challenge_id, capture_dir=capture)
        elif args.command == "daily":
            return run_daily(
                client, day=args.day, lane=args.lane, timed=args.timed,
                capture_dir=CAPTURE_DIR if args.capture else None,
            )
        elif args.command == "bench":
            print_result(run_bench(client, count=args.count, challenge_id=args.challenge), secrets)
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
        if client is not None:
            client.close()

