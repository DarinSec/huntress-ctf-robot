"""Read-only integration checks and redacted captures of actual API responses."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
import math
from pathlib import Path
from statistics import median
import time
from typing import Any, Callable
from uuid import uuid4

from .autopilot import find_challenge
from .client import GameMasterClient, GameMasterError
from .display import safe_value
from .network import record as record_network
from .state import AttemptState, mode_name


def schema_summary(response: Any) -> dict[str, Any]:
    if not isinstance(response, dict):
        raise GameMasterError("The schema is not an OpenAPI object.")
    version = response.get("openapi", response.get("swagger"))
    paths = response.get("paths")
    if (
        not isinstance(version, str)
        or not (version.startswith("3.") or version == "2.0")
        or not isinstance(paths, dict) or not paths
        or any(not isinstance(path, str) or not isinstance(item, dict) for path, item in paths.items())
    ):
        raise GameMasterError("The schema has an unsupported version or paths structure.")
    methods = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
    operations = sum(key.casefold() in methods for item in paths.values() for key in item)
    if not operations:
        raise GameMasterError("The schema contains no inline HTTP operations to inspect.")
    return {"version": version, "path_count": len(paths), "operation_count": operations}


def _records(response: Any) -> list[dict[str, Any]]:
    records = response
    if isinstance(response, dict):
        records = response.get("challenges", response.get("items"))
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise GameMasterError("The challenge list has an unsupported structure.")
    ids = [record.get("id", record.get("challenge_id")) for record in records]
    if any(not isinstance(item, str) or not item.strip() for item in ids):
        raise GameMasterError("The challenge list contains invalid IDs.")
    if len(set(ids)) != len(ids):
        raise GameMasterError("The challenge list contains duplicate IDs.")
    return records


def run_diagnostics(
    client: GameMasterClient, *, challenge_ids: tuple[str, ...] = (),
    output_root: Path | None = None,
) -> tuple[dict[str, Any], int]:
    """Only GET schema/list/status. Never create, retry, or submit an attempt."""
    secrets = (client.token,) if client.token else ()
    captured_at = datetime.now(timezone.utc)
    directory = None
    if output_root is not None:
        name = captured_at.strftime("capture-%Y%m%dT%H%M%SZ-") + uuid4().hex[:8]
        directory = output_root / name
        directory.mkdir(parents=True, exist_ok=False)

    def save(filename: str, value: Any) -> None:
        if directory is not None:
            with (directory / filename).open("x", encoding="utf-8") as stream:
                json.dump(safe_value(value, secrets), stream, indent=2, ensure_ascii=True)
                stream.write("\n")

    report: dict[str, Any] = {
        "captured_at": captured_at.isoformat(),
        "base_url": client.base_url,
        "bearer_configured": bool(client.token),
        "scope": "Read-only endpoint checks and local response parsing; gameplay and CourseStack scoring are unverified.",
        "checks": [],
    }
    if directory is not None:
        report["capture_directory"] = str(directory.resolve())

    def check(
        name: str, filename: str, fetch: Callable[[], Any],
        inspect: Callable[[Any], dict[str, Any]],
    ) -> Any:
        entry: dict[str, Any] = {"name": name}
        response = None
        try:
            response = fetch()
            save(filename, {
                "source": "live Game Master response", "operation": name,
                "captured_at": captured_at.isoformat(), "response": response,
            })
            entry.update(status="passed", details=inspect(response))
        except GameMasterError as exc:
            entry.update(status="failed", error=str(exc))
        report["checks"].append(entry)
        return response if entry["status"] == "passed" else None

    check("openapi", "schema.json", client.api_schema, schema_summary)

    def inspect_list(response: Any) -> dict[str, Any]:
        records = _records(response)
        modes = Counter(mode_name(record, AttemptState()) for record in records)
        return {"count": len(records), "modes": dict(modes)}

    catalog = check("list", "challenges.json", client.list_challenges, inspect_list)
    # Index-based filenames keep arbitrary remote IDs out of filesystem paths.
    for index, challenge_id in enumerate(dict.fromkeys(challenge_ids), 1):
        name = f"status:{challenge_id}"
        if catalog is None:
            report["checks"].append({
                "name": name, "status": "skipped", "error": "The live challenge list was unavailable.",
            })
            continue
        try:
            challenge = find_challenge(catalog, challenge_id)
        except GameMasterError as exc:
            report["checks"].append({"name": name, "status": "failed", "error": str(exc)})
            continue

        def inspect_status(response: Any) -> dict[str, Any]:
            state = AttemptState.parse(response)
            return {
                "mode": mode_name(challenge, state), "deadline": state.deadline,
                "answer_count": len(state.answer_ids) if state.answer_ids is not None else None,
                "remaining": state.remaining, "expired": state.expired,
                "complete": state.complete, "pending": state.pending,
            }

        check(name, f"status-{index:03}.json", lambda: client.status(challenge_id), inspect_status)

    report["ok"] = all(entry["status"] == "passed" for entry in report["checks"])
    save("report.json", report)
    return safe_value(report, secrets), 0 if report["ok"] else 1


def _latency(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    return {
        "min": round(ordered[0], 1), "median": round(median(ordered), 1),
        "p90": round(ordered[math.ceil(0.9 * len(ordered)) - 1], 1),
        "max": round(ordered[-1], 1),
    }


def run_bench(
    client: GameMasterClient, *, count: int = 10, challenge_id: str | None = None,
    clock: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    """Only GET list or status. Never create, retry, or submit an attempt.

    Compares a new TCP+TLS connection per request with one kept-alive connection,
    which is the per-request cost a timed run pays twice on the clock.
    """
    if type(count) is not int or count < 1:
        raise GameMasterError("count must be a positive integer.")
    fetch = (lambda: client.status(challenge_id)) if challenge_id else client.list_challenges

    def measure(fresh: bool) -> list[float]:
        samples = []
        for _ in range(count):
            if fresh:
                client.close()
            began = clock()
            fetch()
            samples.append((clock() - began) * 1000)
        return samples

    fresh = measure(True)
    client.close()
    client.warm()
    kept = measure(False)
    fresh_summary, kept_summary = _latency(fresh), _latency(kept)
    report: dict[str, Any] = {
        "base_url": client.base_url,
        "operation": "status" if challenge_id else "list",
        "count": count,
        "fresh_connection_ms": fresh_summary,
        "kept_alive_ms": kept_summary,
        "saved_per_request_ms": round(fresh_summary["median"] - kept_summary["median"], 1),
    }
    if challenge_id:
        # The download is on the timed clock too; a few kept-alive GETs show its cost.
        try:
            samples = []
            for _ in range(min(count, 3)):
                began = clock()
                size = len(client.artifact(challenge_id))
                samples.append((clock() - began) * 1000)
            report["artifact_ms"] = {**_latency(samples), "bytes": size}
        except GameMasterError as exc:
            report["artifact_ms"] = {"unavailable": str(exc)}
    client.close()
    return report


# Pipelining is only worth turning on where it measurably beats one request at a time.
MIN_PIPELINE_SAVING_MS = 5.0


def probe_pipelining(
    client: GameMasterClient, *, challenge_id: str, rounds: int = 3,
    clock: Callable[[], float] = time.perf_counter, network_path: Path | None = None,
) -> dict[str, Any]:
    """Only GET status and artifact. Never create, retry, or submit an attempt.

    Sends the race's own pair shape (a JSON response, then the artifact bytes) in one
    write, `rounds` times, on one kept-alive connection. It passes only if every round
    returns both, in order, and the connection stays open; the verdict is saved so timed
    runs pipeline start + artifact only where it passed. (Not the list: listing every
    day takes the server about 80 s.)
    """
    calls = (
        {"operation": "status", "params": {"challenge": challenge_id}},
        {"operation": "artifact", "params": {"challenge": challenge_id}, "expect_json": False},
    )
    pipelined: list[float] = []
    sequential: list[float] = []
    reason = None
    client.close()
    client.warm()
    for _ in range(rounds):
        began = clock()
        results = client.pipeline(*calls)
        pipelined.append((clock() - began) * 1000)
        failed = next((result for result in results if isinstance(result, GameMasterError)), None)
        if failed is not None:
            reason = str(failed)
        elif not client.connected:
            reason = "The server closed the connection after a pipelined pair."
        elif not isinstance(results[0], dict) or not isinstance(results[1], bytes):
            reason = "The pipelined responses did not come back as status, then artifact."
        if reason:
            break
        began = clock()
        for call in calls:
            client.request(**call)
        sequential.append((clock() - began) * 1000)
    client.close()
    report: dict[str, Any] = {"base_url": client.base_url, "rounds": rounds}
    timings: dict[str, Any] = {}
    if not reason:
        report["pipelined_pair_ms"] = _latency(pipelined)
        report["sequential_pair_ms"] = _latency(sequential)
        saved = report["saved_per_race_ms"] = round(median(sequential) - median(pipelined), 1)
        timings = {"pipelined_pair_ms": report["pipelined_pair_ms"]["median"],
                   "sequential_pair_ms": report["sequential_pair_ms"]["median"]}
        if saved < MIN_PIPELINE_SAVING_MS:
            # Correct but no faster: the server answers the pair one after the other.
            reason = f"Pipelining works but saved {saved} ms; one request at a time is kept."
    report["pipelining"] = reason is None
    if reason:
        report["reason"] = reason
    note = record_network(
        client.base_url, network_path, pipelining=reason is None,
        **({"reason": reason} if reason else {}), **timings,
    )
    if note:
        report["note"] = note
    return report


def compare_routes(
    benches: list[tuple[str, Callable[[], dict[str, Any]]]],
) -> dict[str, Any]:
    """Run each route's bench; recommend the lowest kept-alive median that answered."""
    routes = []
    for label, bench in benches:
        try:
            routes.append({"route": label, **bench()})
        except GameMasterError as exc:
            routes.append({"route": label, "unavailable": str(exc)})
    answered = [route for route in routes if "kept_alive_ms" in route]
    best = min(answered, key=lambda route: route["kept_alive_ms"]["median"], default=None)
    return {
        "routes": routes,
        "recommended": None if best is None else {
            "route": best["route"], "base_url": best["base_url"],
            "kept_alive_median_ms": best["kept_alive_ms"]["median"],
            "why": "Lowest kept-alive round trip; a timed run pays about two of them on the clock.",
        },
    }
