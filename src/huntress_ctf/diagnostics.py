"""Read-only integration checks and redacted captures of actual API responses."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from .autopilot import find_challenge
from .client import GameMasterClient, GameMasterError
from .display import safe_value
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
