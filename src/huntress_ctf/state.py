"""Parse current attempt fields without interpreting examples or past attempts."""

from __future__ import annotations

from dataclasses import dataclass, replace
import re
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .client import GameMasterError


def string_ids(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise GameMasterError(f"{field} must be a list of nonempty string IDs.")
    if len(set(value)) != len(value):
        raise GameMasterError(f"{field} contains duplicate IDs.")
    return tuple(value)


def current_fields(response: Any) -> dict[str, Any]:
    if not isinstance(response, dict) or not response:
        raise GameMasterError("Expected a nonempty Game Master response object.")
    fields = dict(response)
    for key in ("attempt", "current_attempt"):
        nested = response.get(key)
        if isinstance(nested, dict):
            fields.update(nested)
            if "id" in nested and "attempt_id" not in nested:
                fields["attempt_id"] = nested["id"]
    return fields


_CAPABILITY_PATH = re.compile(r"/download/([A-Za-z0-9_-]{16,})/?$")


def deliveries(response: Any) -> list[dict[str, Any]]:
    """Every listed artifact in listed order: {index, filename, sha256, capability}.

    Questions name them "delivery N: <filename>" (N = index + 1). The robot fetches each
    with op=artifact&delivery=<index>, which works on every route. The download link's
    capability ("/?op=download&capability=..." directly, ".../download/<capability>" in
    Homebase-style links, absent through the proxy) is kept as a fallback.
    """
    try:
        fields = current_fields(response)
    except GameMasterError:
        return []
    found = []
    listed = fields.get("artifacts")
    if not isinstance(listed, list) and isinstance(fields.get("download"), str):
        # A single-artifact start response carries its link and hash at the top level.
        listed = [{"download": fields["download"], "sha256": fields.get("sha256")}]
    for item in listed or ():
        if not isinstance(item, dict):
            continue
        capability = None
        if isinstance(item.get("download"), str):
            parts = urlsplit(item["download"])
            capability = (parse_qs(parts.query).get("capability") or [None])[0]
            if not capability:
                match = _CAPABILITY_PATH.search(parts.path)
                capability = match[1] if match else None
        found.append({
            "index": len(found),
            "filename": item.get("filename") if isinstance(item.get("filename"), str) else "artifact",
            "capability": capability,
            "sha256": item["sha256"].lower() if isinstance(item.get("sha256"), str) else None,
            "size": item["size"] if isinstance(item.get("size"), int) else None,
        })
    return found


def _text(value: Any) -> str:
    return value.casefold() if isinstance(value, str) else ""


@dataclass(frozen=True)
class AttemptState:
    answer_ids: tuple[str, ...] | None = None
    accepted_ids: frozenset[str] = frozenset()
    attempt_id: str | None = None
    artifact_sha256: str | None = None
    mode: str | None = None
    deadline: str | None = None
    remaining: int | None = None
    expired: bool = False
    complete: bool = False
    pending: bool = False
    inactive: bool = False

    @classmethod
    def parse(cls, response: Any) -> AttemptState:
        fields = current_fields(response)
        known = {
            "answer_ids", "accepted_answer_ids", "accepted_ids", "attempt_id", "artifact_sha256",
            "artifact", "artifacts", "mode", "deadline", "remaining", "result", "status", "state",
        }
        if not known.intersection(fields):
            raise GameMasterError("The Game Master response has no recognized attempt fields.")
        if fields.get("error") or _text(fields.get("result")) in {"error", "failed"}:
            raise GameMasterError("The Game Master reported an operation error.")
        states = {_text(fields.get(key)) for key in ("result", "status", "state")}
        if "error" in states:
            raise GameMasterError("The Game Master reported an operation error.")
        # "already_solved": a teammate solved this attempt first ("Further submissions are not
        # scored"). Day 24's Binary TT and Mastery ended "error" on that submit response.
        completed = bool(states.intersection({"correct", "completed", "complete", "solved", "already_solved"}))
        if completed and "incorrect" in states:
            raise GameMasterError("The submission response contradicts itself about completion.")
        ids = string_ids(fields["answer_ids"], "answer_ids") if "answer_ids" in fields else None
        # The live service says `accepted_ids`; `accepted_answer_ids` is the older spelling.
        accepted_key = next((key for key in ("accepted_answer_ids", "accepted_ids") if key in fields), None)
        accepted = string_ids(fields[accepted_key], accepted_key) if accepted_key else ()
        attempt_id = fields.get("attempt_id")
        if attempt_id is not None and (
            not isinstance(attempt_id, str) or not attempt_id.strip()
        ):
            raise GameMasterError("attempt_id must be a nonempty string.")
        digest = fields.get("artifact_sha256")
        if digest is None and isinstance(fields.get("artifact"), dict):
            digest = fields["artifact"].get("sha256")
        if digest is None and isinstance(fields.get("download"), str):
            # A single-artifact start response: top-level {download, sha256} (19 Oct 2026).
            digest = fields.get("sha256")
        listed = fields.get("artifacts")
        if digest is None and isinstance(listed, list) and len(listed) == 1 and isinstance(listed[0], dict):
            # The live service lists one artifact {filename, sha256, size, download}; its
            # sha256 is that of the op=artifact bytes (checked on Day 1 responses).
            digest = listed[0].get("sha256")
        if digest is not None:
            if not isinstance(digest, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
                raise GameMasterError("The assigned artifact SHA-256 is malformed.")
            digest = digest.lower()
        remaining = fields.get("remaining")
        if remaining is not None and (
            type(remaining) is not int or remaining < 0
        ):
            raise GameMasterError("remaining must be a nonnegative integer.")
        if completed and remaining:
            raise GameMasterError("The response reports completion but still has remaining answers.")
        mode = fields.get("mode")
        deadline = fields.get("deadline")
        for name, value in (("mode", mode), ("deadline", deadline)):
            if value is not None and not isinstance(value, str):
                raise GameMasterError(f"{name} must be a string or null.")
        return cls(
            answer_ids=ids, accepted_ids=frozenset(accepted),
            attempt_id=attempt_id, artifact_sha256=digest, mode=mode,
            deadline=deadline, remaining=remaining,
            expired="expired" in states,
            complete=completed,
            pending="pending" in states,
            inactive=bool(states.intersection({"locked", "not_started", "unavailable"})),
        )


def ensure_same_attempt(reference: AttemptState, current: AttemptState) -> None:
    for field in ("attempt_id", "artifact_sha256", "deadline", "mode"):
        before, after = getattr(reference, field), getattr(current, field)
        if before is not None and after is not None and before != after:
            raise GameMasterError(
                f"The attempt's {field} changed during analysis. Reconnect before submitting."
            )
    if reference.answer_ids is not None and current.answer_ids is not None:
        if set(reference.answer_ids) != set(current.answer_ids):
            raise GameMasterError("The attempt's answer IDs changed during analysis.")


def remember_identity(reference: AttemptState, current: AttemptState) -> AttemptState:
    """Keep known identifiers even when an intermediate response omits them."""
    ensure_same_attempt(reference, current)
    fields = ("attempt_id", "artifact_sha256", "deadline", "mode", "answer_ids")
    return replace(current, **{
        field: getattr(reference, field)
        for field in fields if getattr(current, field) is None
    })


def mode_name(challenge: dict[str, Any], state: AttemptState) -> str:
    mode = state.mode or challenge.get("mode")
    if not isinstance(mode, str):
        return "Unknown (not reported by the service)"
    normalized = re.sub(r"[\s_-]+", " ", mode.casefold()).strip()
    return {
        "single": "Single Solve", "single solve": "Single Solve",
        "time trial": "Time Trial", "mastery": "Mastery Mode",
        "mastery mode": "Mastery Mode",
    }.get(normalized, mode)
