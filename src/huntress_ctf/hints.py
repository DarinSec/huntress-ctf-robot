"""Remember which solver scored on each challenge, so later runs go straight to it.

A hint is written only after the Game Master returned CORRECT for a submitted
candidate. `daily --timed` races only challenges that have a hint, and only once: a
completed race stores `raced_at`, the race count and the best server-clock time.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
from typing import Any, Iterable

from .config import REPO_ROOT
from .solvers import AnswerCandidate

_WRITING = threading.Lock()  # `daily` runs challenge families in parallel threads.


def default_path() -> Path:
    state = os.environ.get("HUNTRESS_STATE_DIR")
    return (Path(state) if state else REPO_ROOT / ".huntress") / "hints.json"


def load_hints(path: Path | None = None) -> dict[str, dict[str, Any]]:
    path = path or default_path()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def get_hint(challenge_id: str, path: Path | None = None) -> dict[str, Any] | None:
    hint = load_hints(path).get(challenge_id)
    return hint if isinstance(hint, dict) else None


def _save(hints: dict[str, Any], path: Path, what: str) -> str | None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(hints, indent=2, sort_keys=True), encoding="utf-8")
        temporary.replace(path)
    except OSError as exc:
        return f"Could not save the {what}: {exc}"
    return None


def record_hint(
    challenge_id: str, candidates: Iterable[AnswerCandidate], path: Path | None = None,
) -> str | None:
    """Store the scoring solvers; returns an error note instead of raising."""
    candidates = list(candidates)
    if not candidates:
        return None
    path = path or default_path()
    chains = {candidate.chain for candidate in candidates if candidate.chain}
    with _WRITING:
        hints = load_hints(path)
        previous = hints.get(challenge_id) if isinstance(hints.get(challenge_id), dict) else {}
        hints[challenge_id] = {
            **previous,  # Keeps the race record of earlier runs.
            "solvers": sorted({candidate.solver for candidate in candidates}),
            "chain": list(next(iter(chains))) if len(chains) == 1 else [],
            "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        return _save(hints, path, "solver hint")


TURNED_DOWN_KEYS = ("turned_down", "turned_down_at")

# Outcomes that prove another variant would be spent for nothing. A timed run counts only
# when the service rejected a submission: its "unresolved" is also what a gate skip and a
# reserve stop return, and neither spends anything.
TURNED_DOWN = {False: {"incorrect", "unresolved", "conflict"}, True: {"incorrect"}}


def record_outcome(
    challenge_id: str, outcome: str, timed: bool = False, path: Path | None = None,
) -> str | None:
    """Remember a run that no further variant should be spent on until something changes.

    A race submits once and has no second chance, so a route whose answers the service
    has already turned down costs a ranked variant for nothing - day 23's Metadata Time
    Trial raced three times on the same rejected answer, and the Android one three times
    with no answer at all. "complete" clears the mark, so the first run after a fix lets
    the route race again; `--rerace` ignores it meanwhile.
    """
    path = path or default_path()
    if outcome != "complete" and outcome not in TURNED_DOWN[bool(timed)]:
        return None
    with _WRITING:
        hints = load_hints(path)
        entry = hints.get(challenge_id) if isinstance(hints.get(challenge_id), dict) else {}
        if outcome == "complete":
            if not entry.keys() & set(TURNED_DOWN_KEYS):
                return None  # Nothing to clear; record_hint writes the hint itself.
            for key in TURNED_DOWN_KEYS:
                entry.pop(key, None)
        else:
            entry["turned_down"] = outcome + (" (timed)" if timed else "")
            entry["turned_down_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        hints[challenge_id] = entry
        return _save(hints, path, "run outcome")


def record_race(challenge_id: str, on_clock_ms: float | None, path: Path | None = None) -> str | None:
    """After a completed timed race: count it and keep the best server-clock estimate."""
    path = path or default_path()
    with _WRITING:
        hints = load_hints(path)
        entry = hints.get(challenge_id) if isinstance(hints.get(challenge_id), dict) else {}
        best = entry.get("best_on_clock_ms")
        if on_clock_ms is not None and (not isinstance(best, (int, float)) or on_clock_ms < best):
            entry["best_on_clock_ms"] = on_clock_ms
        entry["races"] = int(entry.get("races") or 0) + 1
        entry["raced_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        hints[challenge_id] = entry
        return _save(hints, path, "race record")
