"""One robot per machine: every command that can start, retry or submit holds a lock.

Teammates share attempts, so two robots on one Homebase (cron and a run by hand, 20 Oct
2026) raced each other on the same attempts. The lock is advisory and the OS releases it
when the process ends, so a crash never leaves it stuck. The owner file only explains
who holds it.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from typing import Callable, Iterator

from .client import GameMasterError

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None
    import msvcrt

POLL_SECONDS = 1.0


def default_path() -> Path:
    configured = os.environ.get("HUNTRESS_LOCK")
    return Path(configured) if configured else Path.home() / ".huntress" / "robot.lock"


def _acquire(handle) -> bool:
    try:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        else:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        return True
    except OSError:
        return False


def _release(handle) -> None:
    try:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        else:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    except OSError:
        pass


def holder(path: Path | None = None) -> str:
    owner = (path or default_path()).with_suffix(".owner")
    try:
        info = json.loads(owner.read_text(encoding="utf-8"))
        return f"pid {info['pid']}, `{info['command']}`, since {info['since']}"
    except (OSError, ValueError, KeyError, TypeError):
        return "an unknown process"


@contextmanager
def robot_lock(
    command: str, *, wait: float = 0.0, path: Path | None = None,
    sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
) -> Iterator[None]:
    """Hold the robot lock; wait up to `wait` seconds for another robot to finish first."""
    path = path or default_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(path, "a+b")
    try:
        deadline = clock() + wait
        announced = False
        while not _acquire(handle):
            if clock() >= deadline:
                raise GameMasterError(
                    f"Another robot holds {path} ({holder(path)}). Teammates share attempts, so "
                    "only one may start, retry or submit. Wait for it, or pass --lock-wait SECONDS."
                )
            if not announced:
                print(f"Waiting up to {wait:.0f} s for the robot lock ({holder(path)}).", flush=True)
                announced = True
            sleep(POLL_SECONDS)
        owner = path.with_suffix(".owner")
        try:
            owner.write_text(json.dumps({
                "pid": os.getpid(), "command": command,
                "since": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }), encoding="utf-8")
        except OSError:
            pass
        try:
            yield
        finally:
            _release(handle)
    finally:
        handle.close()
