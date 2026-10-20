"""Measured transport facts per Game Master URL, kept next to the solver hints.

`bench --pipeline` writes whether a route answers pipelined requests in order; a timed
run uses pipelining only where that probe passed, and turns it off again if a real run
shows otherwise. Nothing here is secret: URLs, booleans, and milliseconds.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import struct
import subprocess
import time
from typing import Any

from .hints import default_path as _hints_path


NTP_SERVER = "time.cloudflare.com"
_NTP_EPOCH = 2208988800


def clock_offset(server: str = NTP_SERVER, tries: int = 3, timeout: float = 1.0) -> float | None:
    """Seconds the local clock is ahead of true time (SNTP), or None when unreachable.

    Needed to place the server's `started_at` on our timeline: the player's PC ran 5 s
    fast (19 Oct 2026), which would swamp a race time measured in hundreds of ms.
    """
    best: tuple[float, float] | None = None
    for _ in range(tries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(timeout)
                sent = time.time()
                udp.sendto(b"\x23" + 47 * b"\0", (server, 123))
                data, _ = udp.recvfrom(48)
                received = time.time()
        except OSError:
            continue
        if len(data) < 48:
            continue
        stamp = lambda at: (lambda s, f: s - _NTP_EPOCH + f / 2**32)(*struct.unpack("!II", data[at:at + 8]))
        server_in, server_out = stamp(32), stamp(40)
        delay = (received - sent) - (server_out - server_in)
        offset = ((sent - server_in) + (received - server_out)) / 2
        if best is None or delay < best[0]:
            best = (delay, offset)
    if best:
        return best[1]
    # Homebase blocks outbound NTP but keeps its own clock synchronized (19 Oct 2026).
    return 0.0 if system_clock_synced() else None


def system_clock_synced() -> bool:
    """True when the operating system reports an NTP-synchronized clock (systemd/chrony)."""
    if Path("/run/systemd/timesync/synchronized").exists():
        return True
    try:
        result = subprocess.run(
            ["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
            capture_output=True, text=True, timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.stdout.strip() == "yes"


def default_path(hints_path: Path | None = None) -> Path:
    """Beside the hints file, so tests that pass a temporary hints path stay isolated."""
    return (hints_path or _hints_path()).with_name("network.json")


def load(path: Path | None = None) -> dict[str, dict[str, Any]]:
    try:
        value = json.loads((path or default_path()).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def pipelining_ok(base_url: str | None, path: Path | None = None) -> bool:
    entry = load(path).get(base_url or "")
    return isinstance(entry, dict) and entry.get("pipelining") is True


def record(base_url: str, path: Path | None = None, **fields: Any) -> str | None:
    """Merge fields into the route's entry; returns an error note instead of raising."""
    path = path or default_path()
    state = load(path)
    entry = state.get(base_url) if isinstance(state.get(base_url), dict) else {}
    entry.update(fields, recorded_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    state[base_url] = entry
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
        temporary.replace(path)
    except OSError as exc:
        return f"Could not save the network facts: {exc}"
    return None
