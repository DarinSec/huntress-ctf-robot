"""Web Exploitation lane: read a flag from the challenge's own assigned live target.

Unlike the file solvers, a web solver reaches the network -- but only the host(s) the Game
Master listed in the started attempt's `targets[]`, checked before every request. The
deterministic file solvers keep their no-network rule; this package is the one exception,
confined to the assigned target. A handler lives in its own module here, defines
`WEB_SOLVERS = (YourHandler(),)` and is picked up automatically, the same shape as the
file lanes. It returns an AnswerCandidate with the flag only when it actually read one.
"""

from __future__ import annotations

from dataclasses import dataclass
import http.cookiejar
import importlib
import os
import pkgutil
import re
import threading
import time
from typing import Any, Protocol, runtime_checkable
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from ..base import AnswerCandidate

# A single flag read from a live target is small; cap the body so a misbehaving or hostile
# target cannot exhaust memory on the clock.
MAX_BODY_BYTES = 4 * 1024 * 1024
DEFAULT_TIMEOUT = 10.0
_DEFAULT_PORTS = {"http": 80, "https": 443}

# ROBUSTNESS.md workstream 2: the autonomous prober/crawler/fuzzer can fire many requests at
# one target (fingerprint, then every handler, then the universal prober and a form crawl).
# Each request already caps at DEFAULT_TIMEOUT, but hundreds in a row would blow the race
# deadline, so a whole target's probing is also bounded: at most WEB_MAX_REQUESTS requests
# inside WEB_TARGET_BUDGET_S wall-clock seconds. The budget must exceed the slowest single
# legitimate solve (stored XSS polls up to ~18 s). Both are overridable for a tight maze test.
WEB_TARGET_BUDGET_S = float(os.environ.get("HUNTRESS_WEB_BUDGET_S") or 45.0)
WEB_MAX_REQUESTS = int(os.environ.get("HUNTRESS_WEB_MAX_REQUESTS") or 300)


class HostNotAllowed(Exception):
    """A request aimed at a host the Game Master did not list for this attempt."""


class BudgetExhausted(BaseException):
    """A target's request count or wall-clock budget is spent; stop probing it.

    Deliberately a BaseException, not an Exception: the ported handlers wrap almost every
    request in `except Exception`, so a plain exception would be swallowed and the probing
    cascade would run on regardless. This propagates straight out of the handler to the
    adapter, which ends that target cleanly and reports no proof for it.
    """


class Budget:
    """A per-target ceiling on probing: at most `max_requests` requests within `wall_s`
    wall-clock seconds. The clock starts at the first request; `reset()` begins a fresh
    allowance for the next target. `charge()` returns the seconds left so the caller can
    clamp each request's own timeout and never overrun the ceiling by one slow request.
    """

    def __init__(self, *, max_requests: int = WEB_MAX_REQUESTS, wall_s: float = WEB_TARGET_BUDGET_S) -> None:
        self.max_requests = max_requests
        self.wall_s = wall_s
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self.requests = 0
            self._deadline: float | None = None

    def charge(self) -> float:
        """Count one request and return the seconds left; raise BudgetExhausted when spent."""
        with self._lock:
            now = time.monotonic()
            if self._deadline is None:
                self._deadline = now + self.wall_s
            self.requests += 1
            if self.requests > self.max_requests:
                raise BudgetExhausted(f"request budget spent ({self.max_requests} requests)")
            remaining = self._deadline - now
            if remaining <= 0:
                raise BudgetExhausted(f"time budget spent ({self.wall_s:.0f}s)")
            return remaining


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


def _host_port(url: str) -> tuple[str, int]:
    parts = urlsplit(url)
    if parts.scheme not in _DEFAULT_PORTS:
        raise HostNotAllowed(f"unsupported scheme: {url}")
    return parts.hostname or "", parts.port or _DEFAULT_PORTS[parts.scheme]


def target_urls(targets: Any) -> list[str]:
    """The URLs the Game Master issued, from targets[] (strings or {url|target|href|...})."""
    urls: list[str] = []
    for item in targets or ():
        if isinstance(item, str):
            urls.append(item)
        elif isinstance(item, dict):
            for key in ("url", "target", "href", "endpoint", "address", "base_url"):
                value = item.get(key)
                if isinstance(value, str) and value:
                    urls.append(value)
                    break
    return urls


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # A session/auth challenge needs the handler to see the 30x itself, not be bounced on.
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class ScopedHttp:
    """An HTTP client confined to an allowlist of (host, port). Every request checks its
    target first and raises HostNotAllowed otherwise, so a handler can never reach a host
    outside the assignment. One cookie jar per client carries a session across requests.
    """

    def __init__(self, allowed: frozenset[tuple[str, int]], *, timeout: float = DEFAULT_TIMEOUT,
                 opener: Any = None, max_bytes: int = MAX_BODY_BYTES, budget: Budget | None = None) -> None:
        self.allowed = allowed
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.budget = budget
        self.jar = http.cookiejar.CookieJar()
        self._opener = opener or urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPCookieProcessor(self.jar)
        )

    def allows(self, url: str) -> bool:
        try:
            return _host_port(url) in self.allowed
        except HostNotAllowed:
            return False

    def request(self, method: str, url: str, *, data: bytes | None = None,
                headers: dict[str, str] | None = None) -> Response:
        if not self.allows(url):
            raise HostNotAllowed(url)
        timeout = self.timeout
        if self.budget is not None:  # One request at a time stays under the per-target ceiling.
            timeout = min(timeout, self.budget.charge())
        request = urllib.request.Request(url, data=data, method=method.upper(), headers=headers or {})
        try:
            response = self._opener.open(request, timeout=timeout)
            return Response(response.status, dict(response.headers), response.read(self.max_bytes), response.geturl())
        except urllib.error.HTTPError as error:  # A 4xx/5xx is a normal answer, not a failure.
            body = error.read(self.max_bytes) if hasattr(error, "read") else b""
            return Response(error.code, dict(error.headers or {}), body, url)

    def get(self, url: str, **kwargs: Any) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Response:
        return self.request("POST", url, **kwargs)


def scoped_http(targets: Any, **kwargs: Any) -> ScopedHttp:
    """A client allowed to reach exactly the hosts in targets[] and nothing else, with a
    default per-target request/time Budget unless the caller passes its own (or None)."""
    allowed = set()
    for url in target_urls(targets):
        try:
            allowed.add(_host_port(url))
        except HostNotAllowed:
            continue
    kwargs.setdefault("budget", Budget())
    return ScopedHttp(frozenset(allowed), **kwargs)


@dataclass(frozen=True)
class TargetContext:
    """What a web handler is given: the live target(s) and a client confined to them."""

    challenge_id: str
    challenge: dict[str, Any]
    attempt: dict[str, Any]
    answer_ids: tuple[str, ...]
    targets: tuple[Any, ...]
    http: ScopedHttp

    @property
    def curriculum_day(self) -> Any:
        day = self.challenge.get("curriculum_day")
        if day is not None:
            return day
        # Fall back to the calendar day in the challenge ID (web-exploitation-day-07-...).
        # A single-solve route's day equals its vulnerability class (days 1-10), so when the
        # attempt metadata omits the field the handler still dispatches directly instead of
        # paying the fingerprint round trips on the clock. A later/compound day (> 10) is not
        # a known handler, so detect_and_solve fingerprints as before -- no behaviour change.
        match = re.search(r"day-0*(\d+)", self.challenge_id or "")
        return int(match.group(1)) if match else None

    @property
    def url(self) -> str:
        urls = target_urls(self.targets)
        return urls[0] if urls else ""


@runtime_checkable
class TargetSolver(Protocol):
    name: str

    def solve(self, context: TargetContext) -> list[AnswerCandidate]: ...


LOAD_ERRORS: list[str] = []


def _discover() -> tuple[TargetSolver, ...]:
    found: list[TargetSolver] = []
    for module in pkgutil.iter_modules(__path__):
        if module.name.startswith("_"):
            continue
        try:
            loaded = importlib.import_module(f"{__name__}.{module.name}")
        except Exception as exc:  # A broken handler must not take the others down.
            LOAD_ERRORS.append(f"solvers.web.{module.name}: {type(exc).__name__}: {exc}")
            continue
        found.extend(getattr(loaded, "WEB_SOLVERS", ()))
    return tuple(found)


WEB_SOLVERS: tuple[TargetSolver, ...] = _discover()
