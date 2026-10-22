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
import pkgutil
import re
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


class HostNotAllowed(Exception):
    """A request aimed at a host the Game Master did not list for this attempt."""


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
                 opener: Any = None, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.allowed = allowed
        self.timeout = timeout
        self.max_bytes = max_bytes
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
        request = urllib.request.Request(url, data=data, method=method.upper(), headers=headers or {})
        try:
            response = self._opener.open(request, timeout=self.timeout)
            return Response(response.status, dict(response.headers), response.read(self.max_bytes), response.geturl())
        except urllib.error.HTTPError as error:  # A 4xx/5xx is a normal answer, not a failure.
            body = error.read(self.max_bytes) if hasattr(error, "read") else b""
            return Response(error.code, dict(error.headers or {}), body, url)

    def get(self, url: str, **kwargs: Any) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Response:
        return self.request("POST", url, **kwargs)


def scoped_http(targets: Any, **kwargs: Any) -> ScopedHttp:
    """A client allowed to reach exactly the hosts in targets[] and nothing else."""
    allowed = set()
    for url in target_urls(targets):
        try:
            allowed.add(_host_port(url))
        except HostNotAllowed:
            continue
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
