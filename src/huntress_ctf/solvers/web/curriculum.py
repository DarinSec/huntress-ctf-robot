"""Adapter: run the Web Exploitation curriculum handlers as a scoped `TargetSolver`.

`handlers.py` (Parsa's, ported from verified live runs across curriculum days 1-10) is a
set of standalone `solve_*(target_url) -> proof` functions dispatched by `detect_and_solve`
/ `CURRICULUM_HANDLERS`. It is a different shape from this package's `TargetSolver`
protocol, and it reaches the network through its own module-level `_request`, which calls
urllib directly with no host allowlist. This module is the glue between the two shapes --
and, the point of it, it confines every request those handlers make to the hosts the Game
Master listed for this attempt (`ScopedHttp`), so the ported code -- unchanged -- can never
reach a host outside the assignment.

* `CurriculumWebSolver.solve` passes `context.url` and `context.curriculum_day` to
  `detect_and_solve` (which runs the day's handler, or fingerprints a compound target),
  and wraps the proof it recovers as an `AnswerCandidate` -- but only a real `proof_...`
  string, and only when one was actually read.
* For the duration of that run, `handlers._request` is replaced by a shim that raises
  `HostNotAllowed` for any URL off the attempt's allowlist and refuses to follow a redirect
  off it (returning the 30x to the handler, which several read `Set-Cookie` from, rather
  than chasing it). A blocked host, a handler error, or no proof yields no candidate, so
  `_solve_targets` leaves the attempt UNRESOLVED rather than submit a guess.
"""

from __future__ import annotations

import contextlib
import threading
import urllib.error
import urllib.request
from typing import Any, Callable, Iterator

from ..base import AnswerCandidate
from . import HostNotAllowed, ScopedHttp

try:  # handlers.py is third-party within the repo; a broken import must not kill discovery.
    from . import handlers
except Exception:  # pragma: no cover - defensive
    handlers = None  # type: ignore[assignment]

# `handlers._request` is a module global, so the scope guard patches it in place; a lock
# serialises web solves against each other (races run one at a time regardless, and no
# other lane touches this module).
_PATCH_LOCK = threading.Lock()

# Match the User-Agent the ported handlers send, so the shim changes transport only.
_DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def _scoped_request(http: ScopedHttp) -> Callable[..., tuple[int, str, dict[str, str]]]:
    """A drop-in for `handlers._request` confined to `http`'s (host, port) allowlist.

    Keeps the ported function's contract exactly -- `(status, body_text, lower_headers)`,
    its header assembly and its redirect-following -- but gates every hop on the allowlist
    and caps the body, so the handler's own logic is unchanged while its reach is not.
    """

    class _ScopeRedirect(urllib.request.HTTPRedirectHandler):
        # Follow a redirect only to an allowed host; otherwise stop. urllib then raises
        # HTTPError for the 30x, which _request catches and hands back to the handler.
        def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                             headers: Any, newurl: str) -> Any:
            if not http.allows(newurl):
                return None
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(_ScopeRedirect())
    timeout_default = getattr(handlers, "DEFAULT_TIMEOUT", 10.0)

    def _request(url: str, method: str = "GET", data: bytes | None = None,
                 headers: dict[str, str] | None = None, cookie: str | None = None,
                 timeout: float = timeout_default) -> tuple[int, str, dict[str, str]]:
        if not http.allows(url):
            raise HostNotAllowed(url)
        req_headers = {"User-Agent": _DEFAULT_UA}
        if cookie:
            req_headers["Cookie"] = cookie
        if headers:
            req_headers.update(headers)
        request = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        try:
            with opener.open(request, timeout=timeout) as resp:
                body = resp.read(http.max_bytes).decode("utf-8", "replace")
                return resp.status, body, {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as exc:  # a 4xx/5xx -- or a blocked 30x -- is an answer
            body = exc.read(http.max_bytes).decode("utf-8", "replace") if hasattr(exc, "read") else ""
            return exc.code, body, {k.lower(): v for k, v in (exc.headers or {}).items()}

    return _request


@contextlib.contextmanager
def _scope(http: ScopedHttp) -> Iterator[None]:
    """Confine `handlers`' network to `http`'s allowlist for the duration of the block."""
    with _PATCH_LOCK:
        original = handlers._request
        handlers._request = _scoped_request(http)
        try:
            yield
        finally:
            handlers._request = original


class CurriculumWebSolver:
    """Runs the ported curriculum handlers, scoped, and reports only a verified proof."""

    name = "web-curriculum"

    def solve(self, context: Any) -> list[AnswerCandidate]:
        if handlers is None or not context.answer_ids:
            return []
        url = context.url
        if not url or not context.http.allows(url):
            return []
        day = context.curriculum_day
        try:
            day_int: int | None = int(day)
        except (TypeError, ValueError):
            day_int = None
        try:
            with _scope(context.http):
                proof = handlers.detect_and_solve(url, day_int)
        except Exception:
            # WebHandlerError, HostNotAllowed, transport errors: a web route with no proof
            # is left UNRESOLVED, never guessed. Ported handlers must not break the race.
            return []
        if not isinstance(proof, str) or not handlers.PROOF_PATTERN.fullmatch(proof):
            return []  # Only a real proof string is real evidence (solver rules).
        evidence = f"proof read from assigned target {url}"
        chain = ("web-curriculum", f"day={day_int}" if day_int is not None else "detect")
        return [
            AnswerCandidate(answer_id=answer_id, answer=proof, solver=self.name,
                            evidence=evidence, chain=chain)
            for answer_id in context.answer_ids
        ]


WEB_SOLVERS = (CurriculumWebSolver(),)
