"""Adapter: run the Web Exploitation curriculum handlers as a scoped `TargetSolver`.

`handlers.py` (Parsa's, ported from verified live runs across curriculum days 1-10) is a
set of standalone `solve_*(target_url) -> proof` functions dispatched by `detect_and_solve`
/ `CURRICULUM_HANDLERS`. It is a different shape from this package's `TargetSolver`
protocol, and it reaches the network through its own module-level `_request`, which opens a
fresh urllib connection per call with no host allowlist. This module is the glue between the
two shapes, and it does two things to that ported code without changing a line of it:

* **Scope.** Every request is confined to the hosts the Game Master listed for this attempt
  (`ScopedHttp`): a URL off the allowlist raises `HostNotAllowed`, and a redirect off it is
  not followed (the 30x is handed back, which several handlers read `Set-Cookie` from).
* **Speed.** One keep-alive connection per host is reused for the whole handler run, so a
  multi-step solve (robots.txt -> index -> .bak) pays one TCP/TLS handshake instead of one
  per step -- the dominant on-clock cost of a network-bound web route.

`CurriculumWebSolver.solve` passes `context.url` and `context.curriculum_day` to
`detect_and_solve` and wraps the proof it recovers as an `AnswerCandidate` -- but only a
real `proof_...` string, and only when one was actually read. A blocked host, a handler
error, or no proof yields no candidate, so `_solve_targets` leaves the attempt UNRESOLVED
rather than submit a guess.
"""

from __future__ import annotations

import contextlib
import http.client
import threading
from typing import Any, Iterator
from urllib.parse import urljoin, urlsplit

from ..base import AnswerCandidate
from . import HostNotAllowed, ScopedHttp
from . import sessions

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
_REDIRECT_CODES = {301, 302, 303, 307, 308}
_MAX_REDIRECTS = 5


class _ScopedTransport:
    """A drop-in for `handlers._request`, confined to an allowlist and reusing one
    keep-alive connection per host for the life of a handler run.

    Keeps the ported function's contract exactly -- `(status, body_text, lower_headers)`,
    its header assembly, urllib's redirect semantics -- and caps the body, so the handler's
    own logic is unchanged while its reach is gated and its handshakes are amortised.
    """

    def __init__(self, http: ScopedHttp) -> None:
        self._http = http
        self._conns: dict[tuple[str, str, int], http.client.HTTPConnection] = {}
        # Cookie values the target set during the run, so the adapter can read a proof the
        # server stashed in a (signed, not encrypted) session cookie -- no extra request.
        self.seen_cookies: list[str] = []

    # -- connection pool ---------------------------------------------------------------
    def _connection(self, scheme: str, host: str, port: int,
                    timeout: float) -> tuple[http.client.HTTPConnection, bool, tuple[str, str, int]]:
        key = (scheme, host, port)
        conn = self._conns.get(key)
        reused = conn is not None
        if conn is None:
            factory = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
            conn = factory(host, port, timeout=timeout)
            self._conns[key] = conn
        else:
            conn.timeout = timeout
        return conn, reused, key

    def _drop(self, key: tuple[str, str, int]) -> None:
        conn = self._conns.pop(key, None)
        if conn is not None:
            try:
                conn.close()
            except Exception:  # pragma: no cover - a close error is nothing to act on
                pass

    def close(self) -> None:
        for key in list(self._conns):
            self._drop(key)

    # -- the handlers._request drop-in -------------------------------------------------
    def request(self, url: str, method: str = "GET", data: bytes | None = None,
                headers: dict[str, str] | None = None, cookie: str | None = None,
                timeout: float | None = None) -> tuple[int, str, dict[str, str]]:
        if timeout is None:
            timeout = getattr(handlers, "DEFAULT_TIMEOUT", 10.0)
        return self._fetch(url, method.upper(), data, headers, cookie, timeout, _MAX_REDIRECTS)

    def _fetch(self, url: str, method: str, data: bytes | None,
               headers: dict[str, str] | None, cookie: str | None, timeout: float,
               redirects_left: int) -> tuple[int, str, dict[str, str]]:
        if not self._http.allows(url):
            raise HostNotAllowed(url)
        parts = urlsplit(url)
        scheme = parts.scheme
        host = parts.hostname or ""
        port = parts.port or (443 if scheme == "https" else 80)
        target = parts.path or "/"
        if parts.query:
            target = f"{target}?{parts.query}"
        req_headers = {"User-Agent": _DEFAULT_UA, "Connection": "keep-alive"}
        if cookie:
            req_headers["Cookie"] = cookie
        if headers:
            req_headers.update(headers)
        status, body, resp_headers = self._send(scheme, host, port, method, target, data, req_headers, timeout)
        if status in _REDIRECT_CODES and redirects_left > 0:
            location = resp_headers.get("location")
            if location:
                new_url = urljoin(url, location)
                if self._http.allows(new_url):
                    if status in (301, 302, 303) and method not in ("GET", "HEAD"):
                        method, data = "GET", None  # urllib's redirect semantics
                    return self._fetch(new_url, method, data, headers, cookie, timeout, redirects_left - 1)
                # Off scope: stop and hand the 30x back (several handlers read Set-Cookie off it).
        return status, body, resp_headers

    def _send(self, scheme: str, host: str, port: int, method: str, target: str,
              data: bytes | None, req_headers: dict[str, str],
              timeout: float) -> tuple[int, str, dict[str, str]]:
        last_exc: Exception | None = None
        for _ in range(2):  # one retry, but only when a pooled socket turns out stale
            conn, reused, key = self._connection(scheme, host, port, timeout)
            try:
                conn.request(method, target, body=data, headers=req_headers)
                response = conn.getresponse()
                raw = response.read(self._http.max_bytes + 1)
            except (http.client.HTTPException, OSError) as exc:
                last_exc = exc
                self._drop(key)
                if reused:
                    continue  # the server likely closed an idle keep-alive socket; retry fresh
                raise
            oversize = len(raw) > self._http.max_bytes
            body = raw[: self._http.max_bytes].decode("utf-8", "replace")
            resp_headers = {name.lower(): value for name, value in response.getheaders()}
            for hname, hvalue in response.getheaders():
                if hname.lower() == "set-cookie":
                    pair = hvalue.split(";", 1)[0]
                    if "=" in pair:
                        self.seen_cookies.append(pair.split("=", 1)[1])
            if oversize or response.version < 11 or resp_headers.get("connection", "").lower() == "close":
                self._drop(key)  # not safely reusable: a fresh socket next time
            return response.status, body, resp_headers
        raise last_exc  # pragma: no cover - the loop returns or raises on the fresh attempt


@contextlib.contextmanager
def _scope(http: ScopedHttp) -> Iterator["_ScopedTransport"]:
    """Confine `handlers`' network to `http`'s allowlist, over one pooled connection.

    Yields the transport so the caller can read the cookies the target set during the run.
    """
    with _PATCH_LOCK:
        transport = _ScopedTransport(http)
        original = handlers._request
        handlers._request = transport.request
        try:
            yield transport
        finally:
            handlers._request = original
            transport.close()


class CurriculumWebSolver:
    """Runs the ported curriculum handlers, scoped and keep-alive, reporting a verified proof."""

    name = "web-curriculum"

    def solve(self, context: Any) -> list[AnswerCandidate]:
        if handlers is None or not context.answer_ids:
            return []
        day = context.curriculum_day
        try:
            day_int: int | None = int(day)
        except (TypeError, ValueError):
            day_int = None
        # Each answer gets its own assigned target: a day 11-15 mastery route lists several
        # in `targets[]` and names them per question (artifact -> target id); days 1-10 list
        # one. Build an id->url map plus an ordered list, and fall back to context.url (the
        # first target) so a single-target route with no per-question mapping still solves.
        targets_map: dict[str, str] = {}
        target_list: list[str] = []
        for t in context.targets or ():
            if isinstance(t, dict):
                tid = t.get("id")
                turl = t.get("url") or t.get("target") or t.get("endpoint") or ""
                if tid and turl:
                    targets_map[tid] = turl
                if turl:
                    target_list.append(turl)
            elif isinstance(t, str) and t:
                target_list.append(t)
        if not target_list and context.url:
            target_list.append(context.url)

        questions = context.attempt.get("questions", []) if isinstance(context.attempt, dict) else []
        candidates: list[AnswerCandidate] = []

        try:
            with _scope(context.http) as transport:
                for i, answer_id in enumerate(context.answer_ids):
                    turl = None
                    for q in questions:
                        if isinstance(q, dict) and q.get("id") == answer_id:
                            art = q.get("artifact")
                            if art in targets_map:
                                turl = targets_map[art]
                            break
                    if not turl:
                        if i < len(target_list):
                            turl = target_list[i]
                        elif target_list:
                            turl = target_list[0]
                    if not turl or not context.http.allows(turl):
                        continue

                    seen_before = len(transport.seen_cookies)
                    proof: str | None = None
                    chain: tuple[str, ...] = ()
                    try:
                        result = handlers.detect_and_solve(turl, day_int)
                    except Exception:
                        # WebHandlerError, HostNotAllowed, transport errors: never guessed.
                        result = None
                    if isinstance(result, str) and handlers.PROOF_PATTERN.fullmatch(result):
                        proof = result
                        chain = ("web-curriculum", f"day={day_int}" if day_int is not None else "detect")
                    else:
                        # No handler proof: the server may have stashed it in a signed
                        # (readable) session cookie set during this target's run. Scan only
                        # the cookies this target added, so the proof is credited to it.
                        for found in sessions.proofs_in_cookies(
                            transport.seen_cookies[seen_before:], handlers.PROOF_PATTERN
                        ):
                            if handlers.PROOF_PATTERN.fullmatch(found):
                                proof, chain = found, ("web-cookie",)
                                break
                    if proof is None:
                        continue  # Only a real proof string is real evidence (solver rules).
                    evidence = f"proof read from assigned target {turl}"
                    candidates.append(
                        AnswerCandidate(answer_id=answer_id, answer=proof, solver=self.name,
                                        evidence=evidence, chain=chain)
                    )
        except Exception:
            return []
        return candidates


WEB_SOLVERS = (CurriculumWebSolver(),)
