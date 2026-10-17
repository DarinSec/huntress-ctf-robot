"""Bounded transport for the documented Game Master operations over one kept-alive connection."""

from __future__ import annotations

from http.client import HTTPConnection, HTTPException, HTTPMessage, HTTPSConnection
import json
import math
import os
import ssl
import time
from typing import Any
from urllib.parse import urlencode, urlsplit
from urllib.request import getproxies, proxy_bypass

from . import __version__

DEFAULT_BASE_URL = "https://2026.huntress.ctf.games"
PROXY_BASE_URL = "http://10.0.0.219/huntress-ctf-proxy"
DEFAULT_TIMEOUT_SECONDS = 30
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
# Servers drop idle keep-alive connections silently. A POST is never retried, so it
# starts on a fresh connection after this much idle time instead of risking a dead one.
IDLE_RECONNECT_SECONDS = 5.0
USER_AGENT = f"huntress-ctf-robot/{__version__}"


class GameMasterError(RuntimeError):
    """An operation failed or its response cannot safely drive the next step."""


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GameMasterError("Challenge and answer IDs must be nonempty strings.")
    return value


def _error_envelope(value: Any) -> bool:
    return isinstance(value, dict) and (
        bool(value.get("error")) or value.get("result") in ("error", "ERROR", "failed")
    )


class GameMasterClient:
    def __init__(
        self, base_url: str | None = None, token: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        configured = base_url if base_url is not None else os.environ.get(
            "HUNTRESS_GM_URL", DEFAULT_BASE_URL
        )
        try:
            parsed = urlsplit(configured)
            valid = (
                parsed.scheme in {"http", "https"} and parsed.hostname
                and parsed.username is None and parsed.password is None
                and not parsed.query and not parsed.fragment
                and not any(char.isspace() or ord(char) < 32 for char in configured)
            )
            _ = parsed.port
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise GameMasterError("Invalid Game Master URL: use an HTTP(S) base URL without credentials, query, or fragment.")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise GameMasterError("Timeout must be a finite positive number.")
        if not math.isfinite(timeout) or timeout <= 0:
            raise GameMasterError("Timeout must be a finite positive number.")
        self.base_url = configured.rstrip("/")
        # Homebase already provides identity; never send a local bearer to its HTTP proxy.
        self.token = token
        if token is None and self.base_url != PROXY_BASE_URL:
            self.token = os.environ.get("HUNTRESS_GM_TOKEN")
        if self.token is not None and (
            not isinstance(self.token, str)
            or any(not char.isascii() or not char.isprintable() or char.isspace() for char in self.token)
        ):
            raise GameMasterError("The Game Master token has an invalid format.")
        if self.token and parsed.scheme != "https":
            raise GameMasterError("A bearer token may only be sent over HTTPS.")
        self.timeout = timeout
        self._scheme = parsed.scheme
        self._host = parsed.hostname
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self._path = urlsplit(self.base_url).path or "/"
        self._connection: HTTPConnection | None = None
        self._absolute = False
        self._served = 0
        self._last_used = 0.0

    # Connection lifecycle -------------------------------------------------

    def _new_connection(self) -> tuple[HTTPConnection, bool]:
        """Return a connection and whether request targets must be absolute (HTTP proxy)."""
        proxy = None if proxy_bypass(self._host) else getproxies().get(self._scheme)
        if proxy:
            settings = urlsplit(proxy if "://" in proxy else f"http://{proxy}")
            if settings.scheme != "http" or not settings.hostname or settings.username:
                raise GameMasterError("Only an unauthenticated http:// proxy is supported.")
            proxy_port = settings.port or 80
            if self._scheme == "https":
                connection = HTTPSConnection(
                    settings.hostname, proxy_port, timeout=self.timeout,
                    context=ssl.create_default_context(),
                )
                connection.set_tunnel(self._host, self._port)
                return connection, False
            return HTTPConnection(settings.hostname, proxy_port, timeout=self.timeout), True
        if self._scheme == "https":
            return HTTPSConnection(
                self._host, self._port, timeout=self.timeout,
                context=ssl.create_default_context(),
            ), False
        return HTTPConnection(self._host, self._port, timeout=self.timeout), False

    def _open(self) -> HTTPConnection:
        if self._connection is None:
            self._connection, self._absolute = self._new_connection()
            self._served = 0
        return self._connection

    def _drop(self) -> None:
        connection, self._connection, self._served = self._connection, None, 0
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass

    def warm(self) -> None:
        """Finish DNS, TCP, and TLS now so later requests cost one round trip."""
        self._require_credentials()
        connection = self._open()
        if connection.sock is None:
            try:
                connection.connect()
            except (OSError, HTTPException):
                self._drop()
                raise GameMasterError("Game Master transport failed while connecting.") from None
            self._last_used = time.monotonic()

    def close(self) -> None:
        self._drop()

    def __enter__(self) -> GameMasterClient:
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    # Requests ---------------------------------------------------------------

    def _require_credentials(self) -> None:
        if self.base_url == DEFAULT_BASE_URL and not self.token:
            raise GameMasterError("Set HUNTRESS_GM_TOKEN privately before using the direct API.")

    def _send(
        self, method: str, target: str, body: bytes | None,
        headers: dict[str, str], limit: int,
    ) -> tuple[int, HTTPMessage, bytes]:
        """One exchange on the kept-alive connection; reads at most limit + 1 bytes."""
        if (
            body is not None and self._connection is not None
            and time.monotonic() - self._last_used > IDLE_RECONNECT_SECONDS
        ):
            self._drop()
        connection = self._open()
        if self._absolute:
            target = f"{self._scheme}://{self._host}:{self._port}{target}"
        connection.request(method, target, body=body, headers=headers)
        response = connection.getresponse()
        content = response.read(limit + 1)
        if not response.isclosed():
            # Unread bytes would corrupt the next exchange on this connection.
            self._drop()
        elif connection.sock is None:
            self._served = 0
        else:
            self._served += 1
        self._last_used = time.monotonic()
        return response.status, response.headers, content

    def request(
        self, operation: str | None = None, *,
        params: dict[str, str | int] | None = None,
        payload: dict[str, Any] | None = None, expect_json: bool = True,
    ) -> Any:
        self._require_credentials()
        query = dict(params or {})
        if operation:
            query["op"] = operation
        target = f"{self._path}?{urlencode(query)}" if query else self._path
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {
            "Accept": "application/json" if expect_json else "*/*",
            "User-Agent": USER_AGENT,
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        method = "GET" if body is None else "POST"
        limit = MAX_JSON_BYTES if expect_json else MAX_ARTIFACT_BYTES
        retried = False
        while True:
            reused = self._served > 0
            try:
                status, response_headers, content = self._send(method, target, body, headers, limit)
                break
            except (OSError, HTTPException):
                self._drop()
                # Only an idempotent GET on a possibly stale kept-alive connection is
                # repeated, once. An uncertain POST must never be retried automatically.
                if method == "GET" and reused and not retried:
                    retried = True
                    continue
                raise GameMasterError(
                    "Game Master transport failed. A POST may have reached the server; "
                    "check status before repeating it."
                ) from None
        if 300 <= status < 400:
            raise GameMasterError(
                "Game Master redirected the request. No credential or POST was forwarded."
            )
        if not 200 <= status < 300:
            raise GameMasterError(f"Game Master returned HTTP {status}.")
        content_type = response_headers.get_content_type()
        attachment = response_headers.get_content_disposition() == "attachment"
        if len(content) > limit:
            raise GameMasterError(f"Game Master response exceeds the {limit}-byte limit.")
        if not content:
            raise GameMasterError("Game Master returned an empty response.")
        if not expect_json:
            if content_type == "text/html" and not attachment:
                raise GameMasterError("Artifact endpoint returned an HTML page, not an attachment.")
            if content_type == "application/json" and not attachment:
                try:
                    value = json.loads(content)
                except (ValueError, UnicodeDecodeError, RecursionError):
                    value = None
                if _error_envelope(value):
                    raise GameMasterError("Artifact endpoint returned an API error.")
            return content
        try:
            value = json.loads(content)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise GameMasterError("Game Master did not return valid JSON.") from None
        if not isinstance(value, (dict, list)):
            raise GameMasterError("Game Master returned an unexpected JSON value.")
        if _error_envelope(value):
            raise GameMasterError("Game Master reported an operation error.")
        return value

    def list_challenges(self, day: int | None = None, lane: str | None = None) -> Any:
        params: dict[str, str | int] = {}
        if day is not None:
            if type(day) is not int or not 1 <= day <= 31:
                raise GameMasterError("Day must be an integer from 1 to 31.")
            params["day"] = day
        if lane:
            params["lane"] = lane
        return self.request("list", params=params)

    def start(self, challenge_id: str, timed: bool = False) -> Any:
        payload: dict[str, Any] = {"challenge": _identifier(challenge_id)}
        if timed:
            payload.update(op="start", run_for_time=True)
        return self.request(payload=payload)

    def retry(self, challenge_id: str, timed: bool = False) -> Any:
        payload: dict[str, Any] = {"op": "retry", "challenge": _identifier(challenge_id)}
        if timed:
            payload["run_for_time"] = True
        return self.request(payload=payload)

    def status(self, challenge_id: str) -> Any:
        return self.request("status", params={"challenge": _identifier(challenge_id)})

    def artifact(self, challenge_id: str) -> bytes:
        return self.request(
            "artifact", params={"challenge": _identifier(challenge_id)}, expect_json=False
        )

    def submit(self, challenge_id: str, answer_id: str, answer: str) -> Any:
        return self.submit_many(challenge_id, {answer_id: answer})

    def submit_many(self, challenge_id: str, answers: dict[str, str]) -> Any:
        """Send every answer in one POST; the documented `answers` field is a map."""
        if not isinstance(answers, dict) or not answers:
            raise GameMasterError("At least one answer is required.")
        if any(not isinstance(answer, str) for answer in answers.values()):
            raise GameMasterError("An answer must be a string.")
        return self.request(payload={
            "challenge": _identifier(challenge_id),
            "answers": {_identifier(key): value for key, value in answers.items()},
        })

    def api_schema(self) -> Any:
        return self.request("openapi")
