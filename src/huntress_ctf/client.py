"""Bounded, non-retrying transport for the documented Game Master operations."""

from __future__ import annotations

from http.client import HTTPException
import json
import math
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

DEFAULT_BASE_URL = "https://2026.huntress.ctf.games"
PROXY_BASE_URL = "http://10.0.0.219/huntress-ctf-proxy"
DEFAULT_TIMEOUT_SECONDS = 30
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


class GameMasterError(RuntimeError):
    """An operation failed or its response cannot safely drive the next step."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise GameMasterError(
            "Game Master redirected the request. No credential or POST was forwarded."
        )


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
        self._opener = build_opener(_NoRedirect())

    def request(
        self, operation: str | None = None, *,
        params: dict[str, str | int] | None = None,
        payload: dict[str, Any] | None = None, expect_json: bool = True,
    ) -> Any:
        if self.base_url == DEFAULT_BASE_URL and not self.token:
            raise GameMasterError("Set HUNTRESS_GM_TOKEN privately before using the direct API.")
        query = dict(params or {})
        if operation:
            query["op"] = operation
        base = self.base_url + ("/" if not urlsplit(self.base_url).path else "")
        url = f"{base}?{urlencode(query)}" if query else base
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Accept": "application/json" if expect_json else "*/*"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = Request(url, data=body, headers=headers, method="GET" if body is None else "POST")
        limit = MAX_JSON_BYTES if expect_json else MAX_ARTIFACT_BYTES
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                content_type = response.headers.get_content_type()
                attachment = response.headers.get_content_disposition() == "attachment"
                content = response.read(limit + 1)
        except HTTPError as exc:
            code = exc.code
            exc.close()
            raise GameMasterError(f"Game Master returned HTTP {code}.") from None
        except (URLError, OSError, HTTPException):
            # An uncertain POST must never be retried automatically.
            raise GameMasterError(
                "Game Master transport failed. A POST may have reached the server; "
                "check status before repeating it."
            ) from None
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
        if not isinstance(answer, str):
            raise GameMasterError("An answer must be a string.")
        return self.request(payload={
            "challenge": _identifier(challenge_id),
            "answers": {_identifier(answer_id): answer},
        })

    def api_schema(self) -> Any:
        return self.request("openapi")

