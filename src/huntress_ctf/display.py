"""Consistent redaction for API output, including the manual CLI commands."""

from __future__ import annotations

import json
from typing import Any

_PRIVATE_FIELDS = {
    "token", "access_token", "refresh_token", "api_key", "authorization",
    "expected_answer", "expected_answers", "expected_flag", "private_flag", "solution",
}


def safe_value(value: Any, secrets: tuple[str, ...] = ()) -> Any:
    if isinstance(value, dict):
        return {
            safe_value(key, secrets): "[redacted]" if str(key).casefold() in _PRIVATE_FIELDS
            else safe_value(item, secrets)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [safe_value(item, secrets) for item in value]
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[redacted]")
    return value


def print_result(value: Any, secrets: tuple[str, ...] = ()) -> None:
    # JSON escapes terminal control characters from remote content.
    print(json.dumps(safe_value(value, secrets), indent=2, ensure_ascii=True, sort_keys=True))
