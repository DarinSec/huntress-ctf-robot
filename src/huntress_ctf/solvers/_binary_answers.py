"""Validate public answer contracts without changing artifact-derived text."""
import json
import math
import re

from .base import fits_format


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    def constant(value):
        raise ValueError("Non-JSON numeric constant")
    def number(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("Non-finite JSON number")
        return result
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant, parse_float=number)


def valid_answer(answer, contract):
    if not isinstance(answer, str) or not fits_format(answer, contract):
        return False
    kind = contract.get("kind", "")
    syntax = str(contract.get("syntax", "")).casefold()
    if kind == "enum" and answer not in contract.get("accepted_values", ()):
        return False
    if kind == "integer" and not re.fullmatch(r"-?[0-9]+", answer):
        return False
    if kind == "integer" and "unsigned" in syntax and answer.startswith("-"):
        return False
    if kind == "json":
        try:
            value = strict_json(answer)
            if "array" in syntax and not isinstance(value, list):
                return False
            if "object" in syntax and "array" not in syntax and not isinstance(value, dict):
                return False
            if "compact" in syntax and answer != json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False):
                return False
        except (ValueError, TypeError, RecursionError):
            return False
    if "hexadecimal" in syntax or "hex digits" in syntax:
        lower = "lowercase" in syntax
        digits = "[0-9a-f]" if lower else "[0-9A-F]" if "uppercase" in syntax else "[0-9a-fA-F]"
        prefixed = "0x prefix" in syntax or "0x plus" in syntax
        width = re.search(r"exactly (\d+|two|four|eight|sixteen) (?:lowercase |uppercase )?hex(?:adecimal)? (?:characters|digits)", syntax)
        width_value = {"two": "2", "four": "4", "eight": "8", "sixteen": "16"}.get(width[1], width[1]) if width else None
        if width_value and (len(width_value) > 4 or not 0 < int(width_value) <= 4096):
            return False
        count = "{" + width_value + "}" if width else "+"
        if (prefixed or width) and not re.fullmatch(("0x" if prefixed else "") + digits + count, answer):
            return False
    return True
