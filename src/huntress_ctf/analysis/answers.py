"""Format and check answers against the Game Master's public answer_format contract.

The grader matches exactly, so most wrong batches come from formatting, not analysis:
'0x' + lowercase hex, compact JSON, 'true'/'false', base-10 integers, bare text.
`check()` catches those before a submit spends an attempt.
"""
import json
import re

HEX0X_RE = re.compile(r"^0x[0-9a-f]+$")
ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
DIGEST_LEN = {"md5": 32, "sha1": 40, "sha256": 64}


def hex0x(value):
    """0x-prefixed lowercase hex from an int or a hex string ('0X1FA4', '1fa4', 8100)."""
    if isinstance(value, str):
        if re.fullmatch(r"0x[0-9a-f]+", value):
            return value  # already canonical: keep deliberate zero padding (e.g. CRC32 0x03663005)
        value = int(value, 16) if not value.lower().startswith("0x") else int(value[2:], 16)
    return f"0x{value:x}"


def compact_json(value):
    """Compact JSON (no spaces) for list/dict answers; JSON text is re-serialized compactly."""
    if isinstance(value, str):
        value = json.loads(value)
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def boolean(value):
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "false"):
            return v
        raise ValueError(f"not a boolean: {value!r}")
    return "true" if value else "false"


def integer(value):
    if isinstance(value, str):
        value = int(value.strip(), 0)
    return str(int(value))


def format_answer(value, answer_format):
    """Normalize a Python value to the string the question's answer_format expects."""
    kind = (answer_format or {}).get("kind", "exact_text")
    syntax = (answer_format or {}).get("syntax", "").lower()
    if value is None:
        return "none"
    if kind == "json":
        return compact_json(value)
    if kind == "integer":
        return integer(value)
    if kind == "enum":
        accepted = answer_format.get("accepted_values") or []
        v = boolean(value) if set(accepted) == {"true", "false"} else str(value).strip()
        return v
    if "lowercase hexadecimal with a 0x prefix" in syntax:
        return hex0x(value)
    if isinstance(value, bool):
        return boolean(value)
    return str(value).strip()


def build(questions, values, prefix=""):
    """{answer_id: formatted} from {field: value}. `field` is the id without `prefix`
    (e.g. prefix 'set1.' for a Mastery set). Fields not in `values` are left out."""
    fmt = {q["id"]: q.get("answer_format") or {} for q in questions}
    out = {}
    for field, value in values.items():
        aid = prefix + field
        if aid not in fmt:
            raise KeyError(f"unknown answer id {aid!r}")
        out[aid] = format_answer(value, fmt[aid])
    return out


def check(answers, questions):
    """List of human-readable problems with {answer_id: string}; empty means it looks well-formed.
    Checks shape only; it cannot know whether a value is correct."""
    qs = {q["id"]: q for q in questions}
    problems = []
    for aid, v in answers.items():
        q = qs.get(aid)
        if q is None:
            problems.append(f"{aid}: not an answer id of this attempt")
            continue
        if not isinstance(v, str):
            problems.append(f"{aid}: value must be a string, got {type(v).__name__}")
            continue
        f = q.get("answer_format") or {}
        kind, syntax = f.get("kind"), f.get("syntax", "").lower()
        if v != v.strip() and q.get("normalization") == "exact":
            problems.append(f"{aid}: leading/trailing whitespace with exact normalization")
        if kind == "enum" and v not in (f.get("accepted_values") or []):
            problems.append(f"{aid}: {v!r} not in {f.get('accepted_values')}")
        elif kind == "integer" and not re.fullmatch(r"-?\d+", v):
            problems.append(f"{aid}: {v!r} is not a base-10 integer")
        elif kind == "json":
            try:
                parsed = json.loads(v)
            except ValueError as e:
                problems.append(f"{aid}: invalid JSON ({e})")
            else:
                if "compact" in syntax and v != compact_json(parsed):
                    problems.append(f"{aid}: JSON is not compact; use {compact_json(parsed)[:60]}")
        elif kind == "mitre_attack_id" and v != "none" and not ATTACK_RE.match(v):
            problems.append(f"{aid}: {v!r} is not T#### or T####.###")
        if "lowercase hexadecimal with a 0x prefix" in syntax and not HEX0X_RE.match(v):
            problems.append(f"{aid}: {v!r} is not 0x + lowercase hex")
        for algo, n in DIGEST_LEN.items():
            if algo in aid and kind in ("exact_text", "pattern") and v != "none" \
                    and not re.fullmatch(rf"[0-9a-fA-F]{{{n}}}", v):
                problems.append(f"{aid}: expected a {n}-hex-digit {algo} digest")
    return problems


def with_prefix(answers, prefix):
    """Re-key answers for a Mastery set, e.g. with_prefix(a, 'set2.')."""
    return {prefix + k.split(".", 1)[-1] if "." in k else prefix + k: v for k, v in answers.items()}


def load(path):
    with open(path) as f:
        return json.load(f)


def save(answers, path):
    with open(path, "w") as f:
        json.dump(answers, f, indent=1, ensure_ascii=False)
        f.write("\n")
