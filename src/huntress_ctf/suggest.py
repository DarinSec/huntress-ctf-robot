"""Candidate fields for a `Determine <property>` that has no parser yet (for the AI, not the clock).

Property names so far carry their format in the suffix ("elf.e_machine_u16_hex",
"pe.address_of_entry_point_rva_hex", "macho.cpu_type_set"), so the field whose name shares
the most words with the property, formatted by the suffix convention the service accepted
before, is a strong first guess. It is printed in triage.md, never submitted: the AI
checks it, then adds the one-line parser to PROPERTIES in solvers/metadata.py.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .formats import describe

# Conventions accepted live (CLAUDE.md, Metadata lane): u16 "0x%04x", u32/RVA "0x%08x".
_SUFFIXES = (
    ("_u16_hex", lambda value: f"0x{value:04x}" if isinstance(value, int) else None),
    ("_u32_hex", lambda value: f"0x{value:08x}" if isinstance(value, int) else None),
    ("_rva_hex", lambda value: f"0x{value:08x}" if isinstance(value, int) else None),
    ("_u64_hex", lambda value: f"0x{value:016x}" if isinstance(value, int) else None),
    ("_hex", lambda value: f"0x{value:x}" if isinstance(value, int) else None),
    ("_set", lambda value: json.dumps(sorted(set(value)), separators=(",", ":")) if isinstance(value, list) else None),
    ("_list", lambda value: json.dumps(value, separators=(",", ":")) if isinstance(value, list) else None),
    ("_count", lambda value: str(len(value)) if isinstance(value, list) else str(value)),
    ("_present", lambda value: "true" if value not in (None, "", [], 0) else "false"),
    ("_guid", lambda value: str(value).lower()),
)
_NAMESPACES = {"macho": "macho", "elf": "elf", "pe": "pe", "dotnet": "pe", "wasm": "wasm",
               "webassembly": "wasm", "java": "java_class", "class": "java_class", "jar": "java_class",
               "dex": "dex", "android": "dex"}
_NOISE = {"u16", "u32", "u64", "hex", "rva", "set", "list", "text", "name", "value", "bytes", "the", "of"}


def _words(text: str) -> set[str]:
    words = {word[:-1] if len(word) > 3 and word.endswith("s") else word
             for word in re.split(r"[^a-z0-9]+", text.lower()) if word}
    return words - _NOISE


def _bare(name: str) -> str:
    """The property name without its format suffix: "subsystem_name" stays, "e_type_u16_hex" -> "e_type"."""
    for suffix, _ in _SUFFIXES:
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return name


def formatted(prop: str, value: Any) -> str:
    for suffix, render in _SUFFIXES:
        if prop.endswith(suffix):
            try:
                result = render(value)
            except (TypeError, ValueError):
                result = None
            if result is not None:
                return result
    if isinstance(value, list):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def ranked(prop: str, data: bytes) -> list[tuple[int, str, str, Any]]:
    """(score, format label, field, value), best first, for the fields matching `prop`."""
    namespace, _, name = prop.partition(".")
    wanted = _words(name)
    label_kind = _NAMESPACES.get(namespace)
    scored = []
    for label, fields in describe(data):
        if label_kind and not label.startswith(label_kind):
            continue
        for key, value in fields.items():
            joined = key.replace("_", "")
            score = (len(wanted & _words(key)) + (2 if key in (name, _bare(name)) else 0)
                     # "cputype" is one word in the header but "cpu_type" in a property.
                     + (1 if len(joined) > 3 and joined in _bare(name).replace("_", "") else 0))
            if score:
                scored.append((score, len(key), label, key, value))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [(score, label, key, value) for score, _, label, key, value in scored]


def confident(prop: str, data: bytes) -> tuple[str, str, str] | None:
    """(format label, field, formatted answer) when one field clearly is the property.

    Clear means a score of 3 or more (the field is named like the property, or shares
    several of its words), or 2 with no other field reaching 2.
    """
    found = ranked(prop, data)
    if not found:
        return None
    score, label, key, value = found[0]
    rivals = [item for item in found[1:] if item[0] >= 2 and item[2] != key]
    if score >= 3 or (score == 2 and not rivals):
        return label.split()[0], key, formatted(prop, value)
    return None


def suggest(prop: str, data: bytes, limit: int = 4) -> list[str]:
    """Lines such as `macho: uuid = '385DB3EB-...' -> candidate answer '385DB3EB-...'`."""
    lines = []
    for score, label, key, value in ranked(prop, data)[:limit]:
        shown = value[:8] if isinstance(value, list) else value
        lines.append(f"{label}: {key} = {shown!r} -> candidate answer {formatted(prop, value)!r}")
    return lines
