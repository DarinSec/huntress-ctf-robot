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
               "dex": "dex", "apk": "apk", "android": "apk", "gzip": "gzip", "gz": "gzip", "tar": "tar",
               "sqlite": "sqlite", "pcap": "pcap", "pcapng": "pcapng", "gif": "gif", "bmp": "bmp",
               "ico": "ico", "icon": "ico", "7z": "sevenzip", "sevenzip": "sevenzip", "rar": "rar",
               "iso": "iso", "iso9660": "iso", "png": "png", "jpeg": "jpeg", "jpg": "jpeg",
               "exif": "jpeg", "pdf": "pdf", "zip": "zip", "ooxml": "ooxml", "docx": "ooxml",
               "xlsx": "ooxml", "pptx": "ooxml", "office": "ooxml", "email": "email", "eml": "email",
               "mail": "email", "media": "media", "wav": "media_wav", "audio": "media", "lnk": "lnk",
               "shortcut": "lnk", "text": "text", "txt": "text", "csv": "text",
               # formats_dfir.py: formats no day has asked about yet.
               "evtx": "evtx", "eventlog": "evtx", "event_log": "evtx", "regf": "regf", "registry": "regf",
               "hive": "regf", "prefetch": "prefetch", "pf": "prefetch", "plist": "plist", "bplist": "plist",
               "webp": "webp", "tiff": "tiff", "tif": "tiff", "mkv": "ebml", "matroska": "ebml",
               "webm": "ebml", "ebml": "ebml", "avi": "avi", "vhd": "vhd", "vhdx": "vhdx", "cab": "cab",
               "xz": "xz", "bzip2": "bzip2", "bz2": "bzip2", "zstd": "zstd", "zst": "zstd", "lz4": "lz4",
               "ar": "ar", "deb": "ar", "debian": "ar", "pyc": "pyc", "python": "pyc", "rtf": "rtf",
               "crx": "crx", "ese": "ese", "edb": "ese", "srum": "ese", "ole": "ole", "ole2": "ole",
               "cfb": "ole", "doc": "ole", "xls": "ole", "ppt": "ole", "msg": "ole", "msi": "ole",
               "jumplist": "ole", "jump_list": "ole", "destlist": "ole", "automaticdestinations": "ole",
               "customdestinations": "custom_destinations", "custom_destinations": "custom_destinations",
               "mft": "mft", "ntfs": "ntfs", "usn": "usn", "usnjrnl": "usn", "usn_journal": "usn",
               "recycle": "recycle_bin_i", "recyclebin": "recycle_bin_i", "recycle_bin": "recycle_bin_i",
               "minidump": "minidump", "mdmp": "minidump", "dmp": "minidump", "crashdump": "minidump",
               "task": "scheduled_task", "scheduled_task": "scheduled_task", "schtask": "scheduled_task",
               "ewf": "ewf", "e01": "ewf", "encase": "ewf", "mbr": "mbr", "gpt": "gpt", "dmg": "dmg",
               "udif": "dmg", "ds_store": "ds_store", "dsstore": "ds_store", "x509": "x509",
               "certificate": "x509", "cert": "x509", "pem": "x509", "der": "x509"}
_NOISE = {"u16", "u32", "u64", "hex", "rva", "set", "list", "text", "name", "value", "bytes", "the", "of"}


def _words(text: str) -> set[str]:
    words = {word[:-1] if len(word) > 3 and word.endswith("s") else word
             for word in re.split(r"[^a-z0-9]+", text.lower()) if word}
    return words - _NOISE


# Units name what a field measures, not the field: "sqlite.page_size_bytes" is the header's page_size.
_UNITS = ("_bytes", "_pixels", "_seconds", "_ms", "_utc")


def _bare(name: str) -> str:
    """The property name without its format or unit suffix: "e_type_u16_hex" -> "e_type", "page_size_bytes" -> "page_size"."""
    for suffix, _ in _SUFFIXES:
        if name.endswith(suffix):
            return name[:-len(suffix)]
    for unit in _UNITS:
        if name.endswith(unit):
            return name[:-len(unit)]
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
            joined = key.replace("_", "").lower()
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
