"""Mach-O, universal (fat) and ar static-library headers: CPU types per slice, stdlib only.

Used by triage and MachoFieldSolver. Bytes are parsed, never executed. A slice's own
header is the truth; what a fat table claims is kept beside it so mismatches show.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import re
import struct

MAX_DEPTH = 4
MAX_SLICES = 512
# Java class files share 0xcafebabe; their major version (>= 45) lands where nfat_arch is.
MAX_FAT_ARCHS = 30
CPU_NAMES = {
    7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64", 0x0200000C: "arm64_32",
    18: "ppc", 0x01000012: "ppc64",
}
FILE_TYPES = {
    1: "object", 2: "execute", 3: "fvmlib", 4: "core", 5: "preload", 6: "dylib",
    7: "dylinker", 8: "bundle", 9: "dylib_stub", 10: "dsym", 11: "kext_bundle",
}
_THIN = {
    b"\xfe\xed\xfa\xce": (">", "32-bit"), b"\xce\xfa\xed\xfe": ("<", "32-bit"),
    b"\xfe\xed\xfa\xcf": (">", "64-bit"), b"\xcf\xfa\xed\xfe": ("<", "64-bit"),
}
_HEADER_BYTES = 28  # magic through flags; 64-bit headers add a reserved word.
_FAT = {b"\xca\xfe\xba\xbe": (">IIIII", 20), b"\xca\xfe\xba\xbf": (">IIQQII", 32)}
_AR = b"!<arch>\n"
_AR_SYMBOLS = re.compile(r"^(?:/|/SYM64/|__\.SYMDEF.*)$")


@dataclass(frozen=True)
class Slice:
    """One Mach-O image. `cputype` is None when its bytes are missing or not Mach-O."""

    path: str
    cputype: int | None
    cpusubtype: int | None = None
    filetype: int | None = None
    claimed_cputype: int | None = None
    claimed_cpusubtype: int | None = None
    problem: str = ""

    @property
    def valid(self) -> bool:
        return self.cputype is not None and not self.problem


def _join(path: str, part: str) -> str:
    return f"{path}/{part}" if path else part


def is_fat(data: bytes) -> bool:
    if data[:4] not in _FAT or len(data) < 8:
        return False
    count = struct.unpack(">I", data[4:8])[0]
    return 0 < count <= MAX_FAT_ARCHS and 8 + count * _FAT[data[:4]][1] <= len(data)


def slices(data: bytes, path: str = "", depth: int = 0) -> list[Slice]:
    """Every Mach-O image in thin, fat, and ar data, in file order; [] for anything else."""
    if depth > MAX_DEPTH:
        return []
    if data[:4] in _THIN:
        order = _THIN[data[:4]][0]
        if len(data) < _HEADER_BYTES:
            return [Slice(path, None, problem="truncated Mach-O header")]
        cputype, cpusubtype, filetype = struct.unpack(order + "III", data[4:16])
        return [Slice(path, cputype, cpusubtype, filetype)]
    if is_fat(data):
        layout, entry = _FAT[data[:4]]
        found: list[Slice] = []
        for index in range(struct.unpack(">I", data[4:8])[0]):
            start = 8 + index * entry
            cputype, cpusubtype, offset, size = struct.unpack(layout, data[start:start + entry])[:4]
            where = _join(path, f"fat[{index}]")
            claimed = {"claimed_cputype": cputype, "claimed_cpusubtype": cpusubtype}
            if not size or offset + size > len(data):
                found.append(Slice(where, None, problem="slice extends past the end of the file", **claimed))
                continue
            inner = slices(data[offset:offset + size], where, depth + 1)
            if not inner:
                found.append(Slice(where, None, problem="slice is not Mach-O", **claimed))
            found.extend(replace(item, **claimed) for item in inner)
        return found[:MAX_SLICES]
    if data.startswith(_AR):
        return _archive(data, path, depth)
    return []


def _archive(data: bytes, path: str, depth: int) -> list[Slice]:
    """ar members (BSD `#1/<len>` and GNU `//` long names); symbol tables are skipped."""
    found: list[Slice] = []
    long_names = b""
    position = len(_AR)
    while position + 60 <= len(data) and len(found) < MAX_SLICES:
        header = data[position:position + 60]
        if header[58:60] != b"`\n":
            break
        try:
            size = int(header[48:58].decode("ascii").strip() or "0")
        except ValueError:
            break
        raw = header[:16].decode("latin-1").rstrip(" ")
        body = data[position + 60:position + 60 + size]
        position += 60 + size + (size & 1)
        if raw == "//":
            long_names = body
            continue
        if raw.startswith("#1/") and raw[3:].isdigit():
            length = int(raw[3:])
            name, body = body[:length].rstrip(b"\x00").decode("utf-8", "replace"), body[length:]
        elif raw[:1] == "/" and raw[1:].isdigit():
            start = int(raw[1:])
            name = long_names[start:].split(b"\n", 1)[0].decode("utf-8", "replace").rstrip("/")
        else:
            name = raw if _AR_SYMBOLS.match(raw) else raw.rstrip("/")
        if _AR_SYMBOLS.match(name):
            continue
        found.extend(slices(body, _join(path, name or "member"), depth + 1))
    return found[:MAX_SLICES]


def hex32(value: int) -> str:
    return f"0x{value:08x}"


def cpu_name(value: int) -> str:
    return CPU_NAMES.get(value, "unknown")


def cpu_type_set(found: list[Slice]) -> list[str]:
    # Unique and ascending; zero-padded hex sorts the same as the numbers.
    return [hex32(value) for value in sorted({item.cputype for item in found if item.valid})]


FIELDS = {"cpu_type_set": cpu_type_set}


def field(name: str, found: list[Slice]) -> str | None:
    """Compact JSON for a `macho.<name>` question, or None when the field or slices are missing."""
    compute = FIELDS.get(name)
    if compute is None or not any(item.valid for item in found):
        return None
    return json.dumps(compute(found), separators=(",", ":"))


def describe(item: Slice) -> str:
    parts = [item.path or "(file)"]
    if item.cputype is not None:
        parts.append(
            f"cputype {hex32(item.cputype)} ({cpu_name(item.cputype)}), "
            f"cpusubtype {hex32(item.cpusubtype or 0)}, "
            f"filetype {FILE_TYPES.get(item.filetype or 0, item.filetype)}"
        )
    if item.claimed_cputype is not None and item.claimed_cputype != item.cputype:
        parts.append(f"fat table claims {hex32(item.claimed_cputype)} ({cpu_name(item.claimed_cputype)})")
    if item.problem:
        parts.append(item.problem)
    return "; ".join(parts)


def kind(data: bytes) -> str | None:
    """artifact_kind label for Mach-O, fat, and ar data; None for anything else."""
    if data[:4] in _THIN:
        label = f"Mach-O {_THIN[data[:4]][1]}"
    elif is_fat(data):
        label = "Mach-O universal (fat) binary"
    elif data.startswith(_AR):
        label = "ar archive (static library)"
    else:
        return None
    cpus = ", ".join(dict.fromkeys(cpu_name(item.cputype) for item in slices(data) if item.valid))
    return f"{label}{f' ({cpus})' if cpus else ''}; lane hint: Metadata Forensics or Binary"
