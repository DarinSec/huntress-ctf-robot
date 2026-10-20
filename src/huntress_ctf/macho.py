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
    found: list[Slice] = []
    for name, body in ar_members(data):
        if len(found) >= MAX_SLICES:
            break
        found.extend(slices(body, _join(path, name or "member"), depth + 1))
    return found[:MAX_SLICES]


def ar_members(data: bytes):
    """(name, bytes) of ar members (BSD `#1/<len>` and GNU `//` names); symbol tables skipped."""
    long_names = b""
    position = len(_AR)
    while position + 60 <= len(data):
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
        if not _AR_SYMBOLS.match(name):
            yield name, body


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


# --- Every header and load-command field, for triage and one-line parsers -------------

LOAD_COMMANDS = {
    0x1: "LC_SEGMENT", 0x2: "LC_SYMTAB", 0x4: "LC_THREAD", 0x5: "LC_UNIXTHREAD",
    0xB: "LC_DYSYMTAB", 0xC: "LC_LOAD_DYLIB", 0xD: "LC_ID_DYLIB", 0xE: "LC_LOAD_DYLINKER",
    0xF: "LC_ID_DYLINKER", 0x19: "LC_SEGMENT_64", 0x1B: "LC_UUID", 0x8000001C: "LC_RPATH",
    0x1D: "LC_CODE_SIGNATURE", 0x1E: "LC_SEGMENT_SPLIT_INFO", 0x8000001F: "LC_REEXPORT_DYLIB",
    0x21: "LC_ENCRYPTION_INFO", 0x22: "LC_DYLD_INFO", 0x80000022: "LC_DYLD_INFO_ONLY",
    0x80000018: "LC_LOAD_WEAK_DYLIB", 0x80000023: "LC_LOAD_UPWARD_DYLIB",
    0x24: "LC_VERSION_MIN_MACOSX", 0x25: "LC_VERSION_MIN_IPHONEOS", 0x26: "LC_FUNCTION_STARTS",
    0x27: "LC_DYLD_ENVIRONMENT", 0x80000028: "LC_MAIN", 0x29: "LC_DATA_IN_CODE",
    0x2A: "LC_SOURCE_VERSION", 0x2B: "LC_DYLIB_CODE_SIGN_DRS", 0x2C: "LC_ENCRYPTION_INFO_64",
    0x2D: "LC_LINKER_OPTION", 0x2E: "LC_LINKER_OPTIMIZATION_HINT", 0x2F: "LC_VERSION_MIN_TVOS",
    0x30: "LC_VERSION_MIN_WATCHOS", 0x31: "LC_NOTE", 0x32: "LC_BUILD_VERSION",
    0x80000033: "LC_DYLD_EXPORTS_TRIE", 0x80000034: "LC_DYLD_CHAINED_FIXUPS",
    0x80000035: "LC_FILESET_ENTRY",
}
PLATFORMS = {
    1: "macos", 2: "ios", 3: "tvos", 4: "watchos", 5: "bridgeos", 6: "maccatalyst",
    7: "iossimulator", 8: "tvossimulator", 9: "watchossimulator", 10: "driverkit",
    11: "visionos", 12: "visionossimulator",
}
HEADER_FLAGS = {
    0x1: "MH_NOUNDEFS", 0x2: "MH_INCRLINK", 0x4: "MH_DYLDLINK", 0x8: "MH_BINDATLOAD",
    0x10: "MH_PREBOUND", 0x20: "MH_SPLIT_SEGS", 0x80: "MH_TWOLEVEL", 0x100: "MH_FORCE_FLAT",
    0x200: "MH_NOMULTIDEFS", 0x2000: "MH_SUBSECTIONS_VIA_SYMBOLS", 0x8000: "MH_WEAK_DEFINES",
    0x10000: "MH_BINDS_TO_WEAK", 0x20000: "MH_ALLOW_STACK_EXECUTION", 0x200000: "MH_PIE",
    0x800000: "MH_HAS_TLV_DESCRIPTORS", 0x1000000: "MH_NO_HEAP_EXECUTION",
    0x2000000: "MH_APP_EXTENSION_SAFE", 0x80000000: "MH_DYLIB_IN_CACHE",
}
_DYLIBS = {0xC, 0x80000018, 0x8000001F, 0x80000023}


def images(data: bytes, path: str = "", depth: int = 0):
    """(path, bytes) of every thin Mach-O image in thin, fat and ar data, in file order."""
    if depth > MAX_DEPTH:
        return
    if data[:4] in _THIN and len(data) >= _HEADER_BYTES:
        yield path, data
    elif is_fat(data):
        layout, entry = _FAT[data[:4]]
        for index in range(struct.unpack(">I", data[4:8])[0]):
            start = 8 + index * entry
            offset, size = struct.unpack(layout, data[start:start + entry])[2:4]
            if size and offset + size <= len(data):
                yield from images(data[offset:offset + size], _join(path, f"fat[{index}]"), depth + 1)
    elif data.startswith(_AR):
        for name, body in ar_members(data):
            yield from images(body, _join(path, name or "member"), depth + 1)


def version(packed: int) -> str:
    """X.Y.Z from Mach-O's xxxx.yy.zz nibbles: 0x000e0100 -> "14.1.0"."""
    return f"{packed >> 16}.{(packed >> 8) & 0xFF}.{packed & 0xFF}"


def _string(blob: bytes, start: int) -> str:
    return blob[start:].split(b"\0", 1)[0].decode("utf-8", "replace")


def image_fields(data: bytes) -> dict:
    """Header and load-command fields of one thin image; a damaged command ends the walk.

    Values stay raw (ints, lists) so a parser applies the answer format's convention.
    """
    order, _ = _THIN[data[:4]]
    wide = data[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
    magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack(order + "7I", data[:28])
    fields: dict = {
        "magic": magic, "bits": 64 if wide else 32, "byte_order": "little" if order == "<" else "big",
        "cputype": cputype, "cpu_name": cpu_name(cputype), "cpusubtype": cpusubtype,
        "filetype": filetype, "filetype_name": FILE_TYPES.get(filetype, "unknown"),
        "ncmds": ncmds, "sizeofcmds": sizeofcmds, "flags": flags,
        "flag_names": [name for bit, name in HEADER_FLAGS.items() if flags & bit],
        "load_commands": [], "dylibs": [], "rpaths": [], "segments": [], "sections": [],
    }
    position = 32 if wide else 28
    try:
        for _ in range(min(ncmds, 4096)):
            cmd, size = struct.unpack_from(order + "II", data, position)
            if size < 8 or position + size > len(data):
                fields["damaged"] = f"load command at {position} runs past the end"
                break
            body = data[position:position + size]
            fields["load_commands"].append(LOAD_COMMANDS.get(cmd, f"0x{cmd:x}"))
            if cmd == 0x1B:
                raw = body[8:24]
                fields["uuid"] = "-".join((raw[:4].hex(), raw[4:6].hex(), raw[6:8].hex(), raw[8:10].hex(), raw[10:].hex())).upper()
            elif cmd == 0x32:
                platform, minos, sdk, ntools = struct.unpack_from(order + "IIII", body, 8)
                fields.update(platform=platform, platform_name=PLATFORMS.get(platform, "unknown"),
                              min_os=version(minos), sdk=version(sdk), build_tools=ntools)
            elif cmd in (0x24, 0x25, 0x2F, 0x30):
                packed, sdk = struct.unpack_from(order + "II", body, 8)
                fields.update(version_min_command=LOAD_COMMANDS[cmd], min_os=version(packed), sdk=version(sdk))
            elif cmd == 0x80000028:
                fields["entryoff"], fields["stacksize"] = struct.unpack_from(order + "QQ", body, 8)
            elif cmd in _DYLIBS:
                name_offset, _, current, compatibility = struct.unpack_from(order + "IIII", body, 8)
                fields["dylibs"].append(_string(body, name_offset))
            elif cmd == 0xD:
                name_offset, _, current, compatibility = struct.unpack_from(order + "IIII", body, 8)
                fields.update(install_name=_string(body, name_offset), current_version=version(current),
                              compatibility_version=version(compatibility))
            elif cmd == 0xE:
                fields["dylinker"] = _string(body, struct.unpack_from(order + "I", body, 8)[0])
            elif cmd == 0x8000001C:
                fields["rpaths"].append(_string(body, struct.unpack_from(order + "I", body, 8)[0]))
            elif cmd == 0x1D:
                fields["code_signature_offset"], fields["code_signature_size"] = struct.unpack_from(order + "II", body, 8)
            elif cmd in (0x21, 0x2C):
                fields["cryptoff"], fields["cryptsize"], fields["cryptid"] = struct.unpack_from(order + "III", body, 8)
            elif cmd == 0x2A:
                packed = struct.unpack_from(order + "Q", body, 8)[0]
                parts = (packed >> 40, (packed >> 30) & 0x3FF, (packed >> 20) & 0x3FF, (packed >> 10) & 0x3FF, packed & 0x3FF)
                fields["source_version"] = ".".join(str(part) for part in parts)
            elif cmd in (0x1, 0x19):
                segment = _string(body[8:24], 0)
                fields["segments"].append(segment)
                count = struct.unpack_from(order + "I", body, 64 if cmd == 0x19 else 48)[0]
                first, step = (72, 80) if cmd == 0x19 else (56, 68)
                for index in range(min(count, 256)):
                    at = first + index * step
                    fields["sections"].append(f"{_string(body[at + 16:at + 32], 0)},{_string(body[at:at + 16], 0)}")
            position += size
    except struct.error:
        fields["damaged"] = f"load command at {position} is cut short"
    return fields
