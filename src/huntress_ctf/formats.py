"""Every header field of the executable formats Metadata Forensics asks about, stdlib only.

Day 19 asked an ELF field and day 20 a Mach-O one; a new day's "Determine <property>"
is most likely another field of these formats. triage.md lists all of them, so the value
is in sight the moment the question arrives, and a new parser in solvers/metadata.py is
one line: `formats.elf(data).get("e_type")` or `formats.macho_fields(data)["uuid"]`,
formatted as the answer format asks.

Values stay raw (ints, lists, strings). A damaged file yields the fields read before the
damage plus a "damaged" note; nothing here raises on untrusted bytes or executes them.
`describe()` is the one entry point: executables and the everyday file types here, then the
forensic artifact formats of formats_dfir.py (registry, EVTX, disk images, ...).
"""

from __future__ import annotations

from datetime import datetime, timezone
import email
import email.policy
import hashlib
from io import BytesIO
import re
import struct
import zipfile
from typing import Any, Callable

from . import macho
from .containers import ZIP_ERRORS, read_member

ELF_TYPES = {0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN", 4: "ET_CORE"}
ELF_MACHINES = {
    0x03: "x86", 0x08: "mips", 0x14: "ppc", 0x15: "ppc64", 0x28: "arm", 0x2A: "superh",
    0x32: "ia64", 0x3E: "x86_64", 0xB7: "aarch64", 0xF3: "riscv", 0x102: "loongarch",
}
ELF_OSABI = {0: "SYSV", 1: "HPUX", 2: "NETBSD", 3: "LINUX", 6: "SOLARIS", 9: "FREEBSD", 12: "OPENBSD", 97: "ARM", 255: "STANDALONE"}
ELF_SEGMENTS = {
    0: "PT_NULL", 1: "PT_LOAD", 2: "PT_DYNAMIC", 3: "PT_INTERP", 4: "PT_NOTE", 5: "PT_SHLIB",
    6: "PT_PHDR", 7: "PT_TLS", 0x6474E550: "PT_GNU_EH_FRAME", 0x6474E551: "PT_GNU_STACK",
    0x6474E552: "PT_GNU_RELRO", 0x6474E553: "PT_GNU_PROPERTY",
}
PE_MACHINES = {0x14C: "i386", 0x8664: "amd64", 0x1C0: "arm", 0x1C4: "armnt", 0xAA64: "arm64", 0x200: "ia64"}
PE_SUBSYSTEMS = {
    1: "native", 2: "windows_gui", 3: "windows_cui", 5: "os2_cui", 7: "posix_cui",
    9: "windows_ce_gui", 10: "efi_application", 11: "efi_boot_service_driver",
    12: "efi_runtime_driver", 13: "efi_rom", 14: "xbox", 16: "windows_boot_application",
}
PE_VERSION_KEYS = (
    "CompanyName", "FileDescription", "FileVersion", "InternalName", "LegalCopyright",
    "OriginalFilename", "ProductName", "ProductVersion", "Comments", "LegalTrademarks",
)
WASM_SECTIONS = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table", 5: "memory", 6: "global",
    7: "export", 8: "start", 9: "element", 10: "code", 11: "data", 12: "datacount", 13: "tag",
}
WASM_KINDS = {0: "func", 1: "table", 2: "memory", 3: "global", 4: "tag"}
JAVA_RELEASES = {45: "1.1", 46: "1.2", 47: "1.3", 48: "1.4", 49: "5", 50: "6", 51: "7", 52: "8"}


def _cstring(blob: bytes, start: int) -> str:
    return blob[start:].split(b"\0", 1)[0].decode("utf-8", "replace")


def _guarded(parse: Callable[[bytes, dict], None], data: bytes) -> dict:
    fields: dict = {}
    try:
        parse(data, fields)
    except (struct.error, IndexError, ValueError, UnicodeDecodeError, OverflowError, *ZIP_ERRORS) as exc:
        fields["damaged"] = f"{type(exc).__name__} while reading"
    return fields


# --- ELF ---------------------------------------------------------------------------------

def _elf(data: bytes, f: dict) -> None:
    wide = data[4] == 2
    order = "<" if data[5] == 1 else ">"
    f.update(ei_class="ELF64" if wide else "ELF32", ei_data="LSB" if order == "<" else "MSB",
             ei_version=data[6], ei_osabi=data[7], osabi_name=ELF_OSABI.get(data[7], "unknown"),
             ei_abiversion=data[8])
    layout = order + ("HHIQQQIHHHHHH" if wide else "HHIIIIIHHHHHH")
    (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize,
     e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(layout, data, 16)
    f.update(e_type=e_type, e_type_name=ELF_TYPES.get(e_type, "unknown"), e_machine=e_machine,
             e_machine_name=ELF_MACHINES.get(e_machine, "unknown"), e_version=e_version,
             e_entry=e_entry, e_phoff=e_phoff, e_shoff=e_shoff, e_flags=e_flags, e_ehsize=e_ehsize,
             e_phentsize=e_phentsize, e_phnum=e_phnum, e_shentsize=e_shentsize, e_shnum=e_shnum,
             e_shstrndx=e_shstrndx)
    segments = []
    for index in range(min(e_phnum, 256)):
        at = e_phoff + index * e_phentsize
        p_type = struct.unpack_from(order + "I", data, at)[0]
        if wide:  # p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz
            offset, filesz = struct.unpack_from(order + "Q16xQ", data, at + 8)
        else:  # p_type, p_offset, p_vaddr, p_paddr, p_filesz
            offset, filesz = struct.unpack_from(order + "I8xI", data, at + 4)
        segments.append(ELF_SEGMENTS.get(p_type, f"0x{p_type:x}"))
        if p_type == 3:
            f["interp"] = _cstring(data[offset:offset + filesz], 0)
    f["segments"] = segments
    sections = []
    for index in range(min(e_shnum, 1024)):
        at = e_shoff + index * e_shentsize
        if wide:
            name, kind, _, _, offset, size, link = struct.unpack_from(order + "IIQQQQI", data, at)
        else:
            name, kind, _, _, offset, size, link = struct.unpack_from(order + "IIIIIII", data, at)
        sections.append((name, kind, offset, size, link))
    if sections and e_shstrndx < len(sections):
        names_at = sections[e_shstrndx][2]
        named = [(_cstring(data, names_at + name), kind, offset, size, link) for name, kind, offset, size, link in sections]
        f["sections"] = [name for name, *_ in named if name]
        for name, kind, offset, size, link in named:
            if name == ".note.gnu.build-id" and size >= 16:
                namesz, descsz = struct.unpack_from(order + "II", data, offset)
                start = offset + 12 + ((namesz + 3) & ~3)
                f["build_id"] = data[start:start + descsz].hex()
            if kind == 6 and link < len(named):  # SHT_DYNAMIC; its strings are in sh_link.
                strings = named[link][2]
                step, layout = (16, order + "qQ") if wide else (8, order + "iI")
                needed = []
                for at in range(offset, offset + size, step):
                    tag, value = struct.unpack_from(layout, data, at)
                    if tag == 0:
                        break
                    if tag == 1:
                        needed.append(_cstring(data, strings + value))
                    elif tag == 14:
                        f["soname"] = _cstring(data, strings + value)
                f["needed"] = needed


def elf(data: bytes) -> dict | None:
    return _guarded(_elf, data) if data.startswith(b"\x7fELF") and len(data) >= 52 else None


# --- PE ----------------------------------------------------------------------------------

def _rva(rva: int, sections: list[tuple[str, int, int, int, int]]) -> int | None:
    for _, virtual_address, size, raw_size, raw_pointer in sections:
        if virtual_address <= rva < virtual_address + max(size, raw_size):
            return raw_pointer + rva - virtual_address
    return None


def _utf16_value(data: bytes, key: str) -> str | None:
    """A version-resource string: its UTF-16 key, padding to 32 bits, then the value."""
    marker = (key + "\0").encode("utf-16-le")
    at = data.find(marker)
    if at < 6:
        return None
    length = struct.unpack_from("<H", data, at - 4)[0]
    start = at + len(marker)
    start += (-start) % 4
    return data[start:start + 2 * length].decode("utf-16-le", "replace").split("\0", 1)[0] or None


def _pe(data: bytes, f: dict) -> None:
    header = struct.unpack_from("<I", data, 0x3C)[0]
    machine, count, stamp, symbols, nsymbols, optional_size, characteristics = struct.unpack_from("<HHIIIHH", data, header + 4)
    f.update(machine=machine, machine_name=PE_MACHINES.get(machine, "unknown"), number_of_sections=count,
             time_date_stamp=stamp,
             time_date_stamp_utc=datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             pointer_to_symbol_table=symbols, number_of_symbols=nsymbols,
             size_of_optional_header=optional_size, characteristics=characteristics)
    optional = header + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    wide = magic == 0x20B
    f.update(optional_magic=magic, pe_format="PE32+" if wide else "PE32",
             linker_version=f"{data[optional + 2]}.{data[optional + 3]}")
    size_of_code, _, _, entry, base_of_code = struct.unpack_from("<IIIII", data, optional + 4)
    image_base = struct.unpack_from("<Q" if wide else "<I", data, optional + 24)[0]
    (section_alignment, file_alignment, os_major, os_minor, image_major, image_minor,
     sub_major, sub_minor, _, size_of_image, size_of_headers, checksum, subsystem,
     dll_characteristics) = struct.unpack_from("<IIHHHHHHIIIIHH", data, optional + 32)
    f.update(size_of_code=size_of_code, address_of_entry_point=entry, base_of_code=base_of_code,
             image_base=image_base, section_alignment=section_alignment, file_alignment=file_alignment,
             os_version=f"{os_major}.{os_minor}", image_version=f"{image_major}.{image_minor}",
             subsystem_version=f"{sub_major}.{sub_minor}", size_of_image=size_of_image,
             size_of_headers=size_of_headers, checksum=checksum, subsystem=subsystem,
             subsystem_name=PE_SUBSYSTEMS.get(subsystem, "unknown"), dll_characteristics=dll_characteristics)
    directories_at = optional + (112 if wide else 96)
    count_dirs = struct.unpack_from("<I", data, directories_at - 4)[0]
    directories = [struct.unpack_from("<II", data, directories_at + 8 * i) for i in range(min(count_dirs, 16))]
    sections = []
    for index in range(min(count, 96)):
        at = optional + optional_size + 40 * index
        name = data[at:at + 8].rstrip(b"\0").decode("utf-8", "replace")
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", data, at + 8)
        sections.append((name, virtual_address, virtual_size, raw_size, raw_pointer))
    f["sections"] = [name for name, *_ in sections]
    if len(directories) > 1 and directories[1][0]:
        at, imports = _rva(directories[1][0], sections), []
        while at is not None and len(imports) < 512:
            name_rva = struct.unpack_from("<I", data, at + 12)[0]
            if not name_rva:
                break
            name_at = _rva(name_rva, sections)
            imports.append(_cstring(data, name_at) if name_at is not None else f"rva 0x{name_rva:x}")
            at += 20
        f["imports"] = imports
    if directories and directories[0][0]:
        at = _rva(directories[0][0], sections)
        name_at = _rva(struct.unpack_from("<I", data, at + 12)[0], sections) if at is not None else None
        if name_at is not None:
            f["export_name"] = _cstring(data, name_at)
    if len(directories) > 6 and directories[6][0]:
        at = _rva(directories[6][0], sections)
        for index in range(min(directories[6][1] // 28, 16) if at is not None else 0):
            entry = at + 28 * index  # IMAGE_DEBUG_DIRECTORY: Type at +12, PointerToRawData at +24.
            kind, pointer = struct.unpack_from("<I", data, entry + 12)[0], struct.unpack_from("<I", data, entry + 24)[0]
            if kind == 2 and data[pointer:pointer + 4] == b"RSDS":
                raw = data[pointer + 4:pointer + 20]
                f["pdb_guid"] = "{%s}" % "-".join((raw[3::-1].hex(), raw[5:3:-1].hex(), raw[7:5:-1].hex(), raw[8:10].hex(), raw[10:16].hex())).upper()
                f["pdb_age"] = struct.unpack_from("<I", data, pointer + 20)[0]
                f["pdb_path"] = _cstring(data, pointer + 24)
    if len(directories) > 14 and directories[14][0]:
        cli = _rva(directories[14][0], sections)
        metadata_at = _rva(struct.unpack_from("<I", data, cli + 8)[0], sections) if cli is not None else None
        if metadata_at is not None and data[metadata_at:metadata_at + 4] == b"BSJB":
            length = struct.unpack_from("<I", data, metadata_at + 12)[0]
            f["clr_runtime_version"] = _cstring(data[metadata_at + 16:metadata_at + 16 + length], 0)
    for key in PE_VERSION_KEYS:
        value = _utf16_value(data, key)
        if value:
            f[f"version_{key}"] = value


def pe(data: bytes) -> dict | None:
    if len(data) < 64 or not data.startswith(b"MZ"):
        return None
    header = struct.unpack_from("<I", data, 0x3C)[0]
    return _guarded(_pe, data) if data[header:header + 4] == b"PE\0\0" else None


# --- WebAssembly -------------------------------------------------------------------------

def _leb(data: bytes, at: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, at


def _name(data: bytes, at: int) -> tuple[str, int]:
    length, at = _leb(data, at)
    return data[at:at + length].decode("utf-8", "replace"), at + length


def _skip_limits(data: bytes, at: int) -> int:
    flags = data[at]
    _, at = _leb(data, at + 1)
    return _leb(data, at)[1] if flags & 1 else at


def _skip_import(data: bytes, at: int, kind: int) -> int:
    if kind == 0:  # function: type index
        return _leb(data, at)[1]
    if kind == 1:  # table: reference type, limits
        return _skip_limits(data, at + 1)
    if kind == 2:  # memory: limits
        return _skip_limits(data, at)
    if kind == 3:  # global: value type, mutability
        return at + 2
    if kind == 4:  # tag: attribute, type index
        return _leb(data, at + 1)[1]
    raise ValueError(f"import kind {kind}")


def _wasm(data: bytes, f: dict) -> None:
    f["version"] = struct.unpack_from("<I", data, 4)[0]
    sections, customs, imports, exports = [], [], [], []
    at = 8
    while at < len(data) and len(sections) < 1024:
        kind = data[at]
        size, body = _leb(data, at + 1)
        end = body + size
        if end > len(data):
            f["damaged"] = f"section {kind} runs past the end"
            break
        sections.append(WASM_SECTIONS.get(kind, f"0x{kind:x}"))
        if kind == 0:
            customs.append(_name(data, body)[0])
        elif kind == 2:
            count, cursor = _leb(data, body)
            for _ in range(min(count, 4096)):
                module, cursor = _name(data, cursor)
                field, cursor = _name(data, cursor)
                import_kind = data[cursor]
                imports.append(f"{module}.{field}:{WASM_KINDS.get(import_kind, import_kind)}")
                cursor = _skip_import(data, cursor + 1, import_kind)
        elif kind == 7:
            count, cursor = _leb(data, body)
            for _ in range(min(count, 4096)):
                name, cursor = _name(data, cursor)
                export_kind = data[cursor]
                _, cursor = _leb(data, cursor + 1)
                exports.append(f"{name}:{WASM_KINDS.get(export_kind, export_kind)}")
        elif kind == 3:
            f["function_count"] = _leb(data, body)[0]
        elif kind == 8:
            f["start_function"] = _leb(data, body)[0]
        at = end
    f.update(sections=sections, custom_sections=customs, imports=imports, exports=exports)


def wasm(data: bytes) -> dict | None:
    return _guarded(_wasm, data) if data.startswith(b"\0asm") and len(data) >= 8 else None


# --- Java class and DEX ------------------------------------------------------------------

def _java_class(data: bytes, f: dict) -> None:
    minor, major, count = struct.unpack_from(">HHH", data, 4)
    f.update(minor_version=minor, major_version=major,
             java_release=JAVA_RELEASES.get(major, str(major - 44) if major > 52 else "unknown"),
             constant_pool_count=count)
    utf8, classes = {}, {}
    at, index = 10, 1
    while index < count:
        tag = data[at]
        if tag == 1:
            length = struct.unpack_from(">H", data, at + 1)[0]
            utf8[index] = data[at + 3:at + 3 + length].decode("utf-8", "replace")
            at += 3 + length
        elif tag == 7:
            classes[index] = struct.unpack_from(">H", data, at + 1)[0]
            at += 3
        elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
            at += 5
        elif tag in (5, 6):
            at += 9
            index += 1  # Long and double take two entries.
        elif tag in (8, 16, 19, 20):
            at += 3
        elif tag == 15:
            at += 4
        else:
            raise ValueError(f"constant tag {tag}")
        index += 1
    access, this_class, super_class, interfaces = struct.unpack_from(">HHHH", data, at)
    f.update(access_flags=access, this_class=utf8.get(classes.get(this_class), ""),
             super_class=utf8.get(classes.get(super_class), ""), interfaces_count=interfaces)


def java_class(data: bytes) -> dict | None:
    if not data.startswith(b"\xca\xfe\xba\xbe") or len(data) < 10 or macho.is_fat(data):
        return None
    return _guarded(_java_class, data)


def _dex(data: bytes, f: dict) -> None:
    f.update(version=data[4:7].decode("ascii"), checksum=struct.unpack_from("<I", data, 8)[0],
             signature=data[12:32].hex())
    names = ("file_size", "header_size", "endian_tag", "link_size", "link_off", "map_off",
             "string_ids_size", "string_ids_off", "type_ids_size", "type_ids_off", "proto_ids_size",
             "proto_ids_off", "field_ids_size", "field_ids_off", "method_ids_size", "method_ids_off",
             "class_defs_size", "class_defs_off", "data_size", "data_off")
    f.update(zip(names, struct.unpack_from("<20I", data, 32)))
    f["checksum_valid"] = f["checksum"] == (__import__("zlib").adler32(data[12:]) & 0xFFFFFFFF)
    f["signature_valid"] = f["signature"] == hashlib.sha1(data[32:]).hexdigest()


def dex(data: bytes) -> dict | None:
    return _guarded(_dex, data) if data.startswith(b"dex\n") and len(data) >= 112 else None


# --- Archives, databases, captures and images --------------------------------------------

GZIP_OS = {0: "FAT", 1: "Amiga", 2: "VMS", 3: "Unix", 4: "VM/CMS", 5: "Atari", 6: "HPFS", 7: "Macintosh",
           8: "Z-System", 9: "CP/M", 10: "TOPS-20", 11: "NTFS", 12: "QDOS", 13: "Acorn", 255: "unknown"}
PCAP_LINKTYPES = {0: "NULL", 1: "ETHERNET", 101: "RAW", 105: "IEEE802_11", 113: "LINUX_SLL",
                  127: "IEEE802_11_RADIOTAP", 228: "IPV4", 229: "IPV6", 276: "LINUX_SLL2"}


def _gzip(data: bytes, f: dict) -> None:
    flags = data[3]
    f.update(method=data[2], flags=flags, mtime=struct.unpack_from("<I", data, 4)[0],
             extra_flags=data[8], os=data[9], os_name=GZIP_OS.get(data[9], "unknown"))
    if f["mtime"]:
        f["mtime_utc"] = datetime.fromtimestamp(f["mtime"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    at = 10
    if flags & 4:
        at += 2 + struct.unpack_from("<H", data, at)[0]
    if flags & 8:
        f["original_name"] = _cstring(data, at)
        at += len(data[at:].split(b"\0", 1)[0]) + 1
    if flags & 16:
        f["comment"] = _cstring(data, at)
    f["isize"] = struct.unpack_from("<I", data, len(data) - 4)[0]  # Uncompressed size mod 2^32.


def _tar(data: bytes, f: dict) -> None:
    octal = lambda raw: int(raw.split(b"\0", 1)[0].strip() or b"0", 8)
    f.update(first_name=_cstring(data[:100], 0), mode=octal(data[100:108]), uid=octal(data[108:116]),
             gid=octal(data[116:124]), size=octal(data[124:136]), mtime=octal(data[136:148]),
             typeflag=chr(data[156]) if data[156] else "0", linkname=_cstring(data[157:257], 0),
             magic=data[257:263].decode("ascii", "replace").strip("\0 "), uname=_cstring(data[265:297], 0),
             gname=_cstring(data[297:329], 0))
    names, at = [], 0
    while at + 512 <= len(data) and len(names) < 4096 and data[at:at + 1] != b"\0":
        names.append(_cstring(data[at:at + 100], 0))
        at += 512 + ((octal(data[at + 124:at + 136]) + 511) // 512) * 512
    f["names"] = names


def _sqlite(data: bytes, f: dict) -> None:
    page = struct.unpack_from(">H", data, 16)[0]
    f.update(page_size=65536 if page == 1 else page, write_version=data[18], read_version=data[19],
             file_change_counter=struct.unpack_from(">I", data, 24)[0],
             database_size_pages=struct.unpack_from(">I", data, 28)[0],
             schema_cookie=struct.unpack_from(">I", data, 40)[0], schema_format=struct.unpack_from(">I", data, 44)[0],
             text_encoding={1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}.get(struct.unpack_from(">I", data, 56)[0], "unknown"),
             user_version=struct.unpack_from(">I", data, 60)[0], application_id=struct.unpack_from(">I", data, 68)[0],
             sqlite_version_number=struct.unpack_from(">I", data, 96)[0])
    # Page geometry (Day 23 "copied, truncated, embedded"): the header's claims against the bytes.
    pages, size = f["database_size_pages"], f["page_size"]
    f.update(reserved_bytes=data[20], freelist_trunk_page=struct.unpack_from(">I", data, 32)[0],
             freelist_page_count=struct.unpack_from(">I", data, 36)[0],
             default_cache_size=struct.unpack_from(">I", data, 48)[0],
             largest_root_page=struct.unpack_from(">I", data, 52)[0],
             incremental_vacuum=bool(struct.unpack_from(">I", data, 64)[0]),
             version_valid_for=struct.unpack_from(">I", data, 92)[0],
             journal_mode="wal" if data[18] == 2 and data[19] == 2 else "rollback",
             file_size_bytes=len(data), expected_size_bytes=pages * size,
             actual_page_count=len(data) // size if size else 0,
             page_aligned=bool(size) and len(data) % size == 0,
             truncated=len(data) < pages * size, trailing_bytes=max(0, len(data) - pages * size))
    # The in-header size is only trusted when the change counter matches (sqlite fileformat 1.3.7).
    f["header_size_valid"] = pages > 0 and f["file_change_counter"] == f["version_valid_for"]
    f["application"] = SQLITE_APPLICATIONS.get(f["application_id"], "none" if not f["application_id"] else "unknown")
    f["application_id_hex"] = f"0x{f['application_id']:08x}"
    f.update(_sqlite_schema(data))


MAX_SCHEMA_BYTES = 64 * 1024 * 1024


def _sqlite_schema(data: bytes) -> dict:
    """The names in sqlite_schema (tables, indexes, views, triggers) in stored order, which tell
    one application's database from another's. Read by the stdlib sqlite3 from a copy in memory,
    defensive and query-only; a database SQLite calls malformed has none (no partial names)."""
    import sqlite3

    if len(data) > MAX_SCHEMA_BYTES:
        return {}
    connection = sqlite3.connect(":memory:")
    try:
        if hasattr(connection, "setconfig"):  # Python 3.12+
            connection.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
        connection.deserialize(data)
        connection.execute("PRAGMA query_only = ON")
        rows = connection.execute("SELECT type, name FROM sqlite_master").fetchall()
    except (sqlite3.Error, AttributeError, ValueError, OverflowError, MemoryError):
        return {}
    finally:
        connection.close()
    names: dict[str, list[str]] = {}
    for kind, name in rows:
        if isinstance(kind, str) and isinstance(name, str) and not name.startswith("sqlite_"):
            names.setdefault(kind, []).append(name)
    tables = names.get("table", [])
    return {"table_names": tables, "table_count": len(tables), "index_names": names.get("index", []),
            "view_names": names.get("view", []), "trigger_names": names.get("trigger", [])}


# PRAGMA application_id values registered in SQLite's magic.txt (the "parent application" a database claims).
SQLITE_APPLICATIONS = {
    0x0F055112: "Fossil checkout", 0x0F055113: "Fossil global", 0x0F055111: "Fossil repository",
    0x47504B47: "GeoPackage", 0x47503130: "GeoPackage 1.0", 0x47503131: "GeoPackage 1.1",
    0x4D504258: "MBTiles",
}


def sqlite(data: bytes) -> dict | None:
    if not data.startswith(b"SQLite format 3\0") or len(data) < 100:
        return None
    return _guarded(_sqlite, data)


def _pcap(data: bytes, f: dict) -> None:
    order = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    major, minor, zone, sigfigs, snaplen, network = struct.unpack_from(order + "HHiIII", data, 4)
    f.update(version=f"{major}.{minor}", nanosecond=data[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"),
             thiszone=zone, snaplen=snaplen, linktype=network, linktype_name=PCAP_LINKTYPES.get(network, "unknown"))
    count, at = 0, 24
    while at + 16 <= len(data) and count < 1_000_000:
        at += 16 + struct.unpack_from(order + "I", data, at + 8)[0]
        count += 1
    f["packet_count"] = count


def _pcapng(data: bytes, f: dict) -> None:
    order = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    major, minor = struct.unpack_from(order + "HH", data, 12)
    f["version"] = f"{major}.{minor}"
    linktypes, packets, at = [], 0, 0
    while at + 12 <= len(data) and packets < 1_000_000:
        kind, length = struct.unpack_from(order + "II", data, at)
        if length < 12:
            break
        if kind == 1:
            linktype, _, snaplen = struct.unpack_from(order + "HHI", data, at + 8)
            linktypes.append(linktype)
            f.setdefault("snaplen", snaplen)
        elif kind in (2, 3, 6):
            packets += 1
        at += length
    f.update(interfaces=len(linktypes), linktype=linktypes[0] if linktypes else None,
             linktype_name=PCAP_LINKTYPES.get(linktypes[0], "unknown") if linktypes else None, packet_count=packets)


def _sub_blocks(data: bytes, at: int) -> tuple[bytes, int]:
    out = bytearray()
    while data[at]:
        out += data[at + 1:at + 1 + data[at]]
        at += 1 + data[at]
    return bytes(out), at + 1


def _gif(data: bytes, f: dict) -> None:
    width, height, packed = struct.unpack_from("<HHB", data, 6)
    f.update(version=data[3:6].decode("ascii"), width=width, height=height, dimensions=f"{width}x{height}",
             global_color_table=bool(packed & 0x80))
    at = 13 + (3 * 2 ** ((packed & 7) + 1) if packed & 0x80 else 0)
    frames, comments = 0, []
    while at < len(data) and frames < 100_000:
        block = data[at]
        if block == 0x3B:  # Trailer
            break
        if block == 0x21:
            label = data[at + 1]
            body, at = _sub_blocks(data, at + 2)
            if label == 0xFE:
                comments.append(body.decode("utf-8", "replace"))
            elif label == 0xFF and body.startswith(b"NETSCAPE2.0") and len(body) >= 14:
                f["loop_count"] = struct.unpack_from("<H", body, 12)[0]
        elif block == 0x2C:
            frames += 1
            local = data[at + 9]
            at += 10 + (3 * 2 ** ((local & 7) + 1) if local & 0x80 else 0)
            _, at = _sub_blocks(data, at + 1)  # LZW minimum code size, then the image data.
        else:
            raise ValueError(f"GIF block 0x{block:02x}")
    f.update(frames=frames, comments=comments)


def _bmp(data: bytes, f: dict) -> None:
    size, offset, header = struct.unpack_from("<I4xII", data, 2)
    width, height, planes, bpp, compression = struct.unpack_from("<iiHHI", data, 18)
    f.update(file_size=size, pixel_offset=offset, dib_header_size=header, width=width, height=abs(height),
             dimensions=f"{width}x{abs(height)}", top_down=height < 0, planes=planes, bits_per_pixel=bpp,
             compression=compression)


def _ico(data: bytes, f: dict) -> None:
    kind, count = struct.unpack_from("<HH", data, 2)
    images = []
    for index in range(min(count, 256)):
        width, height, _, _, _, bpp = struct.unpack_from("<BBBBHH", data, 6 + 16 * index)
        images.append(f"{width or 256}x{height or 256}@{bpp}")
    f.update(type="cursor" if kind == 2 else "icon", image_count=count, images=images)


def _iso(data: bytes, f: dict) -> None:
    base = 0x8000
    text = lambda start, length: data[base + start:base + start + length].decode("ascii", "replace").strip()
    f.update(system_id=text(8, 32), volume_id=text(40, 32),
             volume_space_size=struct.unpack_from("<I", data, base + 80)[0],
             logical_block_size=struct.unpack_from("<H", data, base + 128)[0],
             volume_set_id=text(190, 128), publisher_id=text(318, 128), preparer_id=text(446, 128),
             application_id=text(574, 128), creation_date=text(813, 16), modification_date=text(830, 16))


def other_formats(data: bytes) -> list[tuple[str, dict]]:
    checks = (
        ("gzip", data.startswith(b"\x1f\x8b") and len(data) >= 18, _gzip),
        ("tar", len(data) >= 512 and data[257:262] == b"ustar", _tar),
        ("sqlite", data.startswith(b"SQLite format 3\0") and len(data) >= 100, _sqlite),
        ("pcap", data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
         and len(data) >= 24, _pcap),
        ("pcapng", data.startswith(b"\x0a\x0d\x0d\x0a") and len(data) >= 28, _pcapng),
        ("gif", data[:6] in (b"GIF87a", b"GIF89a") and len(data) >= 13, _gif),
        ("bmp", data.startswith(b"BM") and len(data) >= 30, _bmp),
        ("ico", data[:4] in (b"\0\0\x01\0", b"\0\0\x02\0") and len(data) >= 22, _ico),
        ("iso", len(data) >= 0x8000 + 881 and data[0x8001:0x8006] == b"CD001", _iso),
    )
    found = [(label, _guarded(parse, data)) for label, match, parse in checks if match]
    if data.startswith(b"7z\xbc\xaf\x27\x1c") and len(data) >= 8:
        found.append(("sevenzip", {"version": f"{data[6]}.{data[7]}"}))
    if data.startswith(b"Rar!\x1a\x07"):
        found.append(("rar", {"version": 5 if data[6:8] == b"\x01\x00" else 4}))
    return found


# --- Documents and images the Metadata lane asks about ------------------------------------

PNG_COLOR_TYPES = {0: "grayscale", 2: "truecolor", 3: "indexed", 4: "grayscale_alpha", 6: "truecolor_alpha"}


def _snake(name: str) -> str:
    """"DateTimeOriginal" -> "date_time_original"; "dc:creator" -> "dc_creator"."""
    name = re.sub(r"[^A-Za-z0-9]+", "_", name)
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).strip("_").lower()


def _evidence_fields(data: bytes, prefixes: tuple[str, ...]) -> dict:
    from .evidence import metadata  # evidence.py parses EXIF, PNG text, PDF Info, XMP, docProps.

    fields: dict = {}
    for key, values in metadata(data).items():
        prefix, _, name = key.partition(":")
        if prefix in prefixes and name and not name.startswith("modified:"):
            field = _snake(name) if prefix not in ("XMP", "GPS") else f"{prefix.lower()}_{_snake(name)}"
            fields.setdefault(field, values[0] if len(values) == 1 else values)
    return fields


def _png(data: bytes, f: dict) -> None:
    chunks, at, idat = [], 8, 0
    while at + 8 <= len(data) and len(chunks) < 10_000:
        length, kind = struct.unpack_from(">I4s", data, at)
        body = data[at + 8:at + 8 + length]
        name = kind.decode("latin-1")
        chunks.append(name)
        if name == "IHDR":
            width, height, depth, color, compression, filtering, interlace = struct.unpack_from(">IIBBBBB", body)
            f.update(width=width, height=height, dimensions=f"{width}x{height}", bit_depth=depth, color_type=color,
                     color_type_name=PNG_COLOR_TYPES.get(color, "unknown"), compression_method=compression,
                     filter_method=filtering, interlace_method=interlace)
        elif name == "tIME":
            year, month, day, hour, minute, second = struct.unpack_from(">HBBBBB", body)
            f["last_modified"] = f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
        elif name == "pHYs":
            f["pixels_per_unit_x"], f["pixels_per_unit_y"], f["unit"] = struct.unpack_from(">IIB", body)
        elif name == "gAMA":
            f["gamma"] = struct.unpack_from(">I", body)[0]
        elif name == "iCCP":
            f["icc_profile_name"] = _cstring(body, 0)
        elif name == "IDAT":
            idat += 1
        at += 12 + length
        if name == "IEND":
            f["trailing_bytes"] = len(data) - at
            break
    f.update(chunks=chunks, chunk_count=len(chunks), idat_count=idat, **_evidence_fields(data, ("PNG", "XMP")))


def _jpeg(data: bytes, f: dict) -> None:
    markers, at = [], 2
    while at + 4 <= len(data) and len(markers) < 10_000:
        if data[at] != 0xFF:
            break
        marker = data[at + 1]
        if marker in (0xD9, 0xDA):  # End of image, or start of scan: the header part is done.
            markers.append(f"FF{marker:02X}")
            break
        length = struct.unpack_from(">H", data, at + 2)[0]
        body = data[at + 4:at + 2 + length]
        markers.append(f"FF{marker:02X}")
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            precision, height, width, components = struct.unpack_from(">BHHB", body)
            f.update(sof_marker=f"FF{marker:02X}", precision=precision, width=width, height=height,
                     dimensions=f"{width}x{height}", components=components, progressive=marker == 0xC2)
        elif marker == 0xE0 and body.startswith(b"JFIF\0"):
            f.update(jfif_version=f"{body[5]}.{body[6]:02d}", density_unit=body[7],
                     density_x=struct.unpack_from(">H", body, 8)[0], density_y=struct.unpack_from(">H", body, 10)[0])
        at += 2 + length
    f.update(markers=markers, **_evidence_fields(data, ("EXIF", "GPS", "JPEG", "XMP")))


def _pdf(data: bytes, f: dict) -> None:
    header = re.match(rb"%PDF-(\d+\.\d+)", data)
    f.update(version=header[1].decode() if header else None,
             page_count=len(re.findall(rb"/Type\s*/Page(?![a-zA-Z])", data)),
             object_count=len(re.findall(rb"\d+\s+\d+\s+obj\b", data)),
             encrypted=b"/Encrypt" in data, linearized=b"/Linearized" in data[:2048],
             eof_markers=data.count(b"%%EOF"), **_evidence_fields(data, ("PDF", "XMP")))


def _zip(data: bytes, f: dict) -> None:
    with zipfile.ZipFile(BytesIO(data)) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        # Also under the words the Metadata lane uses (zip.eocd_total_entries, ..._member_names).
        f.update(entry_count=len(infos), total_entries=len(infos), names=names, member_names=names,
                 comment=archive.comment.decode("utf-8", "replace"),
                 compression_methods=sorted({info.compress_type for info in infos}),
                 encrypted_entries=sum(1 for info in infos if info.flag_bits & 1),
                 total_uncompressed=sum(info.file_size for info in infos))


def _email(data: bytes, f: dict) -> None:
    message = email.message_from_bytes(data, policy=email.policy.default)
    for header in ("from", "to", "cc", "subject", "date", "message-id", "x-mailer", "user-agent",
                   "return-path", "reply-to", "x-originating-ip", "in-reply-to"):
        if message[header] is not None:
            f[_snake(header)] = str(message[header])
    f.update(received_count=len(message.get_all("received") or []), content_type=message.get_content_type(),
             attachments=[part.get_filename() for part in message.walk() if part.get_filename()])


WAVE_CODECS = {6: "pcm_alaw", 7: "pcm_mulaw", 0x11: "adpcm_ima_wav", 2: "adpcm_ms", 0x31: "gsm_ms", 0x55: "mp3"}


def _wav(data: bytes, f: dict) -> None:
    at = 12
    while at + 8 <= len(data):
        kind, size = struct.unpack_from("<4sI", data, at)
        if kind == b"fmt ":
            audio, channels, rate, byte_rate, align, bits = struct.unpack_from("<HHIIHH", data, at + 8)
            if audio == 0xFFFE and size >= 40:  # WAVE_FORMAT_EXTENSIBLE: the GUID starts with the format.
                audio = struct.unpack_from("<H", data, at + 32)[0]
            if audio == 1:
                codec = "pcm_u8" if bits == 8 else f"pcm_s{bits}le"
            elif audio == 3:
                codec = f"pcm_f{bits}le"
            else:
                codec = WAVE_CODECS.get(audio, f"0x{audio:04x}")
            f.update(audio_format=audio, codec_name=codec, channels=channels, sample_rate=rate,
                     byte_rate=byte_rate, block_align=align, bits_per_sample=bits)
        elif kind == b"data":
            f["data_size"] = size
            if f.get("byte_rate"):
                f["duration_seconds"] = round(size / f["byte_rate"], 6)
        at += 8 + size + (size & 1)


def _filetime(value: int) -> str | None:
    if not value:
        return None
    return datetime.fromtimestamp((value - 116444736000000000) / 10_000_000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _lnk(data: bytes, f: dict) -> None:
    flags, attributes, created, accessed, written, size, icon, show, hotkey = struct.unpack_from("<IIQQQIiIH", data, 20)
    f.update(link_flags=flags, file_attributes=attributes, creation_time=_filetime(created),
             access_time=_filetime(accessed), write_time=_filetime(written), target_file_size=size,
             icon_index=icon, show_command=show, hotkey=hotkey)
    at = 76
    if flags & 0x1:  # HasLinkTargetIDList
        at += 2 + struct.unpack_from("<H", data, at)[0]
    if flags & 0x2:  # HasLinkInfo
        info_size, header_size, info_flags, volume, local, network, suffix = struct.unpack_from("<IIIIIII", data, at)
        if info_flags & 1:
            f["local_base_path"] = data[at + local:].split(b"\0", 1)[0].decode("cp1252", "replace")
            f["common_path_suffix"] = data[at + suffix:].split(b"\0", 1)[0].decode("cp1252", "replace")
            f["target_path"] = f["local_base_path"] + f["common_path_suffix"]
            if volume:
                drive_type, serial = struct.unpack_from("<II", data, at + volume + 4)
                f.update(drive_type=drive_type, drive_serial_number=f"{serial:08X}")
        at += info_size
    unicode = bool(flags & 0x80)
    for bit, name in ((0x4, "name"), (0x8, "relative_path"), (0x10, "working_directory"),
                      (0x20, "arguments"), (0x40, "icon_location")):
        if flags & bit:
            count = struct.unpack_from("<H", data, at)[0]
            width = 2 if unicode else 1
            raw = data[at + 2:at + 2 + count * width]
            f[name] = raw.decode("utf-16-le" if unicode else "cp1252", "replace")
            at += 2 + count * width


def _text(data: bytes, f: dict) -> None:
    bom = data.startswith(b"\xef\xbb\xbf")
    text = data.decode("utf-8-sig")
    endings = {"crlf": text.count("\r\n"), "lf": text.count("\n") - text.count("\r\n"),
               "cr": text.count("\r") - text.count("\r\n")}
    used = [name for name, count in endings.items() if count]
    f.update(utf8_bom_present=bom, encoding="utf-8-sig" if bom else "utf-8", byte_count=len(data),
             char_count=len(text), line_count=len(text.splitlines()),
             line_ending=used[0] if len(used) == 1 else ("mixed" if used else "none"),
             trailing_newline=text.endswith(("\n", "\r")))


# Android attribute resource IDs, for manifests whose attribute name strings are empty.
ANDROID_ATTRIBUTES = {
    0x01010003: "name", 0x01010001: "label", 0x0101021B: "versionCode", 0x0101021C: "versionName",
    0x0101020C: "minSdkVersion", 0x01010270: "targetSdkVersion", 0x01010271: "maxSdkVersion",
    0x01010572: "compileSdkVersion", 0x01010573: "compileSdkVersionCodename",
}


def _axml_strings(data: bytes, at: int) -> list[str]:
    count, _, flags, strings_start = struct.unpack_from("<IIII", data, at + 8)
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from(f"<{count}I", data, at + 28)
    found = []
    for offset in offsets:
        position = at + strings_start + offset
        if utf8:
            position += 2 if data[position] & 0x80 else 1  # Length in characters.
            length = data[position]
            if length & 0x80:
                length = ((length & 0x7F) << 8) | data[position + 1]
                position += 1
            found.append(data[position + 1:position + 1 + length].decode("utf-8", "replace"))
        else:
            length = struct.unpack_from("<H", data, position)[0]
            if length & 0x8000:
                length = ((length & 0x7FFF) << 16) | struct.unpack_from("<H", data, position + 2)[0]
                position += 2
            found.append(data[position + 2:position + 2 + 2 * length].decode("utf-16-le", "replace"))
    return found


def axml(data: bytes) -> list[tuple[str, dict[str, str]]]:
    """Elements of Android binary XML (AndroidManifest.xml) as (tag, {attribute: value})."""
    if data[:2] != b"\x03\x00":
        raise ValueError("not Android binary XML")
    strings: list[str] = []
    resource_ids: list[int] = []
    elements = []
    at = struct.unpack_from("<H", data, 2)[0]
    while at + 8 <= len(data):
        kind, header, size = struct.unpack_from("<HHI", data, at)
        if size < 8:
            break
        if kind == 0x0001:
            strings = _axml_strings(data, at)
        elif kind == 0x0180:
            resource_ids = list(struct.unpack_from(f"<{(size - header) // 4}I", data, at + header))
        elif kind == 0x0102:
            name_index, attribute_start, attribute_size, count = struct.unpack_from("<4xIHHH", data, at + 16)
            tag = strings[name_index] if name_index < len(strings) else ""
            attributes = {}
            for index in range(count):
                base = at + 16 + attribute_start + index * attribute_size
                _, name, raw, _, data_type, value = struct.unpack_from("<IIIHxBI", data, base)
                key = strings[name] if name < len(strings) else ""
                if not key and name < len(resource_ids):
                    key = ANDROID_ATTRIBUTES.get(resource_ids[name], f"0x{resource_ids[name]:08x}")
                if raw != 0xFFFFFFFF and raw < len(strings):
                    text = strings[raw]
                elif data_type == 0x03 and value < len(strings):
                    text = strings[value]
                elif data_type == 0x12:
                    text = "true" if value else "false"
                elif data_type == 0x11:
                    text = f"0x{value:x}"
                elif data_type == 0x01:
                    text = f"@0x{value:08x}"
                else:
                    text = str(value)
                attributes[key] = text
            elements.append((tag, attributes))
        at += size
    return elements


def _pb_varint(data: bytes, at: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, at
        shift += 7
        if shift > 63:
            raise ValueError("protobuf varint too long")


def _pb_fields(data: bytes) -> list[tuple[int, int, Any]]:
    """(field number, wire type, value) of one protobuf message; length-delimited values as bytes."""
    fields, at = [], 0
    while at < len(data):
        key, at = _pb_varint(data, at)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, at = _pb_varint(data, at)
        elif wire == 2:
            size, at = _pb_varint(data, at)
            if at + size > len(data):
                raise ValueError("protobuf field past its message")
            value, at = data[at:at + size], at + size
        elif wire in (1, 5):
            value, at = data[at:at + (8 if wire == 1 else 4)], at + (8 if wire == 1 else 4)
        else:
            raise ValueError("protobuf wire type")
        fields.append((number, wire, value))
    return fields


def proto_xml(data: bytes) -> list[tuple[str, dict[str, str]]]:
    """An App Bundle's aapt2 proto XML (`base/manifest/AndroidManifest.xml` of an .aab) in axml()'s
    shape: (tag, {attribute: value}) per element in document order. XmlNode: 1 element; XmlElement:
    3 name, 4 attribute (2 name, 3 value), 5 child node."""
    elements: list[tuple[str, dict[str, str]]] = []

    def node(blob: bytes, depth: int) -> None:
        if depth > 64 or len(elements) > 20000:
            raise ValueError("proto XML too deep or too large")
        for number, wire, value in _pb_fields(blob):
            if number == 1 and wire == 2:
                name, attributes, children = "", {}, []
                for field, kind, item in _pb_fields(value):
                    if field == 3 and kind == 2:
                        name = item.decode("utf-8")
                    elif field == 4 and kind == 2:
                        parts = {n: v for n, k, v in _pb_fields(item) if k == 2}
                        if 2 in parts:
                            attributes[parts[2].decode("utf-8")] = parts.get(3, b"").decode("utf-8")
                    elif field == 5 and kind == 2:
                        children.append(item)
                elements.append((name, attributes))
                for child in children:
                    node(child, depth + 1)

    node(data, 0)
    return elements


def _apk(data: bytes, f: dict) -> None:
    with zipfile.ZipFile(BytesIO(data)) as archive:
        names = archive.namelist()
        manifest = read_member(archive, "AndroidManifest.xml")
    # A module of an .aab keeps aapt2's protobuf manifest; an APK has binary XML (RES_XML_TYPE).
    elements = proto_xml(manifest) if manifest[:1] == b"\x0a" else axml(manifest)
    root = next((attributes for tag, attributes in elements if tag == "manifest"), {})
    sdk = next((attributes for tag, attributes in elements if tag == "uses-sdk"), {})
    application = next((attributes for tag, attributes in elements if tag == "application"), {})
    f.update(package_name=root.get("package", "none"), version_code=root.get("versionCode"),
             version_name=root.get("versionName"), compile_sdk_version=root.get("compileSdkVersion"),
             platform_build_version_name=root.get("platformBuildVersionName"),
             min_sdk_version=sdk.get("minSdkVersion"), target_sdk_version=sdk.get("targetSdkVersion"),
             application_label=application.get("label"), application_name=application.get("name"),
             permissions=[a.get("name") for tag, a in elements if tag == "uses-permission"],
             activities=[a.get("name") for tag, a in elements if tag == "activity"],
             services=[a.get("name") for tag, a in elements if tag == "service"],
             receivers=[a.get("name") for tag, a in elements if tag == "receiver"],
             dex_files=[name for name in names if name.endswith(".dex")],
             signature_files=[name for name in names if name.startswith("META-INF/")])


def apk(data: bytes) -> dict | None:
    if not data.startswith(b"PK"):
        return None
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            if "AndroidManifest.xml" not in archive.namelist():
                return None
    except ZIP_ERRORS:
        return None
    return _guarded(_apk, data)


def document_formats(data: bytes) -> list[tuple[str, dict]]:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return [("png", _guarded(_png, data))]
    if data.startswith(b"\xff\xd8\xff"):
        return [("jpeg", _guarded(_jpeg, data))]
    if data.startswith(b"%PDF-"):
        return [("pdf", _guarded(_pdf, data))]
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        android = apk(data)
        found = [("apk", android)] if android is not None else []
        found.append(("zip", _guarded(_zip, data)))
        office = _evidence_fields(data, ("Office", "Office:app", "Office:custom"))
        if office:
            found.append(("ooxml", office))
        return found
    if data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return [("media_wav", _guarded(_wav, data))]
    if data[:4] == b"\x4c\0\0\0" and len(data) >= 76:  # HeaderSize 0x4C, as metadata.py's LNK parser.
        return [("lnk", _guarded(_lnk, data))]
    head = data[:4096]
    if re.search(rb"(?im)^from:", head) and re.search(rb"(?im)^(subject|message-id|received):", head):
        return [("email", _guarded(_email, data))]
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return []
    if text and sum(char.isprintable() or char in "\r\n\t" for char in text[:4096]) >= 0.95 * min(len(text), 4096):
        return [("text", _guarded(_text, data))]
    return []


def macho_fields(data: bytes) -> dict | None:
    """Fields of the first thin Mach-O image (a fat file's first slice), like elf() and pe()."""
    image = next(macho.images(data), None)
    return macho.image_fields(image[1]) if image else None


# --- All of them -------------------------------------------------------------------------

def describe(data: bytes) -> list[tuple[str, dict]]:
    """(label, fields) for each recognized image: one per Mach-O slice, else at most one."""
    found = [(f"macho {path}".strip(), macho.image_fields(image)) for path, image in macho.images(data)]
    if found:
        return found
    for label, parse in (("elf", elf), ("pe", pe), ("wasm", wasm), ("java_class", java_class), ("dex", dex)):
        fields = parse(data)
        if fields is not None:
            from . import formats_dfir

            signature = formats_dfir.pe_signature(data) if label == "pe" else None
            return [(label, fields)] + ([("pe_signature", signature)] if signature else [])
    from . import formats_dfir  # Formats no day has asked about yet (Day 24+ candidates).

    return other_formats(data) + document_formats(data) + formats_dfir.formats(data)
