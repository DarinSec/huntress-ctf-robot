"""Every header field of the executable formats Metadata Forensics asks about, stdlib only.

Day 19 asked an ELF field and day 20 a Mach-O one; a new day's "Determine <property>"
is most likely another field of these formats. triage.md lists all of them, so the value
is in sight the moment the question arrives, and a new parser in solvers/metadata.py is
one line: `formats.elf(data).get("e_type")` or `formats.macho_fields(data)["uuid"]`,
formatted as the answer format asks.

Values stay raw (ints, lists, strings). A damaged file yields the fields read before the
damage plus a "damaged" note; nothing here raises on untrusted bytes or executes them.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import struct
from typing import Any, Callable

from . import macho

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
    except (struct.error, IndexError, ValueError, UnicodeDecodeError) as exc:
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
            return [(label, fields)]
    return []
