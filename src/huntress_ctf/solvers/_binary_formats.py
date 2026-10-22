"""Bounded executable readers. No loading, disassembly, network, or sample execution.

Layouts follow Microsoft's PE format, the System V ELF ABI, and Apple's loader.h.
Malformed/unsupported structures raise ParseError, never an invented empty result.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
import struct

MAX_ENTRIES = 65536
MAX_SECTIONS = 4096


class ParseError(ValueError):
    pass


class Reader:
    def __init__(self, data: bytes, endian: str = "<"):
        self.data, self.endian = data, endian

    def take(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset > len(self.data) - size:
            raise ParseError("Structure extends beyond assigned bytes")
        return self.data[offset:offset + size]

    def unpack(self, layout: str, offset: int) -> tuple:
        return struct.unpack(self.endian + layout, self.take(offset, struct.calcsize(self.endian + layout)))

    def table(self, offset: int, count: int, stride: int, minimum: int) -> None:
        if count < 0 or count > MAX_ENTRIES or stride < minimum:
            raise ParseError("Invalid table dimensions")
        self.take(offset, count * stride)

    def string(self, offset: int, end: int | None = None) -> str:
        end = min(len(self.data), offset + 4096) if end is None else end
        self.take(offset, end - offset)
        zero = self.data.find(b"\0", offset, end)
        if zero < 0:
            raise ParseError("Unterminated string")
        value = self.data[offset:zero].decode("utf-8", "strict")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ParseError("Control character in name")
        return value


@dataclass(frozen=True)
class Section:
    name: str
    address: int
    offset: int
    size: int
    virtual_size: int
    kind: int = 0
    link: int = 0
    entry_size: int = 0
    flags: int = 0


@dataclass(frozen=True)
class Resource:
    path: tuple[str, ...]
    offset: int
    size: int


@dataclass(frozen=True)
class Symbol:
    name: str
    value: int
    size: int
    section: int
    kind: int


def fixed_name(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("ascii", "strict")


class PE(Reader):
    format = "PE"

    def __init__(self, data: bytes):
        super().__init__(data)
        if self.take(0, 2) != b"MZ":
            raise ParseError("Not PE")
        pe, = self.unpack("I", 0x3c)
        if pe < 0x40 or self.take(pe, 4) != b"PE\0\0":
            raise ParseError("Invalid PE signature")
        machine, count, _, self.coff_offset, self.coff_count, optional_size, _ = self.unpack("HHIIIHH", pe + 4)
        if count > MAX_SECTIONS:
            raise ParseError("Too many PE sections")
        optional = pe + 24
        self.take(optional, optional_size)
        magic, = self.unpack("H", optional)
        if magic not in (0x10b, 0x20b):
            raise ParseError("Unsupported optional header")
        self.bits = 32 if magic == 0x10b else 64
        directory_start = 96 if self.bits == 32 else 112
        if optional_size < directory_start:
            raise ParseError("Truncated optional header")
        self.arch = {0x14c: "x86", 0x8664: "x86_64", 0x1c0: "arm", 0x1c4: "arm",
                     0xaa64: "arm64", 0x1f0: "powerpc"}.get(machine)
        expected_bits = {0x14c: 32, 0x8664: 64, 0x1c0: 32, 0x1c4: 32, 0xaa64: 64}.get(machine)
        if expected_bits and expected_bits != self.bits:
            raise ParseError("PE machine and optional-header bitness disagree")
        self.machine = machine
        self.entry, = self.unpack("I", optional + 16)  # RVA, not a file offset.
        self.image_base, = self.unpack("I" if self.bits == 32 else "Q", optional + (28 if self.bits == 32 else 24))
        self.header_size, = self.unpack("I", optional + 60)
        if self.header_size > len(data):
            raise ParseError("Header size exceeds file")
        directories, = self.unpack("I", optional + directory_start - 4)
        if directories > (optional_size - directory_start) // 8:
            raise ParseError("Truncated data directories")
        self.directories = [self.unpack("II", optional + directory_start + index * 8)
                            for index in range(directories)]
        table = optional + optional_size
        self.table(table, count, 40, 40)
        if self.header_size < table + count * 40:
            raise ParseError("SizeOfHeaders does not cover section headers")
        self.sections = []
        for index in range(count):
            at = table + index * 40
            name = fixed_name(self.take(at, 8))
            if name.startswith("/"):
                if not name[1:].isdigit() or int(name[1:]) < 4:
                    raise ParseError("Invalid COFF long section-name reference")
                name = self.coff_strings.string(int(name[1:]))
            virtual_size, address, size, offset = self.unpack("IIII", at + 8)
            if size:
                self.take(offset, size)
                if offset < table + count * 40:
                    raise ParseError("Section overlaps headers")
            self.sections.append(Section(name, address, offset, size, virtual_size))
        self.overlay_offset = max([table + count * 40, self.header_size,
                                   *(s.offset + s.size for s in self.sections if s.size)])

    def rva(self, address: int, size: int = 1) -> int:
        choices = []
        if 0 <= address and address + size <= self.header_size:
            choices.append(address)
        for section in self.sections:
            relative = address - section.address
            if 0 <= relative and relative + size <= section.size:
                choices.append(section.offset + relative)
        if len(choices) != 1:
            raise ParseError("Unmapped or ambiguous RVA")
        self.take(choices[0], size)
        return choices[0]

    def rva_string(self, address: int) -> str:
        offset = self.rva(address)
        # Do not let an unterminated name spill into the next section.
        ends = [s.offset + s.size for s in self.sections if s.offset <= offset < s.offset + s.size]
        end = min(ends) if ends else self.header_size
        value = self.string(offset, min(end, offset + 4096))
        if not value:
            raise ParseError("Empty import/export name")
        return value

    def directory(self, index: int) -> tuple[int, int]:
        if index >= len(self.directories):
            return 0, 0
        address, size = self.directories[index]
        if bool(address) != bool(size):
            raise ParseError("Incomplete data directory")
        return address, size

    @cached_property
    def coff_strings(self) -> Reader:
        if not self.coff_offset:
            raise ParseError("Missing COFF symbol table")
        self.table(self.coff_offset, self.coff_count, 18, 18)
        strings_at = self.coff_offset + self.coff_count * 18
        size, = self.unpack("I", strings_at)
        if size < 4:
            raise ParseError("Invalid COFF string table")
        return Reader(self.take(strings_at, size))

    @cached_property
    def static_symbols(self) -> list[Symbol]:
        if not self.coff_offset and not self.coff_count:
            return []
        strings = self.coff_strings
        result, index = [], 0
        while index < self.coff_count:
            at = self.coff_offset + index * 18
            raw, value, section, kind, storage, aux = self.unpack("8sIhHBB", at)
            if index + aux >= self.coff_count:
                raise ParseError("COFF auxiliary records exceed table")
            if raw[:4] == b"\0" * 4:
                offset = struct.unpack("<I", raw[4:])[0]
                name = strings.string(offset) if offset >= 4 else ""
            else:
                name = fixed_name(raw)
            result.append(Symbol(name, value, 0, section, kind))
            index += 1 + aux
        return result

    @cached_property
    def imports(self) -> tuple[list[str], list[str]]:
        if self.directory(13)[0]:
            raise ParseError("Complete imports require a delay-import reader")
        address, size = self.directory(1)
        if not address:
            return [], []
        start = self.rva(address, size)
        libraries, symbols = [], []
        for index in range(min(size // 20, MAX_ENTRIES)):
            original, stamp, chain, name, thunk = self.unpack("IIIII", start + index * 20)
            if not any((original, stamp, chain, name, thunk)):
                return libraries, symbols
            libraries.append(self.rva_string(name))
            pointer, width = original or thunk, self.bits // 8
            if not pointer:
                raise ParseError("Missing import thunk")
            for number in range(MAX_ENTRIES):
                value, = self.unpack("I" if width == 4 else "Q", self.rva(pointer + number * width, width))
                if value == 0:
                    break
                if value & (1 << (self.bits - 1)):
                    symbols.append(f"#{value & 0xffff}")
                else:
                    self.rva(value, 2)
                    symbols.append(self.rva_string(value + 2))
                if len(symbols) > MAX_ENTRIES:
                    raise ParseError("Too many imports")
            else:
                raise ParseError("Unterminated import thunk")
        raise ParseError("Unterminated import directory")

    @cached_property
    def exports(self) -> list[str]:
        address, size = self.directory(0)
        if not address:
            return []
        if size < 40:
            raise ParseError("Truncated export directory")
        start = self.rva(address, 40)
        _, _, _, _, _, base, count, named, functions, names, ordinals = self.unpack("IIHHIIIIIII", start)
        if count > MAX_ENTRIES or named > count:
            raise ParseError("Invalid export counts")
        functions_at = self.rva(functions, count * 4) if count else 0
        names_at = self.rva(names, named * 4) if named else 0
        ordinals_at = self.rva(ordinals, named * 2) if named else 0
        labels: dict[int, list[str]] = {}
        for index in range(named):
            name, = self.unpack("I", names_at + index * 4)
            ordinal, = self.unpack("H", ordinals_at + index * 2)
            if ordinal >= count:
                raise ParseError("Invalid export ordinal")
            labels.setdefault(ordinal, []).append(self.rva_string(name))
        result = []
        for index in range(count):
            target, = self.unpack("I", functions_at + index * 4)
            if target:
                result.extend(labels.get(index, [f"#{base + index}"]))
        return result

    @cached_property
    def resources(self) -> list[Resource]:
        address, size = self.directory(2)
        if not address:
            return []
        root = self.rva(address, size)
        seen: set[int] = set()
        result = []

        def region(relative: int, length: int) -> int:
            if relative < 0 or relative > size - length:
                raise ParseError("Resource reference outside resource directory")
            return root + relative

        def walk(relative: int, path: tuple[str, ...]) -> None:
            if relative in seen or len(path) >= 3 or len(seen) >= MAX_SECTIONS:
                raise ParseError("Cyclic or excessive resource tree")
            seen.add(relative)
            at = region(relative, 16)
            named, ids = self.unpack("HH", at + 12)
            count = named + ids
            if count > MAX_ENTRIES:
                raise ParseError("Too many resource entries")
            entries = region(relative + 16, count * 8)
            for index in range(count):
                name, target = self.unpack("II", entries + index * 8)
                if name & 0x80000000:
                    string_at = name & 0x7fffffff
                    length, = self.unpack("H", region(string_at, 2))
                    label = self.take(region(string_at + 2, length * 2), length * 2).decode("utf-16-le", "strict")
                else:
                    label = str(name)
                next_path = (*path, label)
                if target & 0x80000000:
                    walk(target & 0x7fffffff, next_path)
                else:
                    rva, length, _, _ = self.unpack("IIII", region(target, 16))
                    offset = self.rva(rva, length) if length else 0
                    result.append(Resource(next_path, offset, length))
                    if len(result) > MAX_ENTRIES:
                        raise ParseError("Too many resources")
        walk(0, ())
        return result


class ELF(Reader):
    format = "ELF"

    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF" or len(data) < 16 or data[4] not in (1, 2) or data[5] not in (1, 2) or data[6] != 1:
            raise ParseError("Invalid ELF identity")
        super().__init__(data, "<" if data[5] == 1 else ">")
        self.bits = 32 if data[4] == 1 else 64
        fields = self.unpack("HHIIIIIHHHHHH" if self.bits == 32 else "HHIQQQIHHHHHH", 16)
        self.file_type, machine, version, self.entry, phoff, shoff, _, ehsize, phsize, phnum, shsize, shnum, shstrings = fields
        if version != 1 or ehsize < (52 if self.bits == 32 else 64):
            raise ParseError("Invalid ELF header")
        self.take(0, ehsize)
        self.machine = machine
        self.arch = {3: "x86", 62: "x86_64", 40: "arm", 183: "arm64", 20: "powerpc",
                     21: "powerpc64", 8: "mips", 243: "riscv"}.get(machine)
        expected_bits = {3: 32, 62: 64, 40: 32, 183: 64, 20: 32, 21: 64}.get(machine)
        if expected_bits and expected_bits != self.bits:
            raise ParseError("ELF class and machine disagree")
        section_layout, minimum = ("IIIIIIIIII", 40) if self.bits == 32 else ("IIQQQQIIQQ", 64)
        if shoff:
            self.table(shoff, 1, shsize, minimum)
            zero = self.unpack(section_layout, shoff)
            shnum = shnum or zero[5]
            shstrings = zero[6] if shstrings == 0xffff else shstrings
            phnum = zero[7] if phnum == 0xffff else phnum
        elif shnum or shstrings or phnum == 0xffff:
            raise ParseError("Missing ELF section table")
        if shnum > MAX_SECTIONS:
            raise ParseError("Too many ELF sections")
        raw = []
        if shnum:
            self.table(shoff, shnum, shsize, minimum)
            raw = [self.unpack(section_layout, shoff + index * shsize) for index in range(shnum)]
        strings = b""
        if shstrings:
            if shstrings >= len(raw) or raw[shstrings][1] != 3:
                raise ParseError("Invalid section name table")
            strings = self.take(raw[shstrings][4], raw[shstrings][5])
        self.sections = []
        for name, kind, flags, address, offset, size, link, info, align, entry_size in raw:
            if kind not in (0, 8):  # NULL and NOBITS have no file-backed contents.
                self.take(offset, size)
            if name and not strings:
                raise ParseError("Section name without string table")
            label = Reader(strings).string(name) if name else ""
            self.sections.append(Section(label, address, offset, size if kind != 8 else 0, size, kind, link, entry_size, flags))
        self.has_dynamic_segment = False
        self.segments = []
        if phnum:
            self.table(phoff, phnum, phsize, 32 if self.bits == 32 else 56)
            for index in range(phnum):
                program = self.unpack("IIIIIIII" if self.bits == 32 else "IIQQQQQQ", phoff + index * phsize)
                kind = program[0]
                offset, size = (program[1], program[4]) if self.bits == 32 else (program[2], program[5])
                self.take(offset, size)
                self.segments.append((kind, offset, size))
                self.has_dynamic_segment |= kind == 2

    @cached_property
    def interpreter(self) -> str | None:
        entries = [(at, size) for kind, at, size in self.segments if kind == 3]
        if not entries:
            return None
        if len(entries) != 1:
            raise ParseError("Multiple ELF interpreters")
        at, size = entries[0]
        raw = self.take(at, size)
        if len(raw) < 2 or not raw.endswith(b"\0") or b"\0" in raw[:-1]:
            raise ParseError("Invalid ELF interpreter string")
        return raw[:-1].decode("utf-8")

    @cached_property
    def notes(self) -> list[tuple[str, int, bytes]]:
        # Sections and PT_NOTE may describe the same bytes. Deduplicate ranges,
        # but do not merge different records with identical contents.
        ranges = dict.fromkeys([(s.offset, s.size) for s in self.sections if s.kind == 7]
                               + [(at, size) for kind, at, size in self.segments if kind == 4])
        if sum(size for _, size in ranges) > 16 * 1024 * 1024:
            raise ParseError("ELF note scan exceeds byte bound")
        result, seen, count = [], set(), 0
        for start, size in ranges:
            at, end = start, start + size
            while at < end:
                count += 1
                if at + 12 > end or count > MAX_ENTRIES:
                    raise ParseError("Truncated/excessive ELF notes")
                namesize, descsize, kind = self.unpack("III", at)
                name_at = at + 12
                desc_at = name_at + ((namesize + 3) & ~3)
                next_at = desc_at + ((descsize + 3) & ~3)
                if next_at > end:
                    raise ParseError("ELF note exceeds its range")
                name = self.take(name_at, namesize)
                if namesize and (not name.endswith(b"\0") or b"\0" in name[:-1]):
                    raise ParseError("Invalid ELF note owner")
                record = (name[:-1].decode("utf-8") if namesize else "", kind, self.take(desc_at, descsize))
                if at not in seen:
                    result.append(record)
                    seen.add(at)
                at = next_at
        return result

    @cached_property
    def build_id(self) -> str | None:
        values = [data.hex() for name, kind, data in self.notes if name == "GNU" and kind == 3]
        if len(values) > 1 or values == [""]:
            raise ParseError("No unique nonempty GNU build ID")
        return values[0] if values else None

    def linked_strings(self, section: Section) -> Reader:
        if section.link >= len(self.sections) or self.sections[section.link].kind != 3:
            raise ParseError("Invalid linked ELF string table")
        strings = self.sections[section.link]
        return Reader(self.take(strings.offset, strings.size))

    @cached_property
    def static_symbols(self) -> list[Symbol]:
        return self._read_symbols((2,))

    @cached_property
    def all_symbols(self) -> list[Symbol]:
        return self._read_symbols((2, 11))

    def _read_symbols(self, kinds: tuple[int, ...]) -> list[Symbol]:
        result = []
        width = 16 if self.bits == 32 else 24
        for section in self.sections:
            if section.kind not in kinds:
                continue
            if section.entry_size != width or section.size % width:
                raise ParseError("Invalid ELF static symbol table")
            self.table(section.offset, section.size // width, width, width)
            strings = self.linked_strings(section)
            for at in range(section.offset, section.offset + section.size, width):
                if self.bits == 32:
                    name, value, size, info, other, index = self.unpack("IIIBBH", at)
                else:
                    name, info, other, index, value, size = self.unpack("IBBHQQ", at)
                result.append(Symbol(strings.string(name) if name else "", value, size, index, info & 15))
        return result

    def symbol_bytes(self, symbol: Symbol) -> bytes:
        if not 0 < symbol.section < len(self.sections) or not symbol.size:
            raise ParseError("Symbol has no bounded file-backed definition")
        section = self.sections[symbol.section]
        relative = symbol.value if self.file_type == 1 else symbol.value - section.address
        if relative < 0 or relative + symbol.size > section.size:
            raise ParseError("Symbol extends beyond section")
        return self.take(section.offset + relative, symbol.size)

    @cached_property
    def dynamic_strings(self) -> dict[int, list[str]]:
        tables = [s for s in self.sections if s.kind == 6]
        if not tables and self.has_dynamic_segment:
            raise ParseError("Sectionless dynamic ELF requires a dynamic-segment reader")
        result = {1: [], 14: []}
        width = 8 if self.bits == 32 else 16
        for section in tables:
            if section.entry_size != width or section.size % width:
                raise ParseError("Invalid ELF dynamic table")
            strings = self.linked_strings(section)
            self.table(section.offset, section.size // width, width, width)
            terminated = False
            for offset in range(section.offset, section.offset + section.size, width):
                tag, value = self.unpack("iI" if self.bits == 32 else "qQ", offset)
                if tag == 0:
                    terminated = True
                    break
                if tag in result:
                    result[tag].append(strings.string(value))
            if not terminated:
                raise ParseError("Unterminated dynamic table")
        return result

    @property
    def libraries(self) -> list[str]:
        return self.dynamic_strings[1]

    @property
    def soname(self) -> str | None:
        names = self.dynamic_strings[14]
        if len(names) > 1 or names == [""]:
            raise ParseError("No unique nonempty ELF SONAME")
        return names[0] if names else None

    @cached_property
    def symbols(self) -> tuple[list[str], list[str]]:
        # Dynamic symbols describe externally visible imports/exports. A plain static
        # symbol table does not prove the dynamic interface and is not substituted.
        tables = [s for s in self.sections if s.kind == 11]
        if not tables and self.has_dynamic_segment:
            raise ParseError("No supported dynamic symbol table")
        imports, exports = [], []
        width = 16 if self.bits == 32 else 24
        for section in tables:
            if section.entry_size != width or section.size % width:
                raise ParseError("Invalid ELF symbol table")
            strings = self.linked_strings(section)
            self.table(section.offset, section.size // width, width, width)
            for offset in range(section.offset, section.offset + section.size, width):
                if self.bits == 32:
                    name, _, _, info, other, index = self.unpack("IIIBBH", offset)
                else:
                    name, info, other, index, _, _ = self.unpack("IBBHQQ", offset)
                if name and info >> 4 in (1, 2) and info & 15 in (0, 1, 2, 10):
                    value = strings.string(name)
                    if index == 0:
                        imports.append(value)
                    elif other & 3 in (0, 3):
                        exports.append(value)
        return imports, exports


MACH_MAGICS = {b"\xce\xfa\xed\xfe": ("<", 32), b"\xcf\xfa\xed\xfe": ("<", 64),
               b"\xfe\xed\xfa\xce": (">", 32), b"\xfe\xed\xfa\xcf": (">", 64)}
FAT_MAGICS = {b"\xca\xfe\xba\xbe": (">", 20), b"\xbe\xba\xfe\xca": ("<", 20),
              b"\xca\xfe\xba\xbf": (">", 32), b"\xbf\xba\xfe\xca": ("<", 32)}


class MachO(Reader):
    format = "Mach-O"

    def __init__(self, data: bytes):
        if data[:4] not in MACH_MAGICS:
            raise ParseError("Not thin Mach-O")
        endian, self.bits = MACH_MAGICS[data[:4]]
        super().__init__(data, endian)
        _, cpu, _, _, count, size, _ = self.unpack("IIIIIII", 0)
        header_size = 32 if self.bits == 64 else 28
        self.take(0, header_size)
        self.machine = cpu
        self.arch = {7: "x86", 12: "arm", 18: "powerpc", 0x01000007: "x86_64",
                     0x0100000c: "arm64", 0x01000012: "powerpc64"}.get(cpu)
        if self.arch and bool(cpu & 0x01000000) != (self.bits == 64):
            raise ParseError("Mach-O CPU and header bitness disagree")
        if count > MAX_SECTIONS:
            raise ParseError("Too many Mach-O commands")
        self.take(header_size, size)
        end = header_size + size
        at = header_size
        self.sections, self.libraries = [], []
        self.entry = None  # LC_MAIN stores a file offset, never a virtual address.
        self.symtab = None
        self.has_dynamic_symbols = False
        for _ in range(count):
            cmd, length = self.unpack("II", at)
            if length < 8 or length % 4 or at + length > end:
                raise ParseError("Invalid Mach-O load command")
            if cmd in (1, 0x19):
                is64 = cmd == 0x19
                if is64 != (self.bits == 64):
                    raise ParseError("Segment and header bitness disagree")
                minimum, stride = (72, 80) if is64 else (56, 68)
                if length < minimum:
                    raise ParseError("Truncated segment command")
                segment = self.unpack("16sQQQQiiII" if is64 else "16sIIIIiiII", at + 8)
                fileoff, filesize, nsects = segment[3], segment[4], segment[7]
                self.take(fileoff, filesize)
                if nsects > MAX_SECTIONS or minimum + nsects * stride > length:
                    raise ParseError("Truncated Mach-O section table")
                for index in range(nsects):
                    section_at = at + minimum + index * stride
                    name, owner, address, extent, offset, align, reloc, nreloc, flags = self.unpack(
                        "16s16sQQIIIII" if is64 else "16s16sIIIIIII", section_at)
                    size_on_disk = 0 if flags & 0xff in (1, 0xc, 0x12) else extent
                    if size_on_disk:
                        self.take(offset, size_on_disk)
                    self.sections.append(Section(fixed_name(name), address, offset, size_on_disk, extent))
            elif cmd == 2:
                if length < 24 or self.symtab is not None:
                    raise ParseError("Invalid/duplicate Mach-O symbol table")
                self.symtab = self.unpack("IIII", at + 8)
            elif cmd in (0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023):
                if length < 24:
                    raise ParseError("Truncated dylib command")
                name, = self.unpack("I", at + 8)
                if name < 24 or name >= length:
                    raise ParseError("Invalid dylib name")
                self.libraries.append(self.string(at + name, at + length))
            elif cmd == 0x80000028:
                if length < 24 or self.entry is not None:
                    raise ParseError("Invalid/duplicate LC_MAIN")
                self.entry, _ = self.unpack("QQ", at + 8)
                self.take(self.entry, 1)
            elif cmd in (0x22, 0x80000022, 0x80000033, 0x80000034):
                self.has_dynamic_symbols = True
            at += length
        if at != end:
            raise ParseError("Load-command sizes disagree with header")

    @cached_property
    def symbols(self) -> tuple[list[str], list[str]]:
        if self.has_dynamic_symbols:
            raise ParseError("Complete trie/chained Mach-O symbols are not supported")
        if self.symtab is None:
            return [], []
        offset, count, strings_at, string_size = self.symtab
        width = 12 if self.bits == 32 else 16
        self.table(offset, count, width, width)
        strings = Reader(self.take(strings_at, string_size))
        imports, exports = [], []
        for index in range(count):
            name, kind, section, desc, value = self.unpack("IBBHI" if self.bits == 32 else "IBBHQ", offset + index * width)
            if not name or kind & 0xe0 or not kind & 1:
                continue
            label = strings.string(name)
            if kind & 0xe == 0 and value == 0:
                imports.append(label)
            elif kind & 0xe in (2, 0xe) and not kind & 0x10:
                exports.append(label)
        return imports, exports


Image = PE | ELF | MachO


def parse_images(data: bytes) -> tuple[Image, ...]:
    """Return validated thin images, or all independently validated fat slices."""
    try:
        if data[:2] == b"MZ":
            return (PE(data),)
        if data[:4] == b"\x7fELF":
            return (ELF(data),)
        if data[:4] in MACH_MAGICS:
            return (MachO(data),)
        if data[:4] in FAT_MAGICS:
            endian, stride = FAT_MAGICS[data[:4]]
            reader = Reader(data, endian)
            count, = reader.unpack("I", 4)
            if not count or count > MAX_SECTIONS:
                raise ParseError("Invalid fat slice count")
            reader.table(8, count, stride, stride)
            images, ranges = [], []
            for index in range(count):
                if stride == 20:
                    cpu, _, offset, size, align = reader.unpack("IIIII", 8 + index * stride)
                else:
                    cpu, _, offset, size, align, _ = reader.unpack("IIQQII", 8 + index * stride)
                if not size or offset < 8 + count * stride or align > 63 or offset % (1 << align):
                    raise ParseError("Invalid fat slice range/alignment")
                if any(offset < stop and start < offset + size for start, stop in ranges):
                    raise ParseError("Overlapping fat slices")
                image = MachO(reader.take(offset, size))
                if image.machine != cpu:
                    raise ParseError("Fat CPU does not match slice")
                images.append(image)
                ranges.append((offset, offset + size))
            return tuple(images)
        raise ParseError("Unsupported binary format")
    except (struct.error, UnicodeError, OverflowError) as exc:
        raise ParseError("Malformed binary structure") from exc
