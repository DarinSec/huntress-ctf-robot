"""Bounded structural reader for core WebAssembly modules and data segments.

Section ordering, LEB widths, vectors, indices and payload bounds are checked.
Function bodies remain opaque after their local declarations; this is a static
container reader, not a WebAssembly execution engine or a full type validator.
Unsupported proposals/constant expressions reject the module rather than being
misread as data. Layouts: webassembly.github.io/spec/core/binary/modules.html.
"""
from ._binary_formats import MAX_ENTRIES, MAX_SECTIONS, ParseError


class Cursor:
    def __init__(self, data: bytes, start=0, end=None):
        self.data, self.at = data, start
        self.end = len(data) if end is None else end

    def take(self, size: int) -> bytes:
        if size < 0 or self.at > self.end - size:
            raise ParseError("WebAssembly field exceeds its section")
        result = self.data[self.at:self.at + size]
        self.at += size
        return result

    def byte(self) -> int:
        return self.take(1)[0]

    def leb(self, bits=32, signed=False) -> int:
        value = 0
        for shift in range(0, bits, 7):
            byte = self.byte()
            value |= (byte & 127) << shift
            if byte < 128:
                width = shift + 7
                if signed and byte & 64:
                    value -= 1 << width
                low, high = (-(1 << (bits - 1)), 1 << (bits - 1)) if signed else (0, 1 << bits)
                if not low <= value < high:
                    raise ParseError("WebAssembly LEB integer overflows")
                return value
        raise ParseError("WebAssembly LEB encoding exceeds width")

    def count(self) -> int:
        value = self.leb()
        if value > MAX_ENTRIES:
            raise ParseError("WebAssembly vector exceeds bound")
        return value

    def name(self) -> str:
        return self.take(self.leb()).decode("utf-8")

    def finish(self):
        if self.at != self.end:
            raise ParseError("Trailing WebAssembly section bytes")


class Wasm:
    def __init__(self, data: bytes):
        if len(data) > 128 * 1024 * 1024 or data[:8] != b"\0asm\x01\0\0\0":
            raise ParseError("Invalid WebAssembly header/version/size")
        self.data_segments: list[tuple[int, bytes]] = []
        self.imports: list[tuple[str, str, str]] = []
        self.exports: list[tuple[str, str, int]] = []
        stream = Cursor(data, 8)
        sections = {}
        order = {kind: rank for rank, kind in enumerate((1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 10, 11), 1)}
        previous, total = 0, 0
        while stream.at < stream.end:
            total += 1
            if total > MAX_SECTIONS:
                raise ParseError("Too many WebAssembly sections")
            kind, size = stream.byte(), stream.leb()
            start = stream.at
            stream.take(size)
            cursor = Cursor(data, start, start + size)
            if kind == 0:
                cursor.name()  # Validate the custom-section name; remaining bytes are opaque.
                continue
            if kind not in order or order[kind] <= previous:
                raise ParseError("Unsupported, duplicated or unordered WebAssembly section")
            previous = order[kind]
            sections[kind] = cursor

        def section(kind, parse):
            cursor = sections.get(kind)
            if cursor is not None:
                parse(cursor)
                cursor.finish()

        def value_type(cursor):
            value = cursor.byte()
            if value not in (0x7f, 0x7e, 0x7d, 0x7c, 0x70, 0x6f):
                raise ParseError("Unsupported WebAssembly value type")
            return value

        types, functions, imported_functions = [], [], []
        tables, memories, globals_ = [], [], []

        def limits(cursor, memory=False):
            flags = cursor.leb()
            if flags not in (0, 1):
                raise ParseError("Unsupported WebAssembly limits (memory64/shared)")
            minimum = cursor.leb()
            maximum = cursor.leb() if flags == 1 else None
            if maximum is not None and maximum < minimum:
                raise ParseError("Inverted WebAssembly limits")
            if memory and (minimum > 65536 or maximum is not None and maximum > 65536):
                raise ParseError("WebAssembly memory32 limit exceeded")
            return minimum, maximum

        def table_type(cursor):
            if cursor.byte() not in (0x70, 0x6f):
                raise ParseError("Unsupported WebAssembly table type")
            return limits(cursor)

        def global_type(cursor):
            kind, mutable = value_type(cursor), cursor.byte()
            if mutable not in (0, 1):
                raise ParseError("Invalid WebAssembly global mutability")
            return kind, mutable

        def expression(cursor):
            opcode = cursor.byte()
            if opcode in (0x41, 0x42):
                cursor.leb(32 if opcode == 0x41 else 64, signed=True)
                kind = 0x7f if opcode == 0x41 else 0x7e
            elif opcode in (0x43, 0x44):
                cursor.take(4 if opcode == 0x43 else 8)
                kind = 0x7d if opcode == 0x43 else 0x7c
            elif opcode == 0x23:
                index = cursor.leb()
                if index >= imported_globals or globals_[index][1]:
                    raise ParseError("Invalid WebAssembly constant global reference")
                kind = globals_[index][0]
            else:
                raise ParseError("Unsupported WebAssembly constant expression")
            if cursor.byte() != 0x0b:
                raise ParseError("Unterminated WebAssembly constant expression")
            return kind

        def parse_types(cursor):
            for _ in range(cursor.count()):
                if cursor.byte() != 0x60:
                    raise ParseError("Unsupported non-function WebAssembly type")
                params = [value_type(cursor) for _ in range(cursor.count())]
                results = [value_type(cursor) for _ in range(cursor.count())]
                types.append((params, results))
        section(1, parse_types)

        def type_index(cursor):
            index = cursor.leb()
            if index >= len(types):
                raise ParseError("Invalid WebAssembly function type index")
            return index

        def imports(cursor):
            for _ in range(cursor.count()):
                module, name = cursor.name(), cursor.name()
                kind = cursor.byte()
                if kind == 0:
                    imported_functions.append(type_index(cursor))
                elif kind == 1:
                    tables.append(table_type(cursor))
                elif kind == 2:
                    memories.append(limits(cursor, memory=True))
                elif kind == 3:
                    globals_.append(global_type(cursor))
                else:
                    raise ParseError("Unsupported WebAssembly import type")
                self.imports.append((module, name, ("function", "table", "memory", "global")[kind]))
        section(2, imports)
        imported_globals = len(globals_)
        section(3, lambda c: functions.extend(type_index(c) for _ in range(c.count())))
        section(4, lambda c: tables.extend(table_type(c) for _ in range(c.count())))
        section(5, lambda c: memories.extend(limits(c, memory=True) for _ in range(c.count())))

        def parse_globals(cursor):
            for _ in range(cursor.count()):
                kind, mutable = global_type(cursor)
                if expression(cursor) != kind:
                    raise ParseError("WebAssembly global initializer type mismatch")
                globals_.append((kind, mutable))
        section(6, parse_globals)
        function_types = imported_functions + functions
        if max(len(tables), len(memories), len(globals_), len(function_types)) > MAX_ENTRIES:
            raise ParseError("WebAssembly index space exceeds bound")

        def exports(cursor):
            names = set()
            for _ in range(cursor.count()):
                name, kind, index = cursor.name(), cursor.byte(), cursor.leb()
                counts = (len(function_types), len(tables), len(memories), len(globals_))
                if name in names or kind >= len(counts) or index >= counts[kind]:
                    raise ParseError("Invalid or duplicate WebAssembly export")
                names.add(name)
                self.exports.append((name, ("function", "table", "memory", "global")[kind], index))
        section(7, exports)

        def start(cursor):
            index = cursor.leb()
            if index >= len(function_types) or types[function_types[index]] != ([], []):
                raise ParseError("Invalid WebAssembly start function")
        section(8, start)

        def elements(cursor):
            # New reference-expression encodings require a separate parser.
            for _ in range(cursor.count()):
                flag = cursor.leb()
                if flag not in (0, 1, 2, 3):
                    raise ParseError("Unsupported WebAssembly element expression")
                if flag in (0, 2):
                    index = cursor.leb() if flag == 2 else 0
                    if index >= len(tables) or expression(cursor) != 0x7f:
                        raise ParseError("Invalid WebAssembly active element")
                if flag and cursor.byte() != 0:
                    raise ParseError("Invalid WebAssembly elemkind")
                for _ in range(cursor.count()):
                    if cursor.leb() >= len(function_types):
                        raise ParseError("Invalid WebAssembly element function index")
        section(9, elements)
        bodies = []

        def code(cursor):
            for _ in range(cursor.count()):
                size = cursor.leb()
                start = cursor.at
                cursor.take(size)
                body = Cursor(data, start, start + size)
                local_total = 0
                for _ in range(body.count()):
                    local_total += body.count()
                    value_type(body)
                if local_total > MAX_ENTRIES or body.at >= body.end or data[body.end - 1] != 0x0b:
                    raise ParseError("Invalid WebAssembly function body framing")
                bodies.append((start, size))
        section(10, code)
        if len(bodies) != len(functions):
            raise ParseError("WebAssembly function/code counts disagree")

        def segments(cursor):
            for _ in range(cursor.count()):
                flag = cursor.leb()
                if flag in (0, 2):
                    index = cursor.leb() if flag == 2 else 0
                    if index >= len(memories) or expression(cursor) != 0x7f:
                        raise ParseError("Invalid WebAssembly active data segment")
                elif flag != 1:
                    raise ParseError("Unsupported WebAssembly data segment flags")
                size = cursor.leb()
                start = cursor.at
                self.data_segments.append((start, cursor.take(size)))
        section(11, segments)

        def data_count(cursor):
            if cursor.leb() != len(self.data_segments):
                raise ParseError("WebAssembly data counts disagree")
        section(12, data_count)
