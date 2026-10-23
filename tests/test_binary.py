"""Synthetic executable layouts; no real challenge data or executable code."""
import base64
from io import BytesIO
from pathlib import Path
import struct
import unittest
from unittest.mock import patch
import zipfile

from huntress_ctf.containers import Member
from huntress_ctf.solvers.base import SolveContext
from huntress_ctf.solvers.binary import BinarySolver, architecture, pe_overlay_size, pe_resource_names
from huntress_ctf.solvers.facts import FactSolver
from huntress_ctf.solvers._binary_formats import ELF, MachO, PE, ParseError, parse_images


def pe_fixture(bits=64, overlay=b"tail"):
    data = bytearray(0xa00)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    optional_size = 0xe0 if bits == 32 else 0xf0
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14c if bits == 32 else 0x8664, 1, 0, 0, 0, optional_size, 2)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10b if bits == 32 else 0x20b)
    struct.pack_into("<I", data, optional + 16, 0x1010)
    struct.pack_into("<I" if bits == 32 else "<Q", data, optional + (28 if bits == 32 else 24), 0x400000 if bits == 32 else 0x140000000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    directories = optional + (96 if bits == 32 else 112)
    struct.pack_into("<I", data, directories - 4, 16)
    section = optional + optional_size
    data[section:section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x800, 0x1000, 0x800, 0x200)
    # Import directory, DLL, and a thunk table with named and ordinal imports.
    struct.pack_into("<II", data, directories + 8, 0x1100, 40)
    struct.pack_into("<IIIII", data, 0x300, 0x1180, 0, 0, 0x1160, 0x1180)
    data[0x360:0x36c] = b"fixture.dll\0"
    layout = "<III" if bits == 32 else "<QQQ"
    struct.pack_into(layout, data, 0x380, 0x11c0, (1 << (bits - 1)) | 7, 0)
    data[0x3c2:0x3cc] = b"demo_read\0"
    # Named export plus an ordinal-only export.
    struct.pack_into("<II", data, directories, 0x1200, 0x100)
    struct.pack_into("<IIHHIIIIIII", data, 0x400, 0, 0, 0, 0, 0x1160, 1, 2, 1, 0x1240, 0x1250, 0x1260)
    struct.pack_into("<II", data, 0x440, 0x1010, 0x1020)
    struct.pack_into("<I", data, 0x450, 0x1270)
    struct.pack_into("<H", data, 0x460, 0)
    data[0x470:0x47c] = b"demo_export\0"
    # Resource type/name/language tree with one validated payload.
    struct.pack_into("<II", data, directories + 16, 0x1400, 0x100)
    for at in (0x600, 0x618, 0x630):
        struct.pack_into("<HH", data, at + 12, 0, 1)
    struct.pack_into("<II", data, 0x610, 10, 0x80000018)
    struct.pack_into("<II", data, 0x628, 1, 0x80000030)
    struct.pack_into("<II", data, 0x640, 1033, 0x48)
    struct.pack_into("<IIII", data, 0x648, 0x1500, 8, 0, 0)
    data[0x700:0x708] = b"fixture!"
    return bytes(data) + overlay


def elf_fixture(bits=64, endian="<", machine=None):
    data = bytearray(0x600)
    data[:16] = b"\x7fELF" + bytes((1 if bits == 32 else 2, 1 if endian == "<" else 2, 1)) + b"\0" * 9
    width, ehsize = (40, 52) if bits == 32 else (64, 64)
    machine = machine if machine is not None else 3 if bits == 32 else 62
    header = "HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH"
    struct.pack_into(endian + header, data, 16, 2, machine, 1, 0x401000, 0, 0x400, 0, ehsize, 0, 0, width, 6, 5)
    dynstrings = b"\0libfixture.so\0demo_read\0demo_export\0"
    data[0x180:0x180 + len(dynstrings)] = dynstrings
    names = b"\0.text\0.dynstr\0.dynsym\0.dynamic\0.shstrtab\0"
    data[0x340:0x340 + len(names)] = names
    sym_width, dyn_width = (16, 8) if bits == 32 else (24, 16)
    sections = (
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (names.index(b".text"), 1, 6, 0x401000, 0x100, 0x20, 0, 0, 16, 0),
        (names.index(b".dynstr"), 3, 2, 0, 0x180, len(dynstrings), 0, 0, 1, 0),
        (names.index(b".dynsym"), 11, 2, 0, 0x200, sym_width * 3, 2, 1, 8, sym_width),
        (names.index(b".dynamic"), 6, 2, 0, 0x300, dyn_width * 2, 2, 0, 8, dyn_width),
        (names.index(b".shstrtab"), 3, 0, 0, 0x340, len(names), 0, 0, 1, 0),
    )
    for index, section in enumerate(sections):
        struct.pack_into(endian + ("IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ"), data, 0x400 + index * width, *section)
    for number, symbol, index in ((1, b"demo_read", 0), (2, b"demo_export", 1)):
        name = dynstrings.index(symbol)
        fields = (name, 0, 0, 0x12, 0, index) if bits == 32 else (name, 0x12, 0, index, 0, 0)
        struct.pack_into(endian + ("IIIBBH" if bits == 32 else "IBBHQQ"), data, 0x200 + number * sym_width, *fields)
    struct.pack_into(endian + ("iI" if bits == 32 else "qQ"), data, 0x300, 1, 1)
    return bytes(data)


def macho_fixture(bits=64, endian="<", cpu=None):
    cpu = cpu if cpu is not None else 7 if bits == 32 else 0x01000007
    data = bytearray(0x400)
    header_size = 28 if bits == 32 else 32
    segment_size = 124 if bits == 32 else 152
    library = b"libfixture.dylib\0"
    dylib_size = (24 + len(library) + 7) & ~7
    total = segment_size + 24 + dylib_size + 24
    struct.pack_into(endian + "IIIIIII", data, 0, 0xfeedface if bits == 32 else 0xfeedfacf, cpu, 3, 2, 4, total, 0)
    at = header_size
    struct.pack_into(endian + "II", data, at, 1 if bits == 32 else 0x19, segment_size)
    base = 0x1000 if bits == 32 else 0x100000000
    struct.pack_into(endian + ("16sIIIIiiII" if bits == 32 else "16sQQQQiiII"), data, at + 8,
                     b"__TEXT", base, 0x1000, 0, len(data), 7, 5, 1, 0)
    struct.pack_into(endian + ("16s16sIIIIIII" if bits == 32 else "16s16sQQIIIII"), data, at + (56 if bits == 32 else 72),
                     b"__text", b"__TEXT", base + 0x200, 0x20, 0x200, 4, 0, 0, 0)
    at += segment_size
    strings = b"\0_demo_read\0_demo_export\0"
    struct.pack_into(endian + "IIIIII", data, at, 2, 24, 0x280, 2, 0x2c0, len(strings))
    at += 24
    struct.pack_into(endian + "IIIIII", data, at, 0xc, dylib_size, 24, 0, 0, 0)
    data[at + 24:at + 24 + len(library)] = library
    at += dylib_size
    struct.pack_into(endian + "IIQQ", data, at, 0x80000028, 24, 0x200, 0)
    data[0x2c0:0x2c0 + len(strings)] = strings
    width = 12 if bits == 32 else 16
    for number, name, kind, index, value in ((0, 1, 1, 0, 0), (1, strings.index(b"_demo_export"), 0xf, 1, base + 0x200)):
        struct.pack_into(endian + ("IBBHI" if bits == 32 else "IBBHQ"), data, 0x280 + number * width, name, kind, index, 0, value)
    return bytes(data)


def fat_fixture(fat64=False, endian=">"):
    slices = [macho_fixture(), macho_fixture(cpu=0x0100000c)]
    stride = 32 if fat64 else 20
    data = bytearray(0x100 + sum(len(s) for s in slices))
    struct.pack_into(endian + "II", data, 0, 0xcafebabf if fat64 else 0xcafebabe, 2)
    offset = 0x100
    for index, (cpu, blob) in enumerate(zip((0x01000007, 0x0100000c), slices)):
        values = (cpu, 3, offset, len(blob), 4, 0) if fat64 else (cpu, 3, offset, len(blob), 4)
        struct.pack_into(endian + ("IIQQII" if fat64 else "IIIII"), data, 8 + index * stride, *values)
        data[offset:offset + len(blob)] = blob
        offset += len(blob)
    return bytes(data)


def bundle(**files):
    out = BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return out.getvalue()


def context(data, texts, reference="sample", lane="binary", members=(), attempt=None):
    questions = [dict(id=str(index), question=text, artifact=reference) for index, text in enumerate(texts)]
    return SolveContext("binary-day-synthetic", {"lane": lane}, {**(attempt or {}), "questions": questions},
                        data, Path("synthetic.bin"), tuple(q["id"] for q in questions), members)


def solve(data, *texts, **kwargs):
    return {item.answer_id: item.answer for item in BinarySolver().solve(context(data, texts, **kwargs))}


class BinaryFormatTests(unittest.TestCase):
    def test_pe_32_and_64_tables_and_address_spaces(self):
        for bits in (32, 64):
            with self.subTest(bits=bits):
                image = PE(pe_fixture(bits))
                self.assertEqual(image.bits, bits)
                self.assertEqual(image.imports, (["fixture.dll"], ["demo_read", "#7"]))
                self.assertEqual(image.exports, ["demo_export", "#2"])
                self.assertEqual(image.rva(0x1010), 0x210)
                self.assertEqual(image.resources[0].path, ("10", "1", "1033"))
                self.assertEqual(image.take(image.resources[0].offset, 8), b"fixture!")
                self.assertEqual(pe_overlay_size(image.data), 4)
                self.assertEqual(pe_resource_names(image.data), ["1", "10", "1033"])

    def test_pe_truncation_bad_directories_and_resource_cycles(self):
        for length in (0, 2, 0x3f, 0x90, 0x190, 0x500):
            self.assertIsNone(architecture(pe_fixture()[:length]))
        for offset, value in ((0x98 + 108, 200), (0x610 + 4, 0x80000000), (0x648, 0xfffffff0)):
            data = bytearray(pe_fixture())
            struct.pack_into("<I", data, offset, value)
            self.assertEqual(solve(bytes(data), "Determine pe.resource_paths for sample."), {})
        data = bytearray(pe_fixture())
        struct.pack_into("<I", data, 0x300, 0x10000000)
        self.assertEqual(solve(bytes(data), "List imported function names as JSON."), {})

    def test_valid_absence_and_unsupported_are_different(self):
        data = bytearray(pe_fixture())
        struct.pack_into("<II", data, 0x98 + 112 + 16, 0, 0)
        self.assertEqual(solve(bytes(data), "Determine pe.resource_count for sample."), {"0": "0"})
        self.assertEqual(solve(b"MZ", "Determine pe.resource_count for sample."), {})
        self.assertEqual(solve(bytes(data), "Determine pe.unknown_property for sample."), {})

    def test_elf_32_64_both_byte_orders(self):
        for bits in (32, 64):
            for endian in ("<", ">"):
                with self.subTest(bits=bits, endian=endian):
                    image = ELF(elf_fixture(bits, endian))
                    self.assertEqual(image.entry, 0x401000)
                    self.assertEqual(image.libraries, ["libfixture.so"])
                    self.assertEqual(image.symbols, (["demo_read"], ["demo_export"]))
                    self.assertEqual(image.sections[1].name, ".text")
        self.assertEqual(architecture(elf_fixture(32, ">", 20)), "powerpc")

    def test_elf_extended_count_and_invalid_links(self):
        data = bytearray(elf_fixture())
        struct.pack_into("<H", data, 60, 0)
        struct.pack_into("<Q", data, 0x400 + 32, 6)
        self.assertEqual(len(ELF(bytes(data)).sections), 6)
        struct.pack_into("<I", data, 0x400 + 3 * 64 + 40, 99)
        self.assertEqual(solve(bytes(data), "List imported symbol names as JSON."), {})
        data[5] = 0
        self.assertIsNone(architecture(bytes(data)))

    def test_macho_headers_commands_symbols_and_fat_slices(self):
        for bits in (32, 64):
            for endian in ("<", ">"):
                image = MachO(macho_fixture(bits, endian))
                self.assertEqual(image.entry, 0x200)
                self.assertEqual(image.libraries, ["libfixture.dylib"])
                self.assertEqual(image.symbols, (["_demo_read"], ["_demo_export"]))
                self.assertEqual(image.sections[0].name, "__text")
        for wide in (False, True):
            for endian in ("<", ">"):
                self.assertEqual(architecture(fat_fixture(wide, endian)), "arm64,x86_64")
                self.assertEqual(solve(fat_fixture(wide, endian), "List the architectures as JSON."), {"0": '["arm64","x86_64"]'})
                self.assertEqual(solve(fat_fixture(wide, endian), "What is the architecture?"), {})

    def test_macho_bad_load_command_and_overlapping_fat_slice(self):
        data = bytearray(macho_fixture())
        struct.pack_into("<I", data, 36, 4)
        self.assertIsNone(architecture(bytes(data)))
        data = bytearray(fat_fixture())
        struct.pack_into(">I", data, 8 + 20 + 8, 0x100)
        self.assertIsNone(architecture(bytes(data)))

    def test_partial_dynamic_formats_do_not_report_empty_imports(self):
        pe = bytearray(pe_fixture())
        struct.pack_into("<II", pe, 0x98 + 112 + 13 * 8, 0x1700, 32)
        self.assertEqual(solve(bytes(pe), "List imported function names."), {})
        macho = bytearray(macho_fixture())
        header_end = 32 + 152 + 24 + 48
        struct.pack_into("<I", macho, header_end, 0x80000034)
        self.assertEqual(solve(bytes(macho), "List imported symbol names."), {})
        self.assertEqual(solve(bytes(macho), "List imported library names."), {"0": '["libfixture.dylib"]'})

    def test_truncation_sweep_has_no_unhandled_parser_errors(self):
        for fixture in (pe_fixture(), elf_fixture(), macho_fixture(), fat_fixture()):
            for length in range(0, len(fixture), 37):
                with self.subTest(magic=fixture[:4].hex(), length=length):
                    BinarySolver().solve(context(fixture[:length], ["What is the architecture?", "List imported symbol names."]))


class BinarySolverTests(unittest.TestCase):
    def test_question_directed_header_tables_and_sections(self):
        got = solve(pe_fixture(), "What is the architecture?", "Determine binary.bitness for sample.",
                    "Determine pe.address_of_entry_point_rva_hex for sample.", "List section names as JSON.",
                    "What is the raw size of the '.rdata' section?", "What is the entry point section?",
                    "List imported library names as JSON.", "List exported symbol names as JSON.",
                    "Determine pe.resource_paths for sample.", "Determine pe.overlay_offset_hex for sample.")
        self.assertEqual(got, {"0": "x86_64", "1": "64", "2": "0x00001010", "3": '[".rdata"]',
                               "4": "2048", "5": ".rdata", "6": '["fixture.dll"]',
                               "7": '["demo_export","#2"]', "8": '["10/1/1033"]', "9": "0x00000a00"})
        self.assertEqual(solve(pe_fixture(), 'Submit section names in section-table entry order as JSON.'), {'0':'[".rdata"]'})

    def test_machine_field_answers_the_decimal_code_for_any_architecture(self):
        # The accepted machine-label spelling is grader-defined (Day 22 rejected "x86" for a
        # managed i386 DLL), but the equivalent decimal machine code is accepted for every
        # machine-field question -- so answer the decimal code for any architecture, except i386:
        # Day 23 rejected 332 for the managed F# DLLs (d22/d23) and accepted "i386" for every
        # 0x14c machine field, d03 included (Time Trial and Mastery CORRECT, 23 Oct 2026).
        machine = "Report the processor architecture identified by its executable-header machine field."
        self.assertEqual(solve(pe_fixture(32), machine), {"0": "i386"})      # 0x14c
        self.assertEqual(solve(pe_fixture(64), machine), {"0": "34404"})     # 0x8664
        self.assertEqual(solve(elf_fixture(64), machine), {"0": "62"})       # EM_X86_64
        self.assertEqual(solve(elf_fixture(32, ">", 20), machine), {"0": "20"})  # a PowerPC ELF
        # A plain architecture question (no "machine field") still returns the readable label.
        self.assertEqual(solve(pe_fixture(32), "What is the architecture?"), {"0": "x86"})

    def test_ambiguous_pe_entry_point_and_function_types_are_skipped(self):
        self.assertEqual(solve(pe_fixture(), "What is the entry point?"), {})
        self.assertEqual(solve(elf_fixture(), "List imported function names."), {})
        self.assertEqual(solve(pe_fixture(), "What is the architecture?", lane="script-analysis"), {})
        self.assertEqual(solve(pe_fixture(), "List exported library names."), {})

    def test_value_extractors_do_not_answer_different_question_types(self):
        for question in ("Is this architecture x86_64?", "What is the offset of the architecture string?",
                         "What is the address of the imported function?", "What is the ordinal of the exported function?",
                         "List section names and raw sizes."):
            with self.subTest(question=question):
                self.assertEqual(solve(pe_fixture(), question), {})
        data = b"https://fixture.example.invalid/\0"
        for question in ("What is the offset of the URL?", "How many URL values are present?", "Is there a URL?"):
            self.assertEqual(solve(data, question), {})
        self.assertEqual(solve(fat_fixture(), "How many architectures are present?"), {"0": "2"})

    def test_macho_offset_not_confused_with_virtual_address(self):
        self.assertEqual(solve(macho_fixture(), "Determine macho.entry_point_file_offset_hex for sample."), {"0": "0x0000000000000200"})
        self.assertEqual(solve(macho_fixture(), "What is the entry point virtual address?"), {})
        self.assertEqual(solve(macho_fixture(), "List imported symbol names as JSON."), {"0": '["_demo_read"]'})

    def test_nested_mastery_archives_keep_identical_names_separate(self):
        data = bundle(**{"set1.zip": bundle(**{"sample.exe": pe_fixture(32)}),
                         "set2.zip": bundle(**{"sample.exe": pe_fixture(64)})})
        self.assertEqual(solve(data, "What is the architecture?", reference="set1.zip -> sample.exe"), {"0": "x86"})
        self.assertEqual(solve(data, "What is the architecture?", reference="set2.zip -> sample.exe"), {"0": "x86_64"})
        members = (Member("set1.zip/sample.exe", pe_fixture(32)), Member("set2.zip/sample.exe", pe_fixture(64)))
        self.assertEqual(solve(data, "What is the architecture?", reference="sample.exe", members=members), {})
        self.assertEqual(solve(data, "What is the architecture?", reference="missing.zip -> sample.exe", members=members), {})

    def test_zip_directory_order_and_separate_delivery(self):
        data = bundle(**{"z.txt": b"z", "a.txt": b"a"})
        # Shared with Metadata, where Day 23 accepted only the sorted names (no Binary day has asked it yet).
        self.assertEqual(solve(data, "Determine zip.central_directory_member_names for sample."), {"0": '["a.txt","z.txt"]'})
        attempt = {"artifacts": [{"filename": "first.exe"}, {"filename": "second.exe"}]}
        members = (Member("delivery 2: second.exe", pe_fixture(32)),)
        self.assertEqual(solve(pe_fixture(), "What is the architecture?", reference="delivery 2: second.exe", members=members, attempt=attempt), {"0": "x86"})

    def test_unique_utf16_indicator_and_ambiguity(self):
        url = "https://fixture.example.invalid/path"
        data = b"\0" * 8 + url.encode("utf-16-le") + b"\0\0"
        self.assertEqual(solve(data, "What exact URL is embedded?"), {"0": url})
        ambiguous = data + b"\0https://second.example.invalid/\0"
        self.assertEqual(solve(ambiguous, "What exact URL is embedded?"), {})
        self.assertEqual(FactSolver().solve(context(data, ["What exact URL is embedded?"])), [])

    def test_encoded_string_and_explicit_xor_scope(self):
        data = bytearray(pe_fixture())
        encoded = base64.b64encode(b"answer: synthetic-code-123")
        data[0x220:0x220 + len(encoded)] = encoded
        got = BinarySolver().solve(context(bytes(data), ["Recover the decoded answer from the base64 string in the '.rdata' section."]))
        self.assertEqual([(v.answer_id, v.answer) for v in got], [("0", "synthetic-code-123")])
        self.assertEqual(got[0].chain, ())  # A fragment cannot be replayed on a whole PE.
        source = b"answer: synthetic-code-456"
        raw = bytes(value ^ 0x5a for value in source)
        self.assertEqual(solve(raw, "Recover the decoded answer in the whole file, XOR key 0x5a."), {"0": "synthetic-code-456"})
        self.assertEqual(solve(raw, "Recover the decoded answer, XOR key 0x5a."), {})

    def test_scoped_indicator_ignores_other_regions(self):
        url = b"https://inside.example.invalid/"
        data = bytearray(pe_fixture(overlay=b"https://outside.example.invalid/\0"))
        data[0x220:0x220 + len(url)] = url
        self.assertEqual(solve(bytes(data), "What exact URL is in the '.rdata' section?"), {"0": url.decode()})
        self.assertEqual(solve(bytes(data), "What exact URL is in the overlay?"), {"0": "https://outside.example.invalid/"})

    def test_one_parse_per_file_and_no_network(self):
        with patch("huntress_ctf.solvers.binary.parse_images", wraps=parse_images) as parse, patch("socket.create_connection", side_effect=AssertionError("offline")):
            self.assertEqual(len(solve(pe_fixture(), *["What is the architecture?"] * 100)), 100)
            self.assertEqual(parse.call_count, 1)

    def test_registry_discovers_lane_but_not_private_readers(self):
        from huntress_ctf.solvers import LOAD_ERRORS, SOLVERS
        self.assertEqual(LOAD_ERRORS, [])
        self.assertEqual(sum(s.name == BinarySolver.name for s in SOLVERS), 1)
        self.assertFalse(any(type(s).__module__.endswith("_binary_formats") for s in SOLVERS))

    def test_string_limit_does_not_claim_uniqueness_from_prefix(self):
        with patch("huntress_ctf.solvers.binary.MAX_STRING_BYTES", 16):
            self.assertEqual(solve(b"https://fixture.example.invalid/", "What URL is embedded?"), {})


if __name__ == "__main__":
    unittest.main()
