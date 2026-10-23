"""Generated public-schema carriers. No event artifacts or accepted answers."""
import hashlib
import json
from dataclasses import replace
import struct
import unittest

from huntress_ctf.solvers.binary import BinarySolver
from huntress_ctf.solvers._binary_formats import PE, ParseError
from huntress_ctf.solvers._binary_payloads import read_overlay
from huntress_ctf.solvers._binary_wasm import Cursor, Wasm
from tests.test_binary import pe_fixture, elf_fixture
from tests.test_binary_assignment import archive_context, config_record


def uleb(value):
    result = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        result.append(byte | (128 if value else 0))
        if not value:
            return bytes(result)


def section(kind, payload):
    return bytes((kind,)) + uleb(len(payload)) + payload


def wasm_fixture(segments, flag=0, custom=b""):
    payload = uleb(len(segments))
    for data in segments:
        payload += uleb(flag)
        if flag in (0, 2):
            payload += (b"\0" if flag == 2 else b"") + b"\x41\0\x0b"
        payload += uleb(len(data)) + data
    return (b"\0asm\x01\0\0\0" + (section(0, b"\x01x" + custom) if custom else b"")
            + section(5, b"\x01\x00\x01") + section(11, payload))


def packed_overlay(payload, k1=29, k2=181):
    packed = bytes((((b ^ k1) << 3) & 255 | ((b ^ k1) >> 5)) ^ k2 for b in payload)
    return (struct.pack("<4sBBBBI", b"PK19", 1, k1, k2, 0, len(packed))
            + hashlib.sha256(payload).digest() + packed)


def resource_overlay(payload, scratch=b"synthetic scratch"):
    return (struct.pack("<4sBBHIHH", b"RS20", 1, 0, 0, len(payload), len(scratch), 0)
            + hashlib.sha256(scratch).digest() + payload + scratch)


PREFIX = "Use all unit-- members in ZIP central-directory order. "
FORMAT = ("Classify final bytes by magic and parsed container: elf for ELF, pe for native PE, "
          "pe_cli for PE with a valid CLR/CLI header and metadata root, jar for a ZIP/JAR "
          "with classfiles, wasm for a valid WebAssembly module, or neko_bytecode for "
          "NEKO bytecode. Submit exactly one listed lowercase token.")
FIELD = "Submit the exact string value of the decoded HCFG JSON object's top-level domain property."


class BinaryPayloadTests(unittest.TestCase):
    def solve(self, data, prompts, timed=False):
        ctx = archive_context({"unit--sample.bin": data}, [("unit_analysis_" + k, PREFIX + text) for k, text in prompts])
        if timed:
            ctx = replace(ctx, attempt={**ctx.attempt, "run_for_time": True, "deadline": "2026-10-24T13:01:00Z"})
        return {c.answer_id.removeprefix("unit_analysis_"): c.answer for c in BinarySolver().solve(ctx)}

    def test_coff_long_section_names_resolve_bounded_string_table(self):
        data = bytearray(pe_fixture())
        name = b".synthetic_long_section\0"
        table = len(data)
        struct.pack_into("<II", data, 0x8c, table, 0)
        at = 0x98 + 0xf0
        data[at:at + 8] = b"/4\0\0\0\0\0\0"
        data += struct.pack("<I", 4 + len(name)) + name
        self.assertEqual(PE(bytes(data)).sections[0].name, name[:-1].decode())
        got = self.solve(bytes(data), [("sections", "Submit every section name in section-header-table index order as a JSON string array.")])
        self.assertEqual(got, {"sections": json.dumps([name[:-1].decode()], separators=(",", ":"))})
        for bad in (b"/3", b"/999999", b"/bad"):
            with self.subTest(bad=bad):
                damaged = data.copy()
                damaged[at:at + 8] = bad.ljust(8, b"\0")
                with self.assertRaises(ParseError):
                    PE(bytes(damaged))
        struct.pack_into("<II", data, 0x8c, 0, 0)
        with self.assertRaises(ParseError):
            PE(bytes(data))

    def test_explicit_format_tokens_and_architecture_do_not_change_generic_names(self):
        arch = "Report x86-64 for an ELF/PE machine field identifying AMD64, or wasm32 for a WebAssembly module."
        for blob, token in ((pe_fixture(), "pe"), (elf_fixture(), "elf"), (wasm_fixture([]), "wasm")):
            with self.subTest(token=token):
                self.assertEqual(self.solve(blob, [("format", FORMAT), ("arch", arch)]),
                                 {"format": token, "arch": "wasm32" if token == "wasm" else "x86-64"})
        self.assertNotIn("arch", self.solve(pe_fixture(32), [("arch", arch)]))
        self.assertEqual(self.solve(b"\0asm\x02\0\0\0", [("format", FORMAT)]), {})
        self.assertEqual(self.solve(b"NEKO", [("format", FORMAT)]), {})

    def test_case_sensitive_section_predicate_and_order(self):
        blob = bytearray(pe_fixture())
        at = 0x98 + 0xf0
        predicate = "Evaluate this public predicate: true exactly when any parsed executable section name contains the lowercase substring hcfg."
        for name, expected in ((b".hcfg", "true"), (b"xhcfg_y", "true"), (b".HCFG", "false")):
            blob[at:at + 8] = name.ljust(8, b"\0")
            self.assertEqual(self.solve(bytes(blob), [("present", predicate)]), {"present": expected})
        got = self.solve(elf_fixture(), [("sections", "Submit every section name in section-header-table index order as a JSON string array.")])
        self.assertEqual(json.loads(got["sections"]), ["", ".text", ".dynstr", ".dynsym", ".dynamic", ".shstrtab"])

    def test_exact_elf_section_predicate_does_not_return_a_name_list(self):
        predicate = "Evaluate this public predicate and submit lowercase true or false: true exactly when the parsed ELF section names contain .hcfg."
        data = bytearray(elf_fixture())
        self.assertEqual(self.solve(bytes(data), [("present", predicate)]), {"present": "false"})
        start = data.index(b".text\0")
        data[start:start + 5] = b".hcfg"
        self.assertEqual(self.solve(bytes(data), [("present", predicate)]), {"present": "true"})
        self.assertEqual(self.solve(bytes(data), [("unknown", "Submit true exactly when any executable section name starts .hcfg.")]), {})

    def test_packed_overlay_keys_hash_lengths_and_public_routing(self):
        payload = config_record()
        for k1, k2 in ((0, 0), (255, 255), (29, 181)):
            with self.subTest(keys=(k1, k2)):
                blob = elf_fixture() + packed_overlay(payload, k1, k2)
                node = read_overlay(blob, b"PK19")
                self.assertEqual((node.offset, node.payload), (len(elf_fixture()), payload))
        rule = "Find the final PK19 overlay. Read k1 at +5, k2 at +6 and packed length at +8. Verify unpacked SHA-256 and use HCFG at offset 0. "
        prompts = [("domain", rule + FIELD),
                   ("offset", "Locate the final overlay magic named by this unit (PK19 or RS20) and submit its zero-based byte offset."),
                   ("size", "Submit the member byte length minus the located overlay magic's zero-based offset.")]
        blob = elf_fixture() + packed_overlay(payload)
        self.assertEqual(self.solve(blob, prompts), {"domain": "example.invalid", "offset": str(len(elf_fixture())), "size": str(44 + len(payload))})
        for changed in (blob[:-1], blob + b"tail", blob + b"PK19", blob[:-1] + bytes((blob[-1] ^ 1,))):
            with self.subTest(size=len(changed)):
                self.assertEqual(self.solve(changed, prompts), {})
        for at in (len(elf_fixture()) + 5, len(elf_fixture()) + 12):
            damaged = bytearray(blob)
            damaged[at] ^= 1
            with self.assertRaises(ParseError):
                read_overlay(bytes(damaged), b"PK19")

    def test_resource_overlay_scratch_hash_exact_bounds_and_hcfg_crc(self):
        payload = config_record()
        rule = "Find the final RS20 overlay. Verify exact end bounds and scratch SHA-256, then use the HCFG resource at offset 0. "
        prompts = [("domain", rule + FIELD), ("resource_size", "In the final RS20 resource overlay, read the HCFG resource size field and submit it in base 10.")]
        blob = pe_fixture() + resource_overlay(payload)
        self.assertEqual(self.solve(blob, prompts), {"domain": "example.invalid", "resource_size": str(len(payload))})
        for changed in (blob[:-1], blob + b"x", blob[:-1] + bytes((blob[-1] ^ 1,))):
            with self.subTest(size=len(changed)):
                self.assertEqual(self.solve(changed, prompts), {})
        damaged = bytearray(payload)
        damaged[8] ^= 1
        self.assertNotIn("domain", self.solve(pe_fixture() + resource_overlay(bytes(damaged)), prompts))
        with self.assertRaises(ParseError):
            read_overlay(b"PK19" + bytes(4) + struct.pack("<I", 0xffffffff) + bytes(32), b"PK19")
        with self.assertRaises(ParseError):
            read_overlay(blob, b"unknown")

    def test_overlay_schema_must_be_unique_in_public_family(self):
        blob = pe_fixture() + resource_overlay(config_record())
        # A timed race keeps to the public schema; untimed, the one CRC-valid record is found anyway.
        self.assertEqual(self.solve(blob, [("domain", FIELD)], timed=True), {})
        self.assertEqual(self.solve(blob, [("domain", FIELD)]), {"domain": "example.invalid"})
        self.assertEqual(self.solve(blob, [("domain", "Find the final PK19 overlay. " + FIELD),
                                           ("other", "Find the final RS20 overlay. " + FIELD)]), {})


class WasmTests(unittest.TestCase):
    def test_leb_widths_sign_extension_and_valid_padding(self):
        for raw, expected in ((b"\x7f", 127), (b"\x80\x00", 0), (b"\xff\xff\xff\xff\x0f", 0xffffffff)):
            self.assertEqual(Cursor(raw).leb(), expected)
        for raw, expected in ((b"\x7f", -1), (b"\x80\x80\x80\x80\x78", -(1 << 31)), (b"\xff\xff\xff\xff\x07", (1 << 31) - 1)):
            self.assertEqual(Cursor(raw).leb(signed=True), expected)
        for raw, signed in ((b"\x80", False), (b"\x80" * 5 + b"\0", False), (b"\xff" * 4 + b"\x10", False), (b"\xff" * 4 + b"\x0f", True)):
            with self.subTest(raw=raw, signed=signed), self.assertRaises(ParseError):
                Cursor(raw).leb(signed=signed)

    def test_data_flags_scope_and_unique_hcfg(self):
        record = config_record()
        for flag in (0, 1, 2):
            blob = wasm_fixture([b"padding", record], flag, custom=record)
            parsed = Wasm(blob)
            self.assertEqual([b for _, b in parsed.data_segments], [b"padding", record])
            for offset, data in parsed.data_segments:
                self.assertEqual(blob[offset:offset + len(data)], data)
            rule = "Parse the WebAssembly section stream and inspect data-section payload bytes for the CRC32-valid literal HCFG JSON record. "
            solver = BinaryPayloadTests()
            self.assertEqual(solver.solve(blob, [("domain", rule + FIELD)]), {"domain": "example.invalid"})
            for ambiguous in ([record, record], [record[:10], record[10:]], [b"nothing"]):
                self.assertEqual(solver.solve(wasm_fixture(ambiguous, custom=record), [("domain", rule + FIELD)]), {})

    def test_sections_order_duplicates_counts_and_truncation(self):
        base = b"\0asm\x01\0\0\0"
        data = wasm_fixture([config_record()])
        for damaged in (data[:-1], data[:7], base + b"\x0b\xff\xff\xff\xff\x0f", base + section(99, b""),
                        data + section(5, b"\0"), data + section(11, b"\0"),
                        base + section(12, b"\x02") + section(11, b"\0"),
                        base + section(5, b"\x01\x01\x02\x01"),
                        base + section(5, b"\x01\x04\x00"),
                        base + section(11, b"\x01\x00\x41\x00\x0b\x00"),
                        base + section(11, b"\x01\x03\x00")):
            with self.subTest(damaged=damaged[:20]), self.assertRaises(ParseError):
                Wasm(damaged)
        self.assertEqual(Wasm(base + section(12, b"\0") + section(11, b"\0")).data_segments, [])
        Wasm(base + section(0, b"\x01a") + section(0, b"\x01a"))

    def test_function_and_export_indices_and_padded_code_length(self):
        base = b"\0asm\x01\0\0\0"
        types = section(1, b"\x01\x60\x00\x00")
        functions = section(3, b"\x01\x00")
        exports = section(7, b"\x01\x01f\x00\x00")
        code = section(10, b"\x01\x82\x80\x80\x80\x00\x00\x0b")
        Wasm(base + types + functions + exports + code)
        for damaged in (base + types + functions, base + types + code,
                        base + functions + code,
                        base + types + functions + section(7, b"\x01\x01f\x00\x01") + code,
                        base + types + functions + section(10, b"\x01\x02\x00\x00"),
                        base + types + functions + code + b"x"):
            with self.subTest(size=len(damaged)), self.assertRaises(ParseError):
                Wasm(damaged)

    def test_const_expression_cannot_bleed_into_data_or_use_mutable_global(self):
        base = b"\0asm\x01\0\0\0"
        memory = section(5, b"\x01\x00\x01")
        for expression in (b"\x41\0", b"\x42\0\x0b", b"\x23\0\x0b", b"\x41\x80\x80\x80\x80\x80\0\x0b"):
            damaged = base + memory + section(11, b"\x01\x00" + expression + b"\x00")
            with self.subTest(expression=expression), self.assertRaises(ParseError):
                Wasm(damaged)
        # env.g: imported immutable i32, usable as a data offset.
        imports = section(2, b"\x01\x03env\x01g\x03\x7f\x00")
        payload = section(11, b"\x01\x00\x23\x00\x0b\x01x")
        self.assertEqual(Wasm(base + imports + memory + payload).data_segments[-1][1], b"x")
        mutable = section(2, b"\x01\x03env\x01g\x03\x7f\x01")
        with self.assertRaises(ParseError):
            Wasm(base + mutable + memory + payload)
