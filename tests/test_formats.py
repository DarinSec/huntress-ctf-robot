"""Executable format fields and property suggestions: synthetic files built byte by byte."""

import hashlib
from io import BytesIO
import struct
import unittest
import zipfile
import zlib

from huntress_ctf.containers import unwrap
from huntress_ctf.formats import describe, dex, elf, java_class, macho_fields, pe, wasm
from huntress_ctf.suggest import suggest
from huntress_ctf.workspace import render_triage
from test_metadata import tiny_pe

UUID = bytes.fromhex("385db3eb80f92d3768a101bf9a83ea22")


def command(cmd, payload):
    payload += b"\0" * (-(8 + len(payload)) % 8)  # cmdsize includes the padding to 8 bytes.
    return struct.pack("<II", cmd, 8 + len(payload)) + payload


def macho_with_commands():
    dylib = b"/usr/lib/libSystem.B.dylib\0"
    commands = (
        command(0x1B, UUID)
        + command(0x32, struct.pack("<IIII", 1, 0x000E0100, 0x000E0200, 0))
        + command(0xC, struct.pack("<IIII", 24, 2, 0x05470000, 0x00010000) + dylib)
        + command(0x80000028, struct.pack("<QQ", 0x3F40, 0))
    )
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 4, len(commands), 0x200085, 0)
    return header + commands


def tiny_elf():
    interp = b"/lib/ld.so\0"
    names = b"\0.interp\0.shstrtab\0"
    interp_at, names_at = 120, 131
    sections_at = (names_at + len(names) + 7) & ~7
    header = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8 + struct.pack(
        "<HHIQQQIHHHHHH", 3, 0xB7, 1, 0x1000, 64, sections_at, 0, 64, 56, 1, 64, 3, 2)
    phdr = struct.pack("<IIQQQQQQ", 3, 4, interp_at, 0, 0, len(interp), len(interp), 1)
    body = header + phdr + interp + names
    body += b"\0" * (sections_at - len(body))
    section = lambda name, kind, offset, size: struct.pack("<IIQQQQIIQQ", name, kind, 0, 0, offset, size, 0, 0, 1, 0)
    return body + section(0, 0, 0, 0) + section(1, 1, interp_at, len(interp)) + section(9, 3, names_at, len(names))


def tiny_wasm():
    def section(kind, payload):
        return bytes([kind, len(payload)]) + payload
    name = lambda text: bytes([len(text)]) + text.encode()
    return (b"\0asm" + struct.pack("<I", 1)
            + section(1, b"\x01\x60\x00\x00")
            + section(2, b"\x01" + name("env") + name("log") + b"\x00\x00")
            + section(3, b"\x01\x00")
            + section(7, b"\x01" + name("evaluate") + b"\x00\x01")
            + section(0, name("producers") + b"x"))


def tiny_class():
    utf8 = lambda text: b"\x01" + struct.pack(">H", len(text)) + text.encode()
    pool = b"\x07\x00\x02" + utf8("Demo") + b"\x07\x00\x04" + utf8("java/lang/Object")
    return b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 65, 5) + pool + struct.pack(">HHHH", 0x21, 1, 3, 0) + b"\0" * 6


def tiny_dex():
    fields = [0x70 + 8, 0x70, 0x12345678] + [0] * 17
    body = struct.pack("<20I", *fields) + b"\0" * 8
    signature = hashlib.sha1(body).digest()
    checksum = zlib.adler32(signature + body)
    return b"dex\n035\0" + struct.pack("<I", checksum) + signature + body


class FormatTests(unittest.TestCase):
    def test_macho_load_commands(self):
        (label, fields), = describe(macho_with_commands())
        self.assertEqual(label, "macho")
        self.assertEqual(fields["uuid"], "385DB3EB-80F9-2D37-68A1-01BF9A83EA22")
        self.assertEqual((fields["platform_name"], fields["min_os"], fields["sdk"]), ("macos", "14.1.0", "14.2.0"))
        self.assertEqual(fields["dylibs"], ["/usr/lib/libSystem.B.dylib"])
        self.assertEqual(fields["entryoff"], 0x3F40)
        self.assertEqual(fields["load_commands"], ["LC_UUID", "LC_BUILD_VERSION", "LC_LOAD_DYLIB", "LC_MAIN"])
        self.assertIn("MH_PIE", fields["flag_names"])
        self.assertNotIn("damaged", fields)
        self.assertEqual(macho_fields(macho_with_commands())["uuid"], fields["uuid"])
        self.assertIsNone(macho_fields(b"not mach-o"))

    def test_elf_pe_wasm_class_dex(self):
        fields = elf(tiny_elf())
        self.assertEqual((fields["e_type_name"], fields["e_machine_name"], fields["interp"]), ("ET_DYN", "aarch64", "/lib/ld.so"))
        self.assertEqual(fields["sections"], [".interp", ".shstrtab"])
        fields = pe(tiny_pe())
        self.assertEqual((fields["machine_name"], fields["address_of_entry_point"]), ("i386", 0x65BD0))
        self.assertEqual(fields["version_OriginalFilename"], "agent-base.exe")
        fields = wasm(tiny_wasm())
        self.assertEqual(fields["sections"], ["type", "import", "function", "export", "custom"])
        self.assertEqual((fields["imports"], fields["exports"]), (["env.log:func"], ["evaluate:func"]))
        self.assertEqual(fields["custom_sections"], ["producers"])
        fields = java_class(tiny_class())
        self.assertEqual((fields["java_release"], fields["this_class"], fields["super_class"]), ("21", "Demo", "java/lang/Object"))
        fields = dex(tiny_dex())
        self.assertEqual(fields["version"], "035")
        self.assertTrue(fields["checksum_valid"] and fields["signature_valid"])

    def test_damaged_and_unknown_bytes_never_raise(self):
        self.assertIn("damaged", elf(tiny_elf()[:70]))
        self.assertEqual(describe(b"just text"), [])
        self.assertEqual(describe(macho_with_commands()[:40])[0][1].get("damaged")[:12], "load command")


class SuggestTests(unittest.TestCase):
    def test_suggestions_follow_the_suffix_conventions(self):
        self.assertIn("'385DB3EB-80F9-2D37-68A1-01BF9A83EA22'", suggest("macho.uuid", macho_with_commands())[0])
        self.assertIn("'0x0003'", suggest("elf.e_type_u16_hex", tiny_elf())[0])
        self.assertIn("'0x00065bd0'", suggest("pe.address_of_entry_point_rva_hex", tiny_pe())[0])
        self.assertIn("exports", suggest("wasm.export_names_list", tiny_wasm())[0])
        self.assertIn("'14.1.0'", suggest("macho.min_os_version", macho_with_commands())[0])
        self.assertEqual(suggest("elf.e_type_u16_hex", macho_with_commands()), [])  # Other format.
        self.assertIn("cputype = 16777228", suggest("macho.cpu_type_u32_hex", macho_with_commands())[0])

    def test_triage_shows_suggestions_and_fields(self):
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("macos-001.bin", macho_with_commands())
        artifact = buffer.getvalue()
        question = {"id": "q", "question": "Determine macho.uuid for macos-001.bin.",
                    "artifact": "evidence.zip -> macos-001.bin"}
        report = render_triage(artifact, unwrap(artifact).members, questions=[question])
        self.assertIn("suggestion: macho: uuid = '385DB3EB", report)
        self.assertIn("## Format fields (1 images)", report)
        self.assertIn('min_os="14.1.0"', report)


if __name__ == "__main__":
    unittest.main()
