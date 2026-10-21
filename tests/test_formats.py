"""Executable format fields and property suggestions: synthetic files built byte by byte."""

import hashlib
import json
from pathlib import Path
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
        self.assertEqual(describe(b"\x00\x01\x02\xff\xfe"), [])
        self.assertEqual(dict(describe(b"just text"))["text"]["line_count"], 1)
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
        self.assertIn("## Format fields (2 images)", report)  # The ZIP itself, then the Mach-O.
        self.assertIn('min_os="14.1.0"', report)


if __name__ == "__main__":
    unittest.main()


class AutoPropertyTests(unittest.TestCase):
    """A new Metadata property answered without a human (solvers/autoprop.py)."""

    def setUp(self):
        import os
        import tempfile
        from unittest.mock import patch
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = directory.name
        patcher = patch.dict(os.environ, {"HUNTRESS_STATE_DIR": self.state})
        patcher.start()
        self.addCleanup(patcher.stop)
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("macos-001.bin", macho_with_commands())
        self.bundle = buffer.getvalue()

    def solve(self, challenge_id, prop):
        from huntress_ctf.solvers import SolveContext
        from huntress_ctf.solvers.autoprop import AutoPropertySolver
        question = {"id": "q", "question": f"Determine {prop} for macos-001.bin.",
                    "artifact": "metadata-day-21-evidence.zip -> macos-001.bin"}
        bundle = BytesIO()
        with zipfile.ZipFile(bundle, "w") as archive:
            archive.writestr("metadata-day-21-evidence.zip", self.bundle)
        context = SolveContext(challenge_id, {"lane": "metadata-forensics"},
                               {"answer_ids": ["q"], "questions": [question]}, bundle.getvalue(), None, ("q",))
        return AutoPropertySolver().solve(context)

    def test_single_solve_answers_a_clear_new_property_and_records_the_mapping(self):
        found = self.solve("metadata-forensics-day-21-x", "macho.uuid")
        self.assertEqual([(c.answer, c.chain) for c in found],
                         [("385DB3EB-80F9-2D37-68A1-01BF9A83EA22", ("autoprop", "macho.uuid=macho:uuid"))])
        self.assertEqual(self.solve("metadata-forensics-day-21-x", "macho.flags_u32_hex")[0].answer, "0x00200085")

    def test_timed_routes_use_only_confirmed_mappings(self):
        from huntress_ctf.hints import record_hint
        self.assertEqual(self.solve("metadata-forensics-day-21-x/time_trial", "macho.uuid"), [])
        record_hint("metadata-forensics-day-21-x", self.solve("metadata-forensics-day-21-x", "macho.uuid"))
        found = self.solve("metadata-forensics-day-21-x/mastery", "macho.uuid")
        self.assertEqual([c.answer for c in found], ["385DB3EB-80F9-2D37-68A1-01BF9A83EA22"])
        self.assertIn("confirmed", found[0].evidence)

    def test_known_or_unclear_properties_are_left_alone(self):
        self.assertEqual(self.solve("metadata-forensics-day-21-x", "macho.cpu_type_set"), [])  # Has a parser.
        self.assertEqual(self.solve("metadata-forensics-day-21-x", "macho.weird_unrelated_thing"), [])


class OtherFormatTests(unittest.TestCase):
    def fields(self, data, label):
        found = dict(describe(data))
        self.assertIn(label, found)
        self.assertNotIn("damaged", found[label])
        return found[label]

    def test_archives(self):
        import gzip
        import tarfile
        buffer = BytesIO()
        with gzip.GzipFile(filename="report.txt", mode="wb", fileobj=buffer, mtime=1_700_000_000) as stream:
            stream.write(b"hello")
        fields = self.fields(buffer.getvalue(), "gzip")
        self.assertEqual((fields["original_name"], fields["mtime"], fields["isize"]), ("report.txt", 1_700_000_000, 5))
        buffer = BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            info = tarfile.TarInfo("notes/a.txt")
            info.size, info.uid, info.uname, info.mtime = 3, 1001, "analyst", 1_700_000_000
            archive.addfile(info, BytesIO(b"abc"))
        fields = self.fields(buffer.getvalue(), "tar")
        self.assertEqual((fields["first_name"], fields["uid"], fields["uname"], fields["names"]),
                         ("notes/a.txt", 1001, "analyst", ["notes/a.txt"]))
        self.assertEqual(dict(describe(b"7z\xbc\xaf\x27\x1c\x00\x04" + b"\0" * 24))["sevenzip"]["version"], "0.4")
        self.assertEqual(dict(describe(b"Rar!\x1a\x07\x01\x00" + b"\0" * 8))["rar"]["version"], 5)

    def test_sqlite_and_captures(self):
        import os
        import sqlite3
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "db.sqlite")
            connection = sqlite3.connect(path)
            connection.execute("PRAGMA user_version = 42")
            connection.execute("PRAGMA application_id = 1234")
            connection.execute("CREATE TABLE t (x)")
            connection.commit()
            connection.close()
            fields = self.fields(Path(path).read_bytes(), "sqlite")
        self.assertEqual((fields["user_version"], fields["application_id"], fields["text_encoding"]), (42, 1234, "UTF-8"))
        packet = struct.pack("<IIII", 1, 0, 4, 4) + b"abcd"
        pcap = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + packet * 3
        fields = self.fields(pcap, "pcap")
        self.assertEqual((fields["version"], fields["linktype_name"], fields["packet_count"]), ("2.4", "ETHERNET", 3))
        shb = struct.pack("<IIIHHq", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1) + struct.pack("<I", 28)
        idb = struct.pack("<IIHHI", 1, 20, 101, 0, 262144) + struct.pack("<I", 20)
        epb = struct.pack("<IIIIIII", 6, 36, 0, 0, 0, 4, 4) + b"abcd" + struct.pack("<I", 36)
        fields = self.fields(shb + idb + epb + epb, "pcapng")
        self.assertEqual((fields["version"], fields["linktype_name"], fields["packet_count"]), ("1.0", "RAW", 2))

    def test_images_and_iso(self):
        frame = b"\x2c" + struct.pack("<HHHH", 0, 0, 1, 1) + b"\x00" + b"\x02\x02\x44\x01\x00"
        gif = (b"GIF89a" + struct.pack("<HHBBB", 1, 1, 0x80, 0, 0) + b"\0\0\0\xff\xff\xff"
               + b"\x21\xfe\x05hello\x00" + b"\x21\xff\x0bNETSCAPE2.0\x03\x01\x05\x00\x00" + frame + frame + b"\x3b")
        fields = self.fields(gif, "gif")
        self.assertEqual((fields["frames"], fields["comments"], fields["loop_count"], fields["dimensions"]),
                         (2, ["hello"], 5, "1x1"))
        bmp = b"BM" + struct.pack("<I4xII", 70, 54, 40) + struct.pack("<iiHHI", 3, -2, 1, 24, 0) + b"\0" * 32
        fields = self.fields(bmp, "bmp")
        self.assertEqual((fields["dimensions"], fields["bits_per_pixel"], fields["top_down"]), ("3x2", 24, True))
        ico = struct.pack("<HHH", 0, 1, 2) + struct.pack("<BBBBHHII", 16, 16, 0, 0, 1, 32, 0, 0) * 2
        self.assertEqual(self.fields(ico, "ico")["images"], ["16x16@32", "16x16@32"])
        iso = bytearray(0x8000 + 2048)
        iso[0x8001:0x8006] = b"CD001"
        iso[0x8028:0x8028 + 32] = b"EVIDENCE_DISK".ljust(32)
        iso[0x8050:0x8054] = struct.pack("<I", 1234)
        self.assertEqual(self.fields(bytes(iso), "iso")["volume_id"], "EVIDENCE_DISK")

    def test_new_formats_feed_suggestions(self):
        import gzip
        buffer = BytesIO()
        with gzip.GzipFile(filename="report.txt", mode="wb", fileobj=buffer, mtime=0) as stream:
            stream.write(b"x")
        self.assertIn("'report.txt'", suggest("gzip.original_name", buffer.getvalue())[0])


class DocumentFormatTests(unittest.TestCase):
    def fields(self, data, label):
        found = dict(describe(data))
        self.assertIn(label, found)
        self.assertNotIn("damaged", found[label])
        return found[label]

    def test_png_jpeg_pdf(self):
        def chunk(kind, body):
            return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
        png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 7, 5, 8, 6, 0, 0, 0))
               + chunk(b"tIME", struct.pack(">HBBBBB", 2026, 10, 21, 9, 0, 1)) + chunk(b"tEXt", b"Author\0Jane")
               + chunk(b"IDAT", b"x") + chunk(b"IEND", b""))
        fields = self.fields(png, "png")
        self.assertEqual((fields["dimensions"], fields["bit_depth"], fields["color_type_name"]), ("7x5", 8, "truecolor_alpha"))
        self.assertEqual((fields["last_modified"], fields["author"], fields["trailing_bytes"]), ("2026-10-21 09:00:01", "Jane", 0))
        sof = b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, 4, 6, 3) + b"\0" * 3
        jfif = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\0\x01\x02\x01" + struct.pack(">HH", 72, 72) + b"\0\0"
        fields = self.fields(b"\xff\xd8" + jfif + sof + b"\xff\xd9", "jpeg")
        self.assertEqual((fields["dimensions"], fields["jfif_version"], fields["components"]), ("6x4", "1.02", 3))
        pdf = b"%PDF-1.7\n1 0 obj << /Type /Pages /Count 2 >> endobj\n2 0 obj << /Type /Page >> endobj\n3 0 obj << /Type /Page >> endobj\n%%EOF"
        fields = self.fields(pdf, "pdf")
        self.assertEqual((fields["version"], fields["page_count"], fields["object_count"]), ("1.7", 2, 3))

    def test_zip_aliases_and_email(self):
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("a.txt", "x")
            archive.writestr("b/c.txt", "y")
            archive.comment = b"evidence"
        fields = self.fields(buffer.getvalue(), "zip")
        self.assertEqual((fields["total_entries"], fields["member_names"], fields["comment"]), (2, ["a.txt", "b/c.txt"], "evidence"))
        self.assertIn("'[\"a.txt\",\"b/c.txt\"]'", suggest("zip.central_directory_member_names", buffer.getvalue())[0])
        mail = (b"From: Ops <ops@example.test>\r\nTo: you@example.test\r\nSubject: Invoice\r\n"
                b"Message-ID: <abc@example.test>\r\nX-Mailer: Synthetic 1.0\r\n\r\nbody\r\n")
        fields = self.fields(mail, "email")
        self.assertEqual((fields["message_id"], fields["x_mailer"], fields["subject"]), ("<abc@example.test>", "Synthetic 1.0", "Invoice"))


class MediaShortcutTextTests(unittest.TestCase):
    def test_wav_lnk_text(self):
        fmt = struct.pack("<HHIIHH", 1, 2, 44100, 176400, 4, 16)
        wav = b"RIFF" + struct.pack("<I", 36 + 8) + b"WAVE" + b"fmt " + struct.pack("<I", 16) + fmt + b"data" + struct.pack("<I", 8) + b"\0" * 8
        fields = dict(describe(wav))["media_wav"]
        self.assertEqual((fields["codec_name"], fields["channels"], fields["sample_rate"]), ("pcm_s16le", 2, 44100))
        from test_metadata import tiny_lnk
        fields = dict(describe(tiny_lnk()))["lnk"]
        self.assertEqual(fields["target_path"], "C:\\Tools\\collector.exe")
        self.assertIn("'C:\\\\Tools\\\\collector.exe'", suggest("lnk.target_path_windows", tiny_lnk())[0])
        fields = dict(describe(b"\xef\xbb\xbfa,b\r\nc,d\r\n"))["text"]
        self.assertEqual((fields["utf8_bom_present"], fields["line_count"], fields["line_ending"]), (True, 2, "crlf"))
        self.assertIn("'true'", suggest("text.utf8_bom_present", b"\xef\xbb\xbfhello")[0])


def tiny_axml(package="com.example.robot", min_sdk=23):
    """Android binary XML with <manifest package=...><uses-sdk minSdkVersion=.../>."""
    strings = ["manifest", "package", package, "uses-sdk", "minSdkVersion", "", "label"]
    encoded = [struct.pack("<H", len(text)) + text.encode("utf-16-le") + b"\0\0" for text in strings]
    offsets, position = [], 0
    for item in encoded:
        offsets.append(position)
        position += len(item)
    body = b"".join(encoded)
    body += b"\0" * (-len(body) % 4)
    header_size = 28
    pool = struct.pack("<HHIIIIII", 1, header_size, header_size + 4 * len(strings) + len(body),
                       len(strings), 0, 0, header_size + 4 * len(strings), 0) + struct.pack(f"<{len(strings)}I", *offsets) + body
    resources = struct.pack("<HHI", 0x0180, 8, 8 + 4 * 7) + struct.pack("<7I", 0, 0, 0, 0, 0, 0, 0x01010001)

    def element(name, attributes):
        attrs = b"".join(struct.pack("<IIIHxBI", 0xFFFFFFFF, key, raw, 8, kind, value) for key, raw, kind, value in attributes)
        ext = struct.pack("<IIHHHHHH", 0xFFFFFFFF, name, 20, 20, len(attributes), 0, 0, 0)
        return struct.pack("<HHIII", 0x0102, 16, 16 + len(ext) + len(attrs), 1, 0xFFFFFFFF) + ext + attrs
    manifest = element(0, [(1, 2, 0x03, 2), (5, 6 - 6 + 0xFFFFFFFF, 0x10, 7)])  # Unnamed attr: resource id label.
    uses_sdk = element(3, [(4, 0xFFFFFFFF, 0x10, min_sdk)])
    chunks = pool + resources + manifest + uses_sdk
    return struct.pack("<HHI", 3, 8, 8 + len(chunks)) + chunks


class ApkTests(unittest.TestCase):
    def apk(self, manifest):
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("AndroidManifest.xml", manifest)
            archive.writestr("classes.dex", tiny_dex())
        return buffer.getvalue()

    def test_package_name_and_sdk_from_binary_manifest(self):
        from huntress_ctf.formats import apk
        from huntress_ctf.solvers.metadata import apk_package_name
        fields = apk(self.apk(tiny_axml()))
        self.assertEqual((fields["package_name"], fields["min_sdk_version"], fields["dex_files"]),
                         ("com.example.robot", "23", ["classes.dex"]))
        self.assertEqual(apk_package_name(self.apk(tiny_axml("com.huntress.arena.p1"))), "com.huntress.arena.p1")
        self.assertIsNone(apk_package_name(b"not an apk"))
        self.assertEqual(dict(describe(self.apk(tiny_axml())))["apk"]["package_name"], "com.example.robot")


class MobilePuzzleTests(unittest.TestCase):
    def apk(self, codec, data, extra=None):
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("AndroidManifest.xml", tiny_axml())
            archive.writestr("assets/huntress_puzzle.json",
                             '{"schema":"huntress.mobile.puzzle.v1","codec":"%s","data":"%s"}' % (codec, data))
            for name, content in (extra or {}).items():
                archive.writestr(name, content)
        return buffer.getvalue()

    def test_codecs_and_the_answer_shape(self):
        import base64
        from huntress_ctf.solvers.mobile_puzzle import answer_code
        code = "ANS-0123456789ABCDEF"
        self.assertEqual(answer_code(self.apk("reverse", code[::-1])), code)
        self.assertEqual(answer_code(self.apk("base64", base64.b64encode(code.encode()).decode())), code)
        self.assertEqual(answer_code(self.apk("hex", code.encode().hex())), code)
        self.assertEqual(answer_code(self.apk("dynamic", "assets/payload.dex", {"assets/payload.dex": b"\0\x14" + code.encode() + b"\0"})), code)
        self.assertEqual(answer_code(self.apk("reflection", code)), code)
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("assets/huntress_puzzle.json", json.dumps(
                {"codec": "split", "data": "", "parts": ["09EA4B497", "ANS-B", "200528"], "order": [2, 0, 1]}))
        self.assertEqual(answer_code(buffer.getvalue()), "ANS-B20052809EA4B497")
        self.assertIsNone(answer_code(self.apk("reverse", "not-an-answer")))
        self.assertIsNone(answer_code(b"not an apk"))

    def test_solver_answers_each_question_from_its_apk(self):
        from huntress_ctf.solvers import SolveContext
        from huntress_ctf.solvers.mobile_puzzle import MobilePuzzleSolver
        apk = self.apk("reverse", "ANS-0123456789ABCDEF"[::-1])
        question = {"id": "answer", "question": "Submit only the exact backend answer code.", "artifact": "x.apk",
                    "answer_format": {"kind": "pattern", "syntax": "ANS- followed by exactly 16 uppercase hexadecimal characters"}}
        context = SolveContext("mobile-android-day-21-x", {"lane": "mobile-android"},
                               {"answer_ids": ["answer"], "questions": [question]}, apk, None, ("answer",))
        self.assertEqual([c.answer for c in MobilePuzzleSolver().solve(context)], ["ANS-0123456789ABCDEF"])
