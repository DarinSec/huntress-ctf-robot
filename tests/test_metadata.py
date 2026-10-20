"""Metadata Forensics lane: synthetic files only, built here byte by byte."""

import hashlib
from io import BytesIO
import json
from pathlib import Path
import struct
import unittest
import zipfile

from huntress_ctf.solvers import SolveContext
from huntress_ctf.solvers import metadata as m
from huntress_ctf.solvers.metadata import MetadataSolver


def zipped(entries):
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return buffer.getvalue()


def box(kind, payload):
    return struct.pack(">I4s", 8 + len(payload), kind) + payload


def tiny_pe(machine=0x14C, entry=0x65BD0, original="agent-base.exe"):
    pe = bytearray(0x200)
    pe[:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x40)
    pe[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", pe, 0x44, machine, 1, 0, 0, 0, 0xE0, 0x102)
    struct.pack_into("<HBBIIIII", pe, 0x58, 0x10B, 0, 0, 0, 0, 0, entry, 0)
    struct.pack_into("<I", pe, 0x58 + 92, 16)  # NumberOfRvaAndSizes
    key = "OriginalFilename\0".encode("utf-16-le")
    value = (original + "\0").encode("utf-16-le")
    record = struct.pack("<HHH", 0, len(original) + 1, 1) + key
    record += b"\0" * ((-(0x180 + len(record))) % 4) + value
    pe[0x180:0x180 + len(record)] = record
    return bytes(pe)


def tiny_lnk(path="C:\\Tools\\collector.exe"):
    header = bytearray(0x4C)
    header[:4] = b"\x4c\0\0\0"
    struct.pack_into("<I", header, 0x14, 0x2)  # HasLinkInfo only
    volume = struct.pack("<IIII", 0x10, 3, 0, 0x10)
    base = path.encode("cp1252") + b"\0"
    header_size = 0x1C
    info_body = volume + base + b"\0"
    info = struct.pack("<IIIIIII", header_size + len(info_body), header_size, 1, header_size, header_size + len(volume), 0,
                       header_size + len(volume) + len(base)) + info_body
    return bytes(header) + info


class FileFactTests(unittest.TestCase):
    def setUp(self):
        self.note = b"Case 3DC121A9A2FA evidence note.\n"
        inner = zipped([("evidence-note.txt", self.note), ("roster.csv", b"host,case\nWS-01,X\n"),
                        ("evidence-note-copy.txt", self.note), ("panel-001.png", b"\x89PNG\r\n\x1a\n" + b"\0" * 8)])
        self.bundle = zipped([("evidence-01.zip", inner), ("solo.zip", zipped([("only-file.txt", b"x")]))])

    def solve(self, questions):
        ids = tuple(q["id"] for q in questions)
        context = SolveContext("metadata-forensics-day-19-x/mastery", {"lane": "metadata-forensics"},
                               {"answer_ids": list(ids), "questions": questions}, self.bundle, Path("x"), ids)
        return {a.answer_id: a.answer for a in MetadataSolver().solve(context)}

    def test_facts_roles_and_digest_order(self):
        files = ["evidence-note.txt", "roster.csv", "panel-001.png"]
        answers = self.solve([
            {"id": "size", "question": "What is its exact size in bytes?", "artifact": "evidence-01.zip -> evidence-note.txt"},
            {"id": "md5", "question": "What is its MD5 digest?", "artifact": "evidence-01.zip -> evidence-note.txt"},
            {"id": "head", "question": "What are the first sixteen bytes as lowercase hexadecimal?", "artifact": "evidence-01.zip -> roster.csv"},
            {"id": "solo", "question": "What is the exact filename of the first evidence note?", "artifact": "solo.zip"},
            {"id": "roster", "question": "What is the exact filename of the roster?", "artifact": "evidence-01.zip"},
            {"id": "copy", "question": "What is the exact filename of the renamed evidence-note copy?", "artifact": "evidence-01.zip"},
            {"id": "first", "question": "What is the exact filename of the first evidence note?", "artifact": "evidence-01.zip"},
            {"id": "order", "question": "Inspect `evidence-note.txt`. Compute the full-file SHA-256 digest of each named file, "
                                        f"then submit a compact JSON array of their filenames in ascending digest order. Files: {json.dumps(files)}",
             "artifact": "evidence-01.zip -> evidence-note.txt"},
        ])
        self.assertEqual(answers["size"], str(len(self.note)))
        self.assertEqual(answers["md5"], hashlib.md5(self.note).hexdigest())
        self.assertEqual(answers["head"], b"host,case\nWS-01,"[:16].hex())
        self.assertEqual(answers["solo"], "only-file.txt")
        self.assertEqual(answers["roster"], "roster.csv")
        self.assertEqual(answers["copy"], "evidence-note-copy.txt")
        self.assertEqual(answers["first"], "evidence-note.txt")
        blobs = {"evidence-note.txt": self.note, "roster.csv": b"host,case\nWS-01,X\n", "panel-001.png": b"\x89PNG\r\n\x1a\n" + b"\0" * 8}
        expected = sorted(files, key=lambda name: hashlib.sha256(blobs[name]).hexdigest())
        self.assertEqual(answers["order"], json.dumps(expected, separators=(",", ":")))

    def test_other_lanes_are_left_alone(self):
        context = SolveContext("warmups-day-01", {"lane": "warmups"}, {"answer_ids": ["a"]}, b"x", Path("x"), ("a",))
        self.assertEqual(MetadataSolver().solve(context), [])


class PropertyTests(unittest.TestCase):
    def test_images_documents_and_text(self):
        jpeg = b"\xff\xd8" + b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\0" + b"\0" * 9 + \
            b"\xff\xc0" + struct.pack(">HBHHB", 11, 8, 146, 257, 1) + b"\x01\x11\x00" + b"\xff\xd9"
        self.assertEqual(m.jpeg_sof_dimensions_pixels(jpeg), "257x146")
        png = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + struct.pack(">IIBBBBB", 269, 153, 8, 2, 0, 0, 0)
        self.assertEqual(m.png_ihdr_dimensions_pixels(png), "269x153")
        self.assertEqual(m.png_ihdr_dimensions_pixels(jpeg), "none")  # A renamed impostor has no IHDR.
        self.assertEqual(m.pdf_header_version(b"%PDF-1.7\n%..."), "1.7")
        self.assertEqual(m.pdf_header_version(b"not a pdf"), "none")
        self.assertEqual(m.text_utf8_bom_present(b"\xef\xbb\xbfhi"), "true")
        self.assertEqual(m.text_utf8_bom_present(b"hi"), "false")

    def test_archives_and_office(self):
        drop = zipped([("room-01/item-1.txt", b"a"), ("room-02/item-1.txt", b"b")])
        self.assertEqual(m.zip_eocd_total_entries(drop), "2")
        self.assertEqual(m.zip_central_directory_member_names(drop), '["room-01/item-1.txt","room-02/item-1.txt"]')
        rels = ('<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId9" Target="https://example.test/evidence/x" TargetMode="External"/>'
                '<Relationship Id="rId10" Target="https://example.test/control" TargetMode="External"/>'
                '<Relationship Id="rId1" Target="styles.xml"/></Relationships>')
        docx = zipped([("word/_rels/document.xml.rels", rels)])
        # Sorted, as the service scored it; internal targets are not listed.
        self.assertEqual(m.ooxml_external_relationship_targets(docx),
                         '["https://example.test/control","https://example.test/evidence/x"]')

    def test_executables_and_shortcuts(self):
        pe = tiny_pe()
        self.assertEqual(m.pe_coff_machine_u16_hex(pe), "0x014c")
        self.assertEqual(m.pe_address_of_entry_point_rva_hex(pe), "0x00065bd0")
        self.assertEqual(m.pe_version_original_filename(pe), "agent-base.exe")
        self.assertEqual(m.pe_coff_machine_u16_hex(b"MZ but nothing else"), "none")
        self.assertEqual(m.dotnet_mvid_guid(pe), "none")  # No CLI header: not .NET.
        elf = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8 + struct.pack("<HH", 2, 0x3E)
        self.assertEqual(m.elf_e_machine_u16_hex(elf), "0x003e")
        self.assertEqual(m.lnk_target_path_windows(tiny_lnk()), "C:\\Tools\\collector.exe")

    def test_mail_and_media(self):
        self.assertEqual(m.email_message_id(b"Message-ID: <a1@example.test>\r\nSubject: x\r\n\r\nbody"), "<a1@example.test>")
        self.assertEqual(m.email_message_id(b"Subject: x\r\n\r\nbody"), "none")
        fmt = struct.pack("<HHIIHH", 1, 1, 44100, 88200, 2, 16)
        wav = b"RIFF" + struct.pack("<I", 36) + b"WAVE" + b"fmt " + struct.pack("<I", 16) + fmt
        self.assertEqual(m.media_primary_audio_codec_name(wav), "pcm_s16le")
        self.assertEqual(m.media_primary_audio_codec_name(b"fLaC...."), "flac")
        entry = box(b"avc1", b"\0" * 6 + struct.pack(">H", 1) + b"\0" * 16 + struct.pack(">HH", 320, 180) + b"\0" * 50)
        stsd = box(b"stsd", struct.pack(">II", 0, 1) + entry)
        hdlr = box(b"hdlr", b"\0" * 8 + b"vide" + b"\0" * 12)
        moov = box(b"moov", box(b"trak", box(b"mdia", hdlr + box(b"minf", box(b"stbl", stsd)))))
        self.assertEqual(m.media_primary_video_dimensions(box(b"ftyp", b"isom\0\0\0\0") + moov), "320x180")

    def test_msi_stream_names_unpack(self):
        alphabet = m._MSI_ALPHABET

        def pack(name):
            units, text = [0x4840], name[1:]
            while len(text) >= 2:
                units.append(0x3800 + alphabet.index(text[0]) + (alphabet.index(text[1]) << 6))
                text = text[2:]
            if text:
                units.append(0x4800 + alphabet.index(text))
            return "".join(map(chr, units))

        for name in ("!_StringPool", "!_StringData", "!Property"):
            self.assertEqual(m._msi_name(pack(name)), name)
        self.assertEqual(m.msi_product_code_guid(b"not a compound file"), "none")


if __name__ == "__main__":
    unittest.main()
