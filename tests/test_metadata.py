"""Metadata Forensics lane: synthetic files only, built here byte by byte."""

import hashlib
from io import BytesIO
import json
from pathlib import Path
import struct
import unittest
import zipfile
import zlib

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


class JarManifestTests(unittest.TestCase):
    def jar(self, manifest):
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            if manifest is not None:
                archive.writestr("META-INF/MANIFEST.MF", manifest)
            archive.writestr("app/Main.class", b"\xca\xfe\xba\xbe")
        return buffer.getvalue()

    def test_main_class_from_the_main_section(self):
        manifest = ("Manifest-Version: 1.0\r\nMain-Class: fixture.example.VeryLongPackageName.Ap\r\n p\r\n"
                    "\r\nName: other/\r\nMain-Class: not.This\r\n")
        self.assertEqual(m.PROPERTIES["jar.main_class"](self.jar(manifest)), "fixture.example.VeryLongPackageName.App")
        self.assertEqual(m.PROPERTIES["jar.main_class"](self.jar("Manifest-Version: 1.0\n")), "none")
        self.assertEqual(m.PROPERTIES["jar.main_class"](self.jar(None)), "none")
        self.assertIsNone(m.PROPERTIES["jar.main_class"](b"not a zip"))


class OrderingTests(unittest.TestCase):
    """Day 23 took the sorted central-directory names and rejected the stored order.

    The parser sorts, because that is what the service accepted. The shapes it did not
    confirm wait as `alternatives`, for a day that wants the names some other way.
    """

    def candidates(self, names):
        drop = zipped([(name, b"x") for name in names])
        bundle = zipped([("evidence-drop-001.zip", drop)])
        question = {"id": "names", "artifact": "evidence.zip -> evidence-drop-001.zip",
                    "question": "Determine zip.central_directory_member_names for evidence-drop-001.zip.",
                    "answer_format": {"kind": "json", "syntax": "compact valid JSON array with exact values and order"}}
        context = SolveContext("metadata-forensics-day-23-x/time_trial", {"lane": "metadata-forensics"},
                               {"answer_ids": ["names"], "questions": [question]}, bundle, Path("x"), ("names",))
        return MetadataSolver().solve(context)

    def test_names_in_directories_offer_the_basename_shapes(self):
        [candidate] = self.candidates(["drop-33/doc-4.csv", "box-28/item-1.csv"])
        self.assertEqual(candidate.answer, '["box-28/item-1.csv","drop-33/doc-4.csv"]')  # Sorted paths.
        self.assertEqual(candidate.alternatives, (
            '["item-1.csv","doc-4.csv"]',  # The basenames of the sorted paths.
            '["doc-4.csv","item-1.csv"]',  # The basenames sorted.
        ))

    def test_flat_names_have_no_other_shape_to_offer(self):
        [candidate] = self.candidates(["z.txt", "a.txt"])
        self.assertEqual(candidate.answer, '["a.txt","z.txt"]')
        self.assertEqual(candidate.alternatives, ())  # No directories, nothing left to vary.


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
        # Day 23: the directory was not in sorted order and only the sorted names were accepted.
        shuffled = zipped([("drop-33/doc-4.csv", b"a"), ("box-28/item-1.csv", b"b"), ("shelf-07/part-4.log", b"c")])
        self.assertEqual(m.zip_central_directory_member_names(shuffled),
                         '["box-28/item-1.csv","drop-33/doc-4.csv","shelf-07/part-4.log"]')
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

    def test_sqlite_page_size(self):
        header = bytearray(b"SQLite format 3\0" + bytes(84))
        header[16:18] = (16384).to_bytes(2, "big")
        self.assertEqual(m.sqlite_page_size_bytes(bytes(header)), "16384")
        header[16:18] = (1).to_bytes(2, "big")  # 1 encodes 65536.
        self.assertEqual(m.sqlite_page_size_bytes(bytes(header)), "65536")
        self.assertIsNone(m.sqlite_page_size_bytes(b"OggS mislabeled as .sqlite"))

    def test_registry_hive_root_name(self):
        # Synthetic regf hive (Day 25): header -> root nk cell, name latin-1 (flags & 0x20).
        def hive(root_name: bytes) -> bytes:
            base = bytearray(0x1000)
            base[:4] = b"regf"
            struct.pack_into("<IIQIIIIIII", base, 4, 7, 7, 0, 1, 5, 0, 1, 0x20, 0x1000, 1)
            checksum = 0
            for (word,) in struct.iter_unpack("<I", bytes(base[:508])):
                checksum ^= word
            struct.pack_into("<I", base, 0x1FC, checksum)
            hbin = bytearray(0x1000)
            hbin[:4] = b"hbin"
            cell = 0x20
            struct.pack_into("<i", hbin, cell, -(0x50 + len(root_name)))
            nk = cell + 4
            hbin[nk:nk + 2] = b"nk"
            struct.pack_into("<HQ", hbin, nk + 2, 0x24, 0)
            struct.pack_into("<I", hbin, nk + 0x14, 3)
            struct.pack_into("<I", hbin, nk + 0x24, 2)
            struct.pack_into("<H", hbin, nk + 0x48, len(root_name))
            hbin[nk + 0x4C:nk + 0x4C + len(root_name)] = root_name
            return bytes(base) + bytes(hbin)

        self.assertEqual(m.registry_hive_root_name(hive(b"HuntressAssemblyLine")), "HuntressAssemblyLine")
        self.assertIsNone(m.registry_hive_root_name(b"not a registry hive at all ...."))

    def test_pcap_packet_count(self):
        # Day 27: classic pcap in both byte orders, a snaplen-truncated record, and pcapng.
        def pcap(order, records, linktype=101):
            magic = b"\xd4\xc3\xb2\xa1" if order == "<" else b"\xa1\xb2\xc3\xd4"
            out = magic + struct.pack(order + "HHiIII", 2, 4, 0, 0, 65535, linktype)
            for captured, original in records:
                out += struct.pack(order + "IIII", 1793793776, 0, captured, original) + b"\x45" * captured
            return out

        three = pcap("<", [(16, 16), (21, 21), (10, 64)])  # the third kept 10 of 64 bytes: still a packet
        self.assertEqual(m.pcap_packet_count(three), "3")
        self.assertEqual(m.pcap_packet_count(pcap(">", [(40, 40)] * 34)), "34")
        self.assertEqual(m.pcap_packet_count(pcap("<", [])), "0")
        # Malformed captures answer nothing: cut short, trailing bytes, captured past original.
        self.assertIsNone(m.pcap_packet_count(three[:-1]))
        self.assertIsNone(m.pcap_packet_count(three + b"\0" * 7))
        self.assertIsNone(m.pcap_packet_count(pcap("<", [(20, 10)])))

        def block(kind, body):
            length = 12 + len(body)
            return struct.pack("<II", kind, length) + body + struct.pack("<I", length)

        shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        idb = block(1, struct.pack("<HHI", 1, 0, 65535))
        epb = block(6, struct.pack("<IIIII", 0, 0, 0, 4, 4) + b"\x45" * 4)
        self.assertEqual(m.pcap_packet_count(shb + idb + epb * 5), "5")
        self.assertIsNone(m.pcap_packet_count(shb + idb + epb[:-4]))
        self.assertIsNone(m.pcap_packet_count(b"not a capture at all ..........."))
        self.assertIn("pcap.packet_count", m.PROPERTIES)
        # Day 28 forecast: header fields with mappings of their own, so a timed race answers them.
        fields = {name: m.PROPERTIES[name] for name in (
            "pcap.version", "pcap.link_type", "pcap.linktype", "pcap.snapshot_length", "pcap.snaplen")}
        for capture, expected in (
            (three, ("2.4", "101", "65535")),
            (pcap(">", [(40, 40)], linktype=1), ("2.4", "1", "65535")),
            (pcap("<", [], linktype=0x10000001), ("2.4", "1", "65535")),  # FCS bits are not the link type
            (shb + idb + epb * 5, ("1.0", "1", "65535")),
        ):
            got = tuple(fields[name](capture) for name in ("pcap.version", "pcap.link_type", "pcap.snapshot_length"))
            self.assertEqual(got, expected)
            self.assertEqual(fields["pcap.linktype"](capture), expected[1])
            self.assertEqual(fields["pcap.snaplen"](capture), expected[2])
        self.assertIsNone(fields["pcap.link_type"](b"not a capture at all ..........."))
        self.assertIsNone(fields["pcap.link_type"](shb))  # No interface block: no link type.

    def test_disk_partition_start_lba_sequence(self):
        # Day 28: a GPT image behind a protective MBR, its backup header, and plain MBR.
        def gpt(starts, sectors=256):
            disk = bytearray(sectors * 512)
            disk[446:462] = struct.pack("<B3sB3sII", 0, b"", 0xEE, b"", 1, sectors - 1)
            disk[510:512] = b"\x55\xaa"
            entries = bytearray(128 * 128)
            for i, start in enumerate(starts):
                entries[i * 128:i * 128 + 16] = b"\x11" * 16
                entries[i * 128 + 32:i * 128 + 48] = struct.pack("<QQ", start, start + 9)
            disk[1024:1024 + len(entries)] = entries
            for lba, other in ((1, sectors - 1), (sectors - 1, 1)):
                header = bytearray(struct.pack("<8sIIII", b"EFI PART", 0x10000, 92, 0, 0))
                header += struct.pack("<QQQQ", lba, other, 34, sectors - 34) + b"\0" * 16
                header += struct.pack("<QIII", 2, 128, 128, zlib.crc32(bytes(entries)))
                header[16:20] = struct.pack("<I", zlib.crc32(bytes(header)))
                disk[lba * 512:lba * 512 + 92] = header
            return disk

        read = m.PROPERTIES["disk.partition_start_lba_sequence"]
        self.assertEqual(read(bytes(gpt([34]))), "[34]")  # not the protective entry's LBA 1
        self.assertEqual(read(bytes(gpt([115, 204, 240]))), "[115,204,240]")
        self.assertEqual(read(bytes(gpt([240, 115]))), "[240,115]")  # table order, not sorted
        damaged = gpt([34, 90])
        damaged[512 + 30] ^= 0xFF  # primary header fails its CRC: the backup header answers
        self.assertEqual(read(bytes(damaged)), "[34,90]")
        damaged[255 * 512 + 30] ^= 0xFF
        self.assertIsNone(read(bytes(damaged)))  # neither header holds
        mbr = bytearray(2048)
        mbr[446:462] = struct.pack("<B3sB3sII", 0x80, b"", 0x07, b"", 2048, 100)
        mbr[462:478] = struct.pack("<B3sB3sII", 0, b"", 0x83, b"", 4096, 100)
        mbr[510:512] = b"\x55\xaa"
        self.assertEqual(read(bytes(mbr)), "[2048,4096]")
        mbr[478 + 4] = 0x05  # an extended chain: answers nothing rather than guess its shape
        self.assertIsNone(read(bytes(mbr)))
        self.assertIsNone(read(b"\0" * 2048))

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
