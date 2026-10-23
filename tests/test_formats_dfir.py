"""Synthetic files for formats_dfir.py: header fields of formats no Metadata day has used yet.

Where the standard library writes the format (plistlib, lzma, bz2) the parser is checked
against that writer; the others are built from their published layouts.
"""

import bz2
import lzma
import plistlib
import struct
import unittest

from huntress_ctf.formats import describe
from huntress_ctf.formats_dfir import formats
from huntress_ctf.suggest import confident


def fields(data, label):
    found = dict(formats(data))
    if label not in found:
        raise AssertionError(f"{label} not recognized: {list(found)}")
    if "damaged" in found[label]:
        raise AssertionError(found[label]["damaged"])
    return found[label]


def filetime(year=2026, month=10, day=1):
    from datetime import datetime, timezone
    delta = datetime(year, month, day, tzinfo=timezone.utc) - datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int(delta.total_seconds()) * 10_000_000


def evtx():
    header = bytearray(4096)
    header[:8] = b"ElfFile\0"
    struct.pack_into("<QQQIHHHH", header, 8, 0, 1, 61, 128, 2, 3, 4096, 2)
    struct.pack_into("<I", header, 0x78, 1)
    chunks = b""
    for first, last in ((1, 40), (41, 60)):
        chunk = bytearray(0x10000)
        chunk[:8] = b"ElfChnk\0"
        struct.pack_into("<QQQQ", chunk, 8, first, last, first, last)
        chunks += chunk
    return bytes(header) + chunks


def regf():
    base = bytearray(0x1000)
    base[:4] = b"regf"
    struct.pack_into("<IIQIIIIIII", base, 4, 7, 7, filetime(), 1, 5, 0, 1, 0x20, 0x1000, 1)
    base[0x30:0x30 + 30] = "\\??\\C:\\Users\\a\\NTUSER.DAT".encode("utf-16-le")[:30]
    checksum = 0
    for (word,) in struct.iter_unpack("<I", bytes(base[:508])):
        checksum ^= word
    struct.pack_into("<I", base, 0x1FC, checksum)
    hbin = bytearray(0x1000)
    hbin[:4] = b"hbin"
    cell = 0x20
    name = b"ROOT"
    struct.pack_into("<i", hbin, cell, -(0x50 + len(name)))
    nk = cell + 4
    hbin[nk:nk + 2] = b"nk"
    struct.pack_into("<HQ", hbin, nk + 2, 0x24, filetime())
    struct.pack_into("<I", hbin, nk + 0x14, 3)
    struct.pack_into("<I", hbin, nk + 0x24, 2)
    struct.pack_into("<H", hbin, nk + 0x48, len(name))
    hbin[nk + 0x4C:nk + 0x4C + len(name)] = name
    return bytes(base) + bytes(hbin)


def prefetch(version=30):
    data = bytearray(0x200)
    struct.pack_into("<I4sI", data, 0, version, b"SCCA", len(data))
    data[0x10:0x10 + 22] = "CMD.EXE".encode("utf-16-le") + bytes(8)
    struct.pack_into("<I", data, 0x4C, 0x0A1B2C3D)
    struct.pack_into("<Q", data, 0x80, filetime())
    struct.pack_into("<I", data, 0xD0, 9)
    return bytes(data)


def tiff():
    entries = [(256, 4, 1, 640), (257, 4, 1, 480), (271, 2, 6, None)]
    ifd = struct.pack("<H", len(entries))
    strings_at = 8 + 2 + 12 * len(entries) + 4
    for tag, kind, count, value in entries:
        raw = struct.pack("<I", value) if value is not None else struct.pack("<I", strings_at)
        ifd += struct.pack("<HHI", tag, kind, count) + raw
    return b"II*\0" + struct.pack("<I", 8) + ifd + b"\0\0\0\0" + b"Canon\0"


def cfb(streams):
    """A minimal OLE2 file: 512-byte sectors, each stream padded to 4096 so no mini stream is needed."""
    sector, end, free = 512, 0xFFFFFFFE, 0xFFFFFFFF
    fat = [0xFFFFFFFD, end]
    body = b""
    starts = []
    for _, data in streams:
        data = data.ljust(4096, b"\0")
        first = len(fat)
        count = len(data) // sector
        fat += [first + i + 1 for i in range(count - 1)] + [end]
        starts.append((first, len(data)))
        body += data
    fat += [free] * (sector // 4 - len(fat))

    def entry(name, kind, child=free, right=free, start=end, size=0):
        raw = name.encode("utf-16-le") + b"\0\0"
        return (raw.ljust(64, b"\0") + struct.pack("<HBB", len(raw), kind, 1) + struct.pack("<III", free, right, child)
                + bytes(16 + 4 + 16) + struct.pack("<IQ", start, size))

    directory = entry("Root Entry", 5, child=1)
    for index, ((name, _), (start, size)) in enumerate(zip(streams, starts), 1):
        directory += entry(name, 2, right=index + 1 if index < len(streams) else free, start=start, size=size)
    directory = directory.ljust(sector, b"\0")
    header = bytearray(512)
    header[:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HHHHH", header, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<IIIIIIII", header, 0x2C, 1, 1, 0, 4096, end, 0, end, 0)
    struct.pack_into("<I", header, 0x4C, 0)
    for index in range(1, 109):
        struct.pack_into("<I", header, 0x4C + 4 * index, free)
    return bytes(header) + struct.pack(f"<{sector // 4}I", *fat) + directory + body


def summary_information(title, author, application):
    props = [(1, struct.pack("<HHH2x", 2, 0, 1252))]
    for pid, text in ((2, title), (4, author), (18, application)):
        raw = text.encode("cp1252") + b"\0"
        props.append((pid, struct.pack("<HHI", 0x1E, 0, len(raw)) + raw.ljust((len(raw) + 3) // 4 * 4, b"\0")))
    props.append((12, struct.pack("<HHQ", 0x40, 0, filetime())))
    table = b""
    values = b""
    offset = 8 + 8 * len(props)
    for pid, value in props:
        table += struct.pack("<II", pid, offset + len(values))
        values += value
    section = struct.pack("<II", 8 + len(table) + len(values), len(props)) + table + values
    fmtid = bytes.fromhex("e0859ff2f94f6810ab9108002b27b3d9")
    return struct.pack("<HHI16sI", 0xFFFE, 0, 0, bytes(16), 1) + fmtid + struct.pack("<I", 48) + section


class DfirFormatTests(unittest.TestCase):
    def test_event_log(self):
        f = fields(evtx(), "evtx")
        self.assertEqual((f["version"], f["chunk_count"], f["chunks_present"], f["next_record_id"]), ("3.2", 2, 2, 61))
        self.assertEqual((f["record_count"], f["first_record_id"], f["last_record_id"], f["dirty"]), (60, 1, 60, True))

    def test_registry_hive(self):
        f = fields(regf(), "regf")
        self.assertEqual((f["version"], f["dirty"], f["checksum_valid"], f["root_key_name"]), ("1.5", False, True, "ROOT"))
        self.assertEqual((f["root_subkey_count"], f["root_value_count"]), (3, 2))
        self.assertEqual(f["last_written_utc"], "2026-10-01T00:00:00Z")

    def test_prefetch(self):
        f = fields(prefetch(), "prefetch")
        self.assertEqual((f["executable_name"], f["prefetch_hash_hex"], f["run_count"]), ("CMD.EXE", "0A1B2C3D", 9))
        self.assertEqual(f["last_run_utc"], "2026-10-01T00:00:00Z")
        compressed = fields(b"MAM\x04" + struct.pack("<I", 4096) + bytes(32), "prefetch")
        self.assertEqual((compressed["compressed"], compressed["uncompressed_size"]), (True, 4096))

    def test_property_lists_from_plistlib(self):
        value = {"Label": "com.example.agent", "ProgramArguments": ["/usr/bin/true", "-x"], "RunAtLoad": True}
        binary = fields(plistlib.dumps(value, fmt=plistlib.FMT_BINARY), "plist")
        self.assertEqual((binary["format"], binary["Label"], binary["keys"]),
                         ("binary", "com.example.agent", ["Label", "ProgramArguments", "RunAtLoad"]))
        self.assertEqual(binary["object_count"], 9)  # dict, 3 keys, 3 values, 2 array items
        xml = fields(plistlib.dumps(value), "plist")
        self.assertEqual((xml["format"], xml["ProgramArguments"]), ("xml", ["/usr/bin/true", "-x"]))

    def test_images_and_video(self):
        vp8x = b"RIFF" + struct.pack("<I", 22) + b"WEBPVP8X" + struct.pack("<I", 10) + bytes([0x10, 0, 0, 0]) \
            + (319).to_bytes(3, "little") + (239).to_bytes(3, "little")
        f = fields(vp8x, "webp")
        self.assertEqual((f["dimensions"], f["has_alpha"], f["animated"]), ("320x240", True, False))
        lossless = (99 | (49 << 14)).to_bytes(4, "little")
        f = fields(b"RIFF" + struct.pack("<I", 21) + b"WEBPVP8L" + struct.pack("<I", 5) + b"\x2f" + lossless, "webp")
        self.assertEqual(f["dimensions"], "100x50")
        f = fields(tiff(), "tiff")
        self.assertEqual((f["dimensions"], f["make"], f["byte_order"]), ("640x480", "Canon", "little"))
        doc_type = b"\x42\x82\x84webm" + b"\x42\x87\x81\x04"
        f = fields(b"\x1a\x45\xdf\xa3" + bytes([0x80 | len(doc_type)]) + doc_type, "ebml")
        self.assertEqual((f["doc_type"], f["doc_type_version"], f["container"]), ("webm", 4, "webm"))
        avih = b"avih" + struct.pack("<I", 56) + struct.pack("<10I", 40000, 0, 0, 0, 250, 0, 2, 0, 1280, 720) + bytes(16)
        strh = b"strh" + struct.pack("<I", 56) + b"vidsH264" + bytes(48)
        f = fields(b"RIFF" + struct.pack("<I", 200) + b"AVI LIST" + struct.pack("<I", 180) + b"hdrl" + avih + strh, "avi")
        self.assertEqual((f["dimensions"], f["frame_rate"], f["total_frames"], f["video_fourcc"]), ("1280x720", 25.0, 250, "H264"))

    def test_disks(self):
        footer = bytearray(512)
        footer[:8] = b"conectix"
        struct.pack_into(">IIQI4sI4sQQIII", footer, 8, 2, 0x10000, 0xFFFFFFFFFFFFFFFF, 0, b"win ", 0xA0000,
                         b"Wi2k", 1 << 30, 1 << 30, (2080 << 16) | (16 << 8) | 63, 2, 0)
        f = fields(bytes(4096) + bytes(footer), "vhd")
        self.assertEqual((f["disk_type_name"], f["creator_application"], f["current_size"], f["timestamp_utc"]),
                         ("fixed", "win", 1 << 30, "2000-01-01T00:00:00Z"))
        self.assertEqual(f["disk_geometry"], "2080/16/63")
        vhdx = b"vhdxfile" + "Microsoft Windows 10.0.19045.0".encode("utf-16-le").ljust(512, b"\0")
        self.assertEqual(fields(vhdx, "vhdx")["creator"], "Microsoft Windows 10.0.19045.0")

    def test_archives_and_packages(self):
        self.assertEqual(fields(lzma.compress(b"x" * 100, check=lzma.CHECK_SHA256), "xz")["check_name"], "sha256")
        self.assertEqual(fields(bz2.compress(b"x" * 100, compresslevel=7), "bzip2")["block_size_bytes"], 700_000)
        cab = bytearray(b"MSCF" + bytes(32))
        struct.pack_into("<I4xI", cab, 8, 0, 44)
        struct.pack_into("<BBHHHHH", cab, 24, 3, 1, 1, 2, 0, 0x1234, 0)
        cab += bytes(8)
        for name in (b"setup.inf", b"payload.dll"):
            cab += bytes(16) + name + b"\0"
        f = fields(bytes(cab), "cab")
        self.assertEqual((f["version"], f["file_count"], f["names"]), ("1.3", 2, ["setup.inf", "payload.dll"]))
        member = lambda name, body: name.ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) \
            + b"100644".ljust(8) + str(len(body)).encode().ljust(10) + b"`\n" + body + (b"\n" if len(body) & 1 else b"")
        deb = b"!<arch>\n" + member(b"debian-binary", b"2.0\n") + member(b"control.tar.xz", b"x")
        f = fields(deb, "ar")
        self.assertEqual((f["package"], f["debian_format_version"], f["names"]), ("deb", "2.0", ["debian-binary", "control.tar.xz"]))
        pyc = struct.pack("<H2sIII", 3531, b"\r\n", 0, 1_790_000_000, 1234)
        f = fields(pyc + b"\xe3", "pyc")
        self.assertEqual((f["python_version"], f["source_size"], f["hash_based"]), ("3.12", 1234, False))
        rtf = rb"{\rtf1\ansi\ansicpg1252\deff0{\*\generator Riched20 10.0.19041;}{\info{\author Analyst}{\creatim\yr2026\mo10\dy1\hr9\min30}}}"
        f = fields(rtf, "rtf")
        self.assertEqual((f["ansicpg"], f["generator"], f["author"], f["creatim"]),
                         (1252, "Riched20 10.0.19041", "Analyst", "2026-10-01T09:30"))
        f = fields(b"Cr24" + struct.pack("<II", 3, 100) + bytes(100) + b"PK\x03\x04", "crx")
        self.assertEqual((f["version"], f["zip_offset"]), (3, 112))

    def test_ese_database(self):
        page = bytearray(4096)
        struct.pack_into("<II", page, 4, 0x89ABCDEF, 0x620)
        struct.pack_into("<I", page, 52, 3)
        struct.pack_into("<II", page, 232, 0x14, 32768)
        f = fields(bytes(page), "ese")
        self.assertEqual((f["database_state_name"], f["page_size"], f["file_type"]), ("clean_shutdown", 32768, "database"))

    def test_ole_summary_information(self):
        data = cfb([("\x05SummaryInformation", summary_information("Q3 plan", "J. Doe", "Microsoft Office Word")),
                    ("WordDocument", b"\xec\xa5")])
        f = fields(data, "ole")
        self.assertEqual((f["document_type"], f["title"], f["author"], f["application_name"]),
                         ("word", "Q3 plan", "J. Doe", "Microsoft Office Word"))
        self.assertEqual(f["created_utc"], "2026-10-01T00:00:00Z")

    def test_new_formats_reach_describe_and_autoprop(self):
        self.assertIn("regf", dict(describe(regf())))
        self.assertEqual(confident("prefetch.run_count", prefetch()), ("prefetch", "run_count", "9"))
        self.assertEqual(confident("evtx.next_record_id", evtx()), ("evtx", "next_record_id", "61"))

    def test_other_bytes_are_left_alone(self):
        self.assertEqual(formats(b"plain text, nothing to see"), [])
        self.assertEqual(formats(b""), [])


if __name__ == "__main__":
    unittest.main()
