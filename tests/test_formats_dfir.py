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


def prefetch(version=30, metrics_at=0x130):
    """Version 30 comes in two file-information sizes: metrics at 0x130 keep the run count at
    0xD0, metrics at 0x128 (Day 26's real file) at 0xC8."""
    data = bytearray(0x200)
    struct.pack_into("<I4sII", data, 0, version, b"SCCA", 0x11, len(data))
    data[0x10:0x10 + 22] = "CMD.EXE".encode("utf-16-le") + bytes(8)
    struct.pack_into("<II", data, 0x4C, 0x0A1B2C3D, 0)
    struct.pack_into("<I", data, 0x54, metrics_at)
    struct.pack_into("<Q", data, 0x80, filetime())
    struct.pack_into("<I", data, 0xC8 if metrics_at == 0x128 else 0xD0, 9)
    return bytes(data)


def xpress_literals(data, matches=()):
    """An [MS-XCA] LZ77+Huffman stream where all 512 symbols have 9-bit codes (so symbol s is
    coded as s); `matches` maps an output position to (length, offset) with length 3..17."""
    bits, at = [], 0
    while at < len(data):
        if at in matches:
            length, offset = matches[at]
            offset_bits = offset.bit_length() - 1
            symbol = 256 + 16 * offset_bits + (length - 3)
            bits += [int(b) for b in format(symbol, "09b")]
            bits += [int(b) for b in format(offset - (1 << offset_bits), f"0{offset_bits}b")] if offset_bits else []
            at += length
        else:
            bits += [int(b) for b in format(data[at], "09b")]
            at += 1
    bits += [0] * (-len(bits) % 16 + 32)
    words = [int("".join(map(str, bits[i:i + 16])), 2) for i in range(0, len(bits), 16)]
    return bytes([0x99] * 256) + b"".join(struct.pack("<H", word) for word in words)


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
        self.assertEqual((f["file_size"], fields(prefetch(metrics_at=0x128), "prefetch")["run_count"]), (0x200, 9))
        plain = prefetch()
        packed = xpress_literals(plain, {0x30: (17, 0x30), 0x100: (12, 0x40)})
        rebuilt = bytearray(plain)
        for at, (length, offset) in {0x30: (17, 0x30), 0x100: (12, 0x40)}.items():
            for i in range(length):
                rebuilt[at + i] = rebuilt[at + i - offset]
        f = fields(b"MAM\x04" + struct.pack("<I", len(plain)) + packed, "prefetch")
        self.assertEqual((f["compressed"], f["executable_name"], f["run_count"]), (True, "CMD.EXE", 9))
        from huntress_ctf.formats_dfir import xpress_huffman
        self.assertEqual(xpress_huffman(packed, len(plain)), bytes(rebuilt))
        damaged = dict(formats(b"MAM\x04" + struct.pack("<I", 4096) + bytes(300)))["prefetch"]
        self.assertEqual((damaged["compressed"], damaged["uncompressed_size"]), (True, 4096))
        self.assertIn("damaged", damaged)  # Code lengths of all zeros are no code: nothing guessed.

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


# --- Days 26+ candidates -------------------------------------------------------------------------

CERT_B64 = "MIIBszCCAVqgAwIBAgIEEjSrzTAKBggqhkjOPQQDAjBCMSMwIQYDVQQDDBphbnRpY2lwYXRlLmV4YW1wbGUuaW52YWxpZDEbMBkGA1UECgwSU3ludGhldGljIFRlc3QgT3JnMB4XDTI2MTAwMTAwMDAwMFoXDTI3MTAwMTAwMDAwMFowQjEjMCEGA1UEAwwaYW50aWNpcGF0ZS5leGFtcGxlLmludmFsaWQxGzAZBgNVBAoMElN5bnRoZXRpYyBUZXN0IE9yZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABND+tU6xlwqWV70zWAkMW8uo3lp+0y8dYAw3yY119CyG7XNdhAX+Drh/YMnam3BkMbwO6otUKIcWvXbadp2KgGSjPjA8MDoGA1UdEQQzMDGCGmFudGljaXBhdGUuZXhhbXBsZS5pbnZhbGlkghNhbHQuZXhhbXBsZS5pbnZhbGlkMAoGCCqGSM49BAMCA0cAMEQCIHrPI6cOU8AVbFWMMSCiYGwYtt8D4qlWGQG4D8AIZeUDAiAvTIPrhP+mFRVpcSkuYEbv3jMUeAUNXaNeI59Un2NHQg=="  # Synthetic self-signed ECDSA certificate (CN=anticipate.example.invalid), made for this test.
CERT_SHA256 = "4f60f369c2d17690d1d04b178c5674ae09dc5c60e171577872adcd6b7afefd5d"


def _resident(kind, content, name=""):
    raw_name = name.encode("utf-16-le")
    offset = 24 + len(raw_name)
    offset += -offset % 8
    length = offset + len(content)
    length += -length % 8
    head = struct.pack("<IIBBHHHIHBB", kind, length, 0, len(name), 24, 0, 0, len(content), offset, 0, 0)
    return (head + raw_name).ljust(offset, b"\0") + content.ljust(length - offset, b"\0")


def mft_record():
    si = struct.pack("<QQQQI", filetime(2026, 1, 1), filetime(2026, 1, 2), filetime(2026, 1, 3), filetime(2026, 1, 4), 0x20)
    name = "evil.exe".encode("utf-16-le")
    fn = struct.pack("<QQQQQQQII", (3 << 48) | 5, filetime(2026, 6, 1), filetime(2026, 6, 1), filetime(2026, 6, 1),
                     filetime(2026, 6, 1), 4096, 1234, 0x20, 0) + bytes([8, 1]) + name
    attributes = (_resident(0x10, si.ljust(72, b"\0")) + _resident(0x30, fn) + _resident(0x80, b"hello")
                  + _resident(0x80, b"[ZoneTransfer]", "Zone.Identifier") + struct.pack("<I", 0xFFFFFFFF))
    record = bytearray(1024)
    record[:4] = b"FILE"
    struct.pack_into("<HHQHHHHIIQH", record, 4, 48, 3, 77, 9, 1, 56, 1, 56 + len(attributes) + 4, 1024, 0, 6)
    struct.pack_into("<I", record, 44, 42)
    record[56:56 + len(attributes)] = attributes
    struct.pack_into("<HHH", record, 48, 0xABCD, struct.unpack_from("<H", record, 510)[0], struct.unpack_from("<H", record, 1022)[0])
    struct.pack_into("<H", record, 510, 0xABCD)
    struct.pack_into("<H", record, 1022, 0xABCD)
    return bytes(record)


def usn_record(usn, name, reason):
    raw = name.encode("utf-16-le")
    length = 60 + len(raw)
    length += -length % 8
    return (struct.pack("<IHHQQQQIIIIHH", length, 2, 0, 0x1000000000005, 0x5000000000005, usn,
                        filetime(2026, 10, usn % 27 + 1), reason, 0, 0, 0x20, len(raw), 60) + raw).ljust(length, b"\0")


def lnk(target):
    """A shell link with only a LinkInfo local path (MS-SHLLINK)."""
    path = target.encode() + b"\0"
    info = struct.pack("<IIIIIII", 28 + len(path) + 1, 28, 1, 0, 28, 0, 28 + len(path)) + path + b"\0"
    header = struct.pack("<I16sIIQQQIiIH", 0x4C, bytes.fromhex("0114020000000000c000000000000046"), 0x2, 0,
                         0, 0, 0, 0, 0, 1, 0).ljust(76, b"\0")
    return header + info


def destlist(paths):
    out = struct.pack("<IIIfIIII", 4, len(paths), 1, 0.0, len(paths), 0, 7, 0)
    for number, path in enumerate(paths, 1):
        entry = bytearray(0x7C)
        entry[0x48:0x48 + 8] = b"WKSTN-01"
        struct.pack_into("<IIQiiI", entry, 0x58, number, 0, filetime(2026, 10, number), 0 if number == 1 else -1, -1, 3)
        raw = path.encode("utf-16-le")
        out += bytes(entry) + struct.pack("<H", len(path)) + raw + bytes(4)
    return out


RECYCLED_PATH = "C:\\Users\\analyst\\Desktop\\secret.xlsx"


def recycle_bin_i():
    return (struct.pack("<QQQI", 2, 48213, filetime(2026, 10, 20), len(RECYCLED_PATH) + 1)
            + (RECYCLED_PATH + "\0").encode("utf-16-le"))


def minidump():
    name = "C:\\Windows\\System32\\lsass.exe".encode("utf-16-le")
    system = struct.pack("<HHHBBIIIII", 9, 6, 0, 4, 1, 10, 0, 19045, 2, 0)
    modules = struct.pack("<I", 1) + struct.pack("<QIIII", 0x7FF600000000, 0x1000, 0, 0, 200).ljust(108, b"\0")
    misc = struct.pack("<IIII", 24, 1, 712, 0)
    directory = struct.pack("<III", 7, len(system), 100) + struct.pack("<III", 4, len(modules), 140) \
        + struct.pack("<III", 15, len(misc), 280)
    data = bytearray(400)
    data[:32] = b"MDMP" + struct.pack("<IIIIIQ", 0xA793, 3, 32, 0, 1793491200, 0x2)
    data[32:32 + len(directory)] = directory
    data[100:100 + len(system)] = system
    data[140:140 + len(modules)] = modules
    data[200:204 + len(name)] = struct.pack("<I", len(name)) + name
    data[280:296] = misc
    return bytes(data)


def scheduled_task():
    xml = ('<?xml version="1.0" encoding="UTF-16"?>\n<Task version="1.2" '
           'xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Author>CORP\\svc</Author>'
           '<URI>\\Updater</URI></RegistrationInfo><Triggers><LogonTrigger/><TimeTrigger/></Triggers>'
           '<Principals><Principal><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>'
           '<Settings><Hidden>true</Hidden></Settings><Actions><Exec><Command>powershell.exe</Command>'
           '<Arguments>-w hidden -enc AAAA</Arguments></Exec></Actions></Task>')
    return b"\xff\xfe" + xml.encode("utf-16-le")


def ewf():
    import zlib
    text = "1\nmain\nc\tn\ta\te\tt\tav\tov\tm\tu\nCASE-26\tEV-1\tLaptop\tJ. Analyst\tnone\t20201230\tWindows\t2026 10 01\t2026 10 01\n\n"
    def section(kind, body, nxt):
        return kind.ljust(16, b"\0") + struct.pack("<QQ", nxt, 76 + len(body)) + bytes(44) + body
    header = zlib.compress(text.encode())
    volume = struct.pack("<B3xIIIQ", 1, 2, 64, 512, 128).ljust(1052, b"\0")
    digest = bytes.fromhex("00112233445566778899aabbccddeeff") + bytes(20)
    a = 13
    b = a + 76 + len(header)
    c = b + 76 + len(volume)
    d = c + 76 + len(digest)
    return (b"EVF\x09\x0d\x0a\xff\x00" + b"\x01" + struct.pack("<HH", 1, 0) + section(b"header", header, b)
            + section(b"volume", volume, c) + section(b"digest", digest, d) + section(b"done", b"", d))


def gpt_disk():
    """A protective MBR and a GPT with one basic data partition named "Data"."""
    disk = bytearray(512 * 34)
    struct.pack_into("<I", disk, 440, 0xDEADBEEF)
    struct.pack_into("<B3xB3xII", disk, 446, 0x00, 0xEE, 1, 0xFFFFFFFF)
    disk[510:512] = b"\x55\xaa"
    disk[512:520] = b"EFI PART"
    struct.pack_into("<IIIIQQQQ", disk, 520, 0x10000, 92, 0, 0, 1, 99, 34, 90)
    disk[568:584] = bytes(range(16))
    struct.pack_into("<QII", disk, 584, 2, 128, 128)
    entry = 1024
    disk[entry:entry + 16] = bytes.fromhex("a2a0d0ebe5b9334487c068b6b72699c7")  # basic data
    struct.pack_into("<QQ", disk, entry + 32, 34, 90)
    disk[entry + 56:entry + 56 + 8] = "Data".encode("utf-16-le")
    return bytes(disk)


def ntfs_boot():
    boot = bytearray(512)
    boot[3:11] = b"NTFS    "
    struct.pack_into("<HB", boot, 11, 512, 8)
    struct.pack_into("<QQQb", boot, 40, 2048000, 786432, 2, -10)
    struct.pack_into("<Q", boot, 72, 0x1234ABCD5678EF90)
    boot[510:512] = b"\x55\xaa"
    return bytes(boot)


def dmg():
    koly = bytearray(512)
    koly[:4] = b"koly"
    struct.pack_into(">IIIQQQQQII", koly, 4, 4, 512, 1, 0, 0, 8192, 0, 0, 1, 1)
    struct.pack_into(">QQ", koly, 0xD8, 8192, 300)
    struct.pack_into(">IQ", koly, 0x1E8, 1, 64)
    return bytes(8492) + bytes(koly)


def ds_store():
    record = lambda name: struct.pack(">I", len(name)) + name.encode("utf-16-be") + b"Ilocblob" + bytes(8)
    return b"\0\0\0\x01Bud1" + bytes(20) + record("payload.app") + record("readme.txt") + record("payload.app")


class Day26CandidateTests(unittest.TestCase):
    def test_mft_record(self):
        f = fields(mft_record(), "mft")
        self.assertEqual((f["file_name"], f["parent_record_number"], f["parent_sequence_number"], f["record_number"]),
                         ("evil.exe", 5, 3, 42))
        self.assertEqual((f["in_use"], f["is_directory"], f["data_size"], f["alternate_data_streams"]),
                         (True, False, 5, ["Zone.Identifier"]))
        self.assertEqual((f["si_created"], f["fn_created"], f["si_before_fn_created"]),
                         ("2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z", True))
        damaged = bytearray(mft_record())
        damaged[510] ^= 1  # A torn sector: the fixup check fails, no wrong fields.
        self.assertIn("damaged", dict(formats(bytes(damaged)))["mft"])

    def test_usn_journal(self):
        data = bytes(8192) + usn_record(100, "invoice.docm", 0x100) + usn_record(200, "invoice.docm", 0x200 | 0x80000000) \
            + usn_record(300, "payload.dll", 0x2)
        f = fields(data, "usn")
        self.assertEqual((f["record_count"], f["first_usn"], f["last_usn"]), (3, 100, 300))
        self.assertEqual((f["file_names"], f["deleted_file_names"], f["created_file_names"]),
                         (["invoice.docm", "payload.dll"], ["invoice.docm"], ["invoice.docm"]))
        self.assertEqual(f["reasons"], ["DATA_EXTEND", "FILE_CREATE", "FILE_DELETE", "CLOSE"])

    def test_recycle_bin_i(self):
        f = fields(recycle_bin_i(), "recycle_bin_i")
        self.assertEqual((f["original_path"], f["original_name"], f["original_size"], f["deleted_utc"]),
                         (RECYCLED_PATH, "secret.xlsx", 48213, "2026-10-20T00:00:00Z"))
        legacy = struct.pack("<QQQ", 1, 7, filetime()) + RECYCLED_PATH.encode("utf-16-le").ljust(520, b"\0")
        self.assertEqual(fields(legacy, "recycle_bin_i")["original_name"], "secret.xlsx")

    def test_jump_lists(self):
        paths = ["C:\\Tools\\mimikatz.exe", "C:\\Users\\a\\notes.txt"]
        data = cfb([("DestList", destlist(paths)), ("1", lnk(paths[0])), ("2", lnk(paths[1]))])
        f = fields(data, "ole")
        self.assertEqual((f["document_type"], f["destlist_entry_count"], f["destlist_paths"]), ("jump_list", 2, paths))
        self.assertEqual((f["destlist_hostnames"], f["destlist_most_recent_path"], f["target_paths"]),
                         (["WKSTN-01"], paths[1], paths))
        custom = b"\x02\0\0\0" + bytes(28) + lnk(paths[0]) + lnk(paths[1]) + b"\xab\xfb\xbf\xba"
        self.assertEqual(fields(custom, "custom_destinations")["target_paths"], paths)

    def test_minidump(self):
        f = fields(minidump(), "minidump")
        self.assertEqual((f["processor_architecture"], f["os_version"], f["module_count"], f["main_module_name"],
                          f["process_id"], f["stream_types"]),
                         ("amd64", "10.0.19045", 1, "lsass.exe", 712, ["SystemInfoStream", "ModuleListStream", "MiscInfoStream"]))

    def test_scheduled_task(self):
        f = fields(scheduled_task(), "scheduled_task")
        self.assertEqual((f["author"], f["uri"], f["user_id"], f["run_level"], f["hidden"]),
                         ("CORP\\svc", "\\Updater", "S-1-5-18", "HighestAvailable", "true"))
        self.assertEqual((f["trigger_types"], f["command"], f["command_arguments"]),
                         (["LogonTrigger", "TimeTrigger"], "powershell.exe", "-w hidden -enc AAAA"))

    def test_ewf_image(self):
        f = fields(ewf(), "ewf")
        self.assertEqual((f["case_number"], f["examiner_name"], f["acquisition_software_version"], f["sector_count"],
                          f["media_size_bytes"], f["md5"]),
                         ("CASE-26", "J. Analyst", "20201230", 128, 65536, "00112233445566778899aabbccddeeff"))
        self.assertEqual(f["section_types"], ["header", "volume", "digest", "done"])

    def test_disk_layouts(self):
        mbr, gpt = fields(gpt_disk(), "mbr"), fields(gpt_disk(), "gpt")
        self.assertEqual((mbr["disk_signature"], mbr["partition_types"]), ("0xdeadbeef", ["0xee"]))
        self.assertEqual((gpt["partition_count"], gpt["partition_names"], gpt["partition_type_guids"]),
                         (1, ["Data"], ["ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"]))
        f = fields(ntfs_boot(), "ntfs")
        self.assertNotIn("mbr", dict(formats(ntfs_boot())))
        self.assertEqual((f["cluster_size"], f["mft_offset"], f["mft_record_size"], f["volume_serial_number"]),
                         (4096, 786432 * 4096, 1024, "1234ABCD5678EF90"))

    def test_dmg_and_ds_store(self):
        f = fields(dmg(), "dmg")
        self.assertEqual((f["data_fork_length"], f["xml_offset"], f["xml_length"], f["sector_count"]), (8192, 8192, 300, 64))
        self.assertEqual(fields(ds_store(), "ds_store")["file_names"], ["payload.app", "readme.txt"])

    def test_x509_certificate(self):
        import base64
        der = base64.b64decode(CERT_B64)
        f = fields(der, "x509")
        self.assertEqual((f["subject_cn"], f["subject_organization"], f["self_signed"], f["serial_number"]),
                         ("anticipate.example.invalid", "Synthetic Test Org", True, "1234abcd"))
        self.assertEqual((f["not_before"], f["not_after"], f["signature_algorithm"], f["public_key_algorithm"]),
                         ("2026-10-01T00:00:00Z", "2027-10-01T00:00:00Z", "ecdsa-with-SHA256", "ecPublicKey"))
        self.assertEqual((f["sha256_fingerprint"], f["subject_alt_names"]),
                         (CERT_SHA256, ["anticipate.example.invalid", "alt.example.invalid"]))
        pem = b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(der) + b"-----END CERTIFICATE-----\n"
        self.assertEqual(fields(pem, "x509")["subject_cn"], "anticipate.example.invalid")

    def test_autoprop_maps_new_properties(self):
        self.assertEqual(confident("mft.file_name", mft_record()), ("mft", "file_name", "evil.exe"))
        self.assertEqual(confident("x509.subject_cn", __import__("base64").b64decode(CERT_B64))[2], "anticipate.example.invalid")

    def test_damaged_new_formats_never_raise(self):
        import random
        rng = random.Random(26)
        seeds = [mft_record(), bytes(4096) + usn_record(1, "a", 1), b"MDMP" + bytes(60), b"EVF\x09\x0d\x0a\xff\x00" + bytes(200),
                 b"\0\0\0\x01Bud1" + bytes(64), __import__("base64").b64decode(CERT_B64),
                 b"\xff\xfe" + "<Task xmlns='mit/task'><".encode("utf-16-le")]
        for seed in seeds:
            for _ in range(200):
                blob = bytearray(seed)
                for _ in range(rng.randint(1, 8)):
                    blob[rng.randrange(len(blob))] = rng.randrange(256)
                formats(bytes(blob[:rng.randint(1, len(blob))]))  # must not raise


if __name__ == "__main__":
    unittest.main()
