"""Forecast for days 26-31: the next question of each series, answered before it is asked.

Every Metadata day added exactly one `Determine <format>.<field>` property (day 3
text.utf8_bom_present ... day 23 sqlite.page_size_bytes, day 24 evtx.record_count, day 25
registry.hive_root_name), and every Warmups day one encoding. Day 25's property had a reader
but no name match, so the lane waited for a human. This file names the likely next ones in
the grader's style and checks that the robot's first untimed answer is the right one: for
Metadata `suggest.confident()`, else the best-ranked field (what autoprop sends untimed); for
Warmups the answer `peel` finds.

A row that fails is a release-day risk found today: add a reader or an alias
(suggest._ALIASES), never an answer.
"""

import base64
import bz2
import codecs
import lzma
import plistlib
import random
import struct
import unittest
import zlib

from huntress_ctf.decoders import peel
from huntress_ctf.formats import describe
from huntress_ctf.formats_dfir import formats
from huntress_ctf.suggest import confident, formatted, ranked
from tests.test_formats_dfir import (CERT_B64, cfb, destlist, dmg, ds_store, ewf, fields, filetime, gpt_disk,
                                     lnk, minidump, mft_record, ntfs_boot, prefetch, recycle_bin_i,
                                     scheduled_task, usn_record)


# --- New readers: disk images, mail stores, kernel dumps, Linux journal and logins --------------

def vmdk():
    descriptor = ('# Disk DescriptorFile\nversion=1\nencoding="UTF-8"\nCID=7e5f1c2a\nparentCID=ffffffff\n'
                  'createType="monolithicSparse"\n\n# Extent description\nRW 4194304 SPARSE "evidence.vmdk"\n\n'
                  '#DDB\nddb.adapterType = "lsilogic"\nddb.virtualHWVersion = "14"\n').encode()
    header = bytearray(512)
    struct.pack_into("<4sIIQQQQIQQQ", header, 0, b"KDMV", 1, 3, 4194304, 128, 1, 20, 512, 21, 41, 128)
    header[73:77] = b"\n \r\n"
    return bytes(header) + descriptor.ljust(20 * 512, b"\0")


def qcow2():
    header = bytearray(512)
    backing = b"base-image.qcow2"
    struct.pack_into(">4sIQIIQIIQQIIQ", header, 0, b"QFI\xfb", 3, 112, len(backing), 16, 10 << 30, 0, 20,
                     0x30000, 0x10000, 1, 2, 0x50000)
    struct.pack_into(">QQQII", header, 72, 1, 0, 0, 4, 112)
    header[112:112 + len(backing)] = backing
    return bytes(header)


def pst(version=23, client=b"SM", crypt=1):
    data = bytearray(1024)
    data[:4] = b"!BDN"
    data[8:10] = client
    struct.pack_into("<HHBB", data, 10, version, 19, 1, 1)
    if version >= 23:
        struct.pack_into("<Q", data, 184, 271360)
        data[513] = crypt
    else:
        struct.pack_into("<I", data, 168, 271360)
        data[461] = crypt
    return bytes(data)


def kernel_dump():
    data = bytearray(0x2000)
    data[:8] = b"PAGEDU64"
    struct.pack_into("<IIQQQQIII", data, 8, 0xF, 19041, 0x1AA000, 0xFFFFFA8000000000, 0xFFFFF80002A4E730,
                     0xFFFFF80002A6E140, 0x8664, 4, 0x7E)
    struct.pack_into("<4Q", data, 0x40, 0xFFFFFFFFC0000005, 0xFFFFF80002A5B123, 0xFFFFF88003C2D998, 0xFFFFF88003C2D200)
    struct.pack_into("<I", data, 0xF98, 1)
    struct.pack_into("<Q", data, 0xFA8, filetime(2026, 10, 27))
    return bytes(data)


MACHINE_ID = "5f0c3f1e2d4b4a69a3b1c2d3e4f50617"


def journal():
    data = bytearray(256)
    data[:8] = b"LPKSHHRH"
    struct.pack_into("<IIB", data, 8, 2, 8 | 16, 2)
    data[24:40], data[40:56], data[56:72] = bytes(range(16)), bytes.fromhex(MACHINE_ID), bytes(range(16, 32))
    struct.pack_into("<15Q", data, 88, 256, 4096, 0, 0, 0, 0, 0, 120, 37, 900, 864, 0,
                     1_793_491_200_000_000, 1_793_577_600_000_000, 5_000_000)
    struct.pack_into("<QQ", data, 208, 60, 12)
    return bytes(data)


def utmp_record(kind, user="", host="", line="", seconds=0, address=b"", pid=1000):
    record = bytearray(384)
    struct.pack_into("<hHi", record, 0, kind, 0, pid)
    record[8:8 + len(line)] = line.encode()
    record[44:44 + len(user)] = user.encode()
    record[76:76 + len(host)] = host.encode()
    struct.pack_into("<ii", record, 340, seconds, 0)
    record[348:348 + len(address)] = address
    return bytes(record)


def wtmp():
    return (utmp_record(2, "reboot", "6.8.0-45-generic", "~", 1793491200, pid=0)
            + utmp_record(7, "analyst", "203.0.113.7", "pts/0", 1793494800, bytes([203, 0, 113, 7]))
            + utmp_record(8, line="pts/0", seconds=1793498400)
            + utmp_record(7, "root", "198.51.100.23", "pts/1", 1793502000, bytes([198, 51, 100, 23])))


class ForecastFormatTests(unittest.TestCase):
    def test_vmdk_sparse_header_and_descriptor(self):
        f = fields(vmdk(), "vmdk")
        self.assertEqual((f["version"], f["capacity_sectors"], f["capacity"], f["grain_size_sectors"], f["compression"]),
                         (1, 4194304, 2147483648, 128, "none"))
        self.assertEqual((f["create_type"], f["cid"], f["parent_cid"], f["adapter_type"], f["virtual_hw_version"]),
                         ("monolithicSparse", "7e5f1c2a", "ffffffff", "lsilogic", "14"))
        self.assertEqual((f["extent_files"], f["descriptor_capacity_sectors"], f["descriptor_version"]),
                         (["evidence.vmdk"], 4194304, "1"))
        text = vmdk()[512:].split(b"\0", 1)[0]
        self.assertEqual(fields(text, "vmdk")["create_type"], "monolithicSparse")  # A descriptor file alone.

    def test_qcow2(self):
        f = fields(qcow2(), "qcow2")
        self.assertEqual((f["version"], f["virtual_size"], f["cluster_size"], f["backing_file"], f["snapshot_count"]),
                         (3, 10 << 30, 65536, "base-image.qcow2", 2))
        self.assertEqual((f["encryption"], f["dirty"], f["refcount_order"], f["compression_type"]), ("none", True, 4, "zlib"))

    def test_pst_and_ost(self):
        f = fields(pst(), "pst")
        self.assertEqual((f["file_type"], f["format"], f["format_version"], f["crypt_method_name"], f["file_eof"]),
                         ("pst", "unicode", 23, "permute", 271360))
        f = fields(pst(version=14, client=b"SO", crypt=0), "pst")
        self.assertEqual((f["file_type"], f["format"], f["crypt_method_name"], f["file_eof"]), ("ost", "ansi", "none", 271360))

    def test_kernel_crash_dump(self):
        f = fields(kernel_dump(), "kernel_dump")
        self.assertEqual((f["bitness"], f["build_number"], f["machine_name"], f["number_processors"], f["bugcheck_code"]),
                         (64, 19041, "amd64", 4, 0x7E))
        self.assertEqual((f["bugcheck_parameters"][0], f["dump_type"], f["system_time_utc"]),
                         ("0xffffffffc0000005", 1, "2026-10-27T00:00:00Z"))
        small = bytearray(0x1000)
        small[:8] = b"PAGEDUMP"
        struct.pack_into("<IIIIIIIII", small, 8, 0xF, 7601, 0x185000, 0, 0, 0, 0x14C, 2, 0xD1)
        f = fields(bytes(small), "kernel_dump")
        self.assertEqual((f["bitness"], f["machine_name"], f["bugcheck_code"], f["build_number"]), (32, "i386", 0xD1, 7601))

    def test_systemd_journal(self):
        f = fields(journal(), "journald")
        self.assertEqual((f["machine_id"], f["entry_count"], f["state_name"], f["features"]),
                         (MACHINE_ID, 37, "archived", ["compressed_zstd", "compact"]))
        self.assertEqual((f["head_entry_realtime_utc"], f["tail_entry_realtime_utc"], f["data_object_count"]),
                         ("2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z", 60))

    def test_utmp_and_wtmp(self):
        f = fields(wtmp(), "utmp")
        self.assertEqual((f["record_count"], f["login_count"], f["boot_count"], f["user_names"]),
                         (4, 2, 1, ["analyst", "root"]))
        self.assertEqual((f["hosts"], f["ip_addresses"], f["terminals"], f["last_login_user"]),
                         (["203.0.113.7", "198.51.100.23"], ["203.0.113.7", "198.51.100.23"], ["pts/0", "pts/1"], "root"))
        self.assertEqual((f["first_time_utc"], f["record_types"]),
                         ("2026-11-01T00:00:00Z", ["BOOT_TIME", "USER_PROCESS", "DEAD_PROCESS"]))

    def test_no_magic_means_strict_detection(self):
        # utmp has no magic: zeros, text and other formats' bytes must not read as login records.
        for data in (bytes(384 * 4), b"A" * 768, prefetch().ljust(768, b"\0"), wtmp()[:-1]):
            self.assertNotIn("utmp", dict(formats(data)))
        self.assertNotIn("vmdk", dict(describe(b"# Disk notes\nversion=1\n")))

    def test_damaged_forecast_formats_never_raise(self):
        rng = random.Random(31)
        for seed in (vmdk(), qcow2(), pst(), pst(version=14), kernel_dump(), journal(), wtmp()):
            for _ in range(200):
                blob = bytearray(seed)
                for _ in range(rng.randint(1, 8)):
                    blob[rng.randrange(len(blob))] = rng.randrange(256)
                formats(bytes(blob[:rng.randint(1, len(blob))]))  # must not raise


# --- Metadata: one new property per day, in the grader's naming style ----------------------------

def fixtures():
    paths = ["C:\\Tools\\a.exe", "C:\\Users\\a\\b.txt"]
    usn = bytes(8192) + usn_record(100, "invoice.docm", 0x100) + usn_record(300, "payload.dll", 0x2)
    pcap = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + (struct.pack("<IIII", 1, 0, 4, 4) + b"abcd") * 3
    return {
        "prefetch": prefetch(), "mft": mft_record(), "usn": usn, "recycle": recycle_bin_i(),
        "jumplist": cfb([("DestList", destlist(paths)), ("1", lnk(paths[0])), ("2", lnk(paths[1]))]),
        "minidump": minidump(), "task": scheduled_task(), "ewf": ewf(), "disk": gpt_disk(), "ntfs": ntfs_boot(),
        "dmg": dmg(), "ds_store": ds_store(), "x509": base64.b64decode(CERT_B64), "pcap": pcap,
        "plist": plistlib.dumps({"CFBundleIdentifier": "com.example.app", "CFBundleShortVersionString": "1.2"},
                                fmt=plistlib.FMT_BINARY),
        "vmdk": vmdk(), "qcow2": qcow2(), "pst": pst(), "kernel_dump": kernel_dump(), "journal": journal(),
        "wtmp": wtmp(),
    }


# (fixture, property, the field it is). Several spellings per format: the grader names the
# structure a field lives in ("jpeg.sof_dimensions_pixels", "pe.coff_machine_u16_hex").
PROPERTIES = (
    ("prefetch", "prefetch.executable_name", "executable_name"), ("prefetch", "prefetch.run_count", "run_count"),
    ("prefetch", "prefetch.last_run_time_utc", "last_run_utc"), ("prefetch", "prefetch.format_version", "version"),
    ("prefetch", "prefetch.path_hash_u32_hex", "prefetch_hash"), ("prefetch", "prefetch.executable_filename", "executable_name"),
    ("prefetch", "prefetch.execution_count", "run_count"), ("prefetch", "prefetch.last_execution_time_utc", "last_run_utc"),
    ("mft", "mft.file_name", "file_name"), ("mft", "mft.record_number", "record_number"),
    ("mft", "mft.parent_record_number", "parent_record_number"), ("mft", "mft.si_created_utc", "si_created"),
    ("mft", "mft.standard_information_created_utc", "si_created"), ("mft", "mft.file_name_created_utc", "fn_created"),
    ("mft", "mft.alternate_data_stream_names", "alternate_data_streams"), ("mft", "mft.ads_names", "alternate_data_streams"),
    ("mft", "mft.timestomp_present", "si_before_fn_created"), ("mft", "mft.data_size_bytes", "data_size"),
    ("usn", "usn.record_count", "record_count"), ("usn", "usnjrnl.file_names", "file_names"), ("usn", "usn.reason_set", "reasons"),
    ("recycle", "recycle_bin.original_path", "original_path"), ("recycle", "recycle_bin.original_size_bytes", "original_size"),
    ("recycle", "recycle_bin.deletion_time_utc", "deleted_utc"), ("recycle", "recycle.original_filename", "original_name"),
    ("jumplist", "jumplist.entry_count", "destlist_entry_count"), ("jumplist", "jumplist.target_paths", "target_paths"),
    ("jumplist", "jumplist.hostnames", "destlist_hostnames"),
    ("minidump", "minidump.process_id", "process_id"), ("minidump", "minidump.module_names", "module_names"),
    ("minidump", "minidump.process_name", "main_module_name"), ("minidump", "minidump.processor_architecture", "processor_architecture"),
    ("minidump", "minidump.os_build_number", "os_build"),
    ("task", "scheduled_task.command", "command"), ("task", "scheduled_task.exec_command", "command"),
    ("task", "task.registration_author", "author"), ("task", "scheduled_task.task_uri", "uri"),
    ("task", "scheduled_task.trigger_set", "trigger_types"), ("task", "scheduled_task.principal_user_id", "user_id"),
    ("ewf", "ewf.case_number", "case_number"), ("ewf", "ewf.examiner_name", "examiner_name"), ("ewf", "e01.md5_hash", "md5"),
    ("ewf", "ewf.acquisition_md5", "md5"), ("ewf", "ewf.media_size_bytes", "media_size_bytes"),
    ("disk", "mbr.disk_signature_u32_hex", "disk_signature"), ("disk", "mbr.partition_type_set", "partition_types"),
    ("disk", "gpt.disk_guid", "disk_guid"), ("disk", "gpt.partition_names", "partition_names"),
    ("ntfs", "ntfs.volume_serial_number", "volume_serial_number"), ("ntfs", "ntfs.cluster_size_bytes", "cluster_size"),
    ("ntfs", "ntfs.mft_start_cluster", "mft_cluster"),
    ("x509", "x509.subject_common_name", "subject_cn"), ("x509", "cert.subject_common_name", "subject_cn"),
    ("x509", "x509.issuer_common_name", "issuer_cn"), ("x509", "x509.serial_number_hex", "serial_number"),
    ("x509", "x509.not_after_utc", "not_after"), ("x509", "x509.valid_to_utc", "not_after"),
    ("x509", "x509.sha256_thumbprint", "sha256_fingerprint"), ("x509", "x509.san_dns_names", "subject_alt_names"),
    ("x509", "x509.signature_algorithm", "signature_algorithm"),
    ("plist", "plist.bundle_identifier", "CFBundleIdentifier"),
    ("plist", "plist.bundle_short_version_string", "CFBundleShortVersionString"),
    ("pcap", "pcap.link_type", "linktype"), ("pcap", "pcap.packet_count", "packet_count"), ("pcap", "pcap.snapshot_length", "snaplen"),
    ("dmg", "dmg.sector_count", "sector_count"), ("ds_store", "ds_store.file_names", "file_names"),
    ("vmdk", "vmdk.create_type", "create_type"), ("vmdk", "vmdk.capacity_sectors", "capacity_sectors"),
    ("vmdk", "vmdk.capacity_bytes", "capacity"), ("vmdk", "vmdk.adapter_type", "adapter_type"),
    ("vmdk", "vmdk.parent_cid", "parent_cid"), ("vmdk", "vmdk.extent_files", "extent_files"),
    ("qcow2", "qcow2.virtual_size_bytes", "virtual_size"), ("qcow2", "qcow2.cluster_size_bytes", "cluster_size"),
    ("qcow2", "qcow2.backing_file", "backing_file"), ("qcow2", "qcow2.snapshot_count", "snapshot_count"),
    ("pst", "pst.format_version", "format_version"), ("pst", "pst.file_type", "file_type"),
    ("pst", "pst.crypt_method_name", "crypt_method_name"), ("pst", "ost.file_eof_bytes", "file_eof"),
    ("kernel_dump", "kernel_dump.bugcheck_code_u32_hex", "bugcheck_code"), ("kernel_dump", "dmp.bugcheck_code_u32_hex", "bugcheck_code"),
    ("kernel_dump", "memory_dump.build_number", "build_number"), ("kernel_dump", "kernel_dump.machine_type_u16_hex", "machine_type"),
    ("kernel_dump", "kernel_dump.number_processors", "number_processors"),
    ("kernel_dump", "kernel_dump.system_time_utc", "system_time_utc"),
    ("journal", "journald.machine_id", "machine_id"), ("journal", "journal.entry_count", "entry_count"),
    ("journal", "journald.boot_id", "boot_id"), ("journal", "journald.head_entry_realtime_utc", "head_entry_realtime_utc"),
    ("wtmp", "wtmp.record_count", "record_count"), ("wtmp", "wtmp.login_count", "login_count"),
    ("wtmp", "wtmp.user_names", "user_names"), ("wtmp", "wtmp.last_login_user", "last_login_user"),
    ("wtmp", "utmp.boot_count", "boot_count"), ("wtmp", "wtmp.remote_hosts", "hosts"),
)


def first_untimed_answer(prop, data):
    """What autoprop sends first on an untimed attempt: the clear field, else the best-ranked one."""
    clear = confident(prop, data)
    if clear:
        return clear[2]
    found = ranked(prop, data)
    return formatted(prop, found[0][3]) if found else None


class MetadataForecastTests(unittest.TestCase):
    def test_the_first_untimed_answer_is_the_right_field(self):
        files = fixtures()
        for name, prop, field in PROPERTIES:
            with self.subTest(prop=prop):
                data = files[name]
                values = {key: value for _, found in describe(data) for key, value in found.items()}
                self.assertIn(field, values)
                self.assertEqual(first_untimed_answer(prop, data), formatted(prop, values[field]))

    def test_no_clear_guess_is_a_wrong_one(self):
        # A clear guess carries no alternatives, so a wrong one is a lane stuck until a human comes.
        files = fixtures()
        for name, prop, field in PROPERTIES:
            clear = confident(prop, files[name])
            if clear:
                values = {key: value for _, found in describe(files[name]) for key, value in found.items()}
                self.assertEqual(clear[2], formatted(prop, values[field]), prop)

    def test_dump_namespaces_cover_both_dump_kinds(self):
        self.assertEqual(confident("dmp.process_id", minidump())[2], "712")
        self.assertEqual(confident("dmp.bugcheck_code_u32_hex", kernel_dump())[2], "0x0000007e")


# --- Warmups: one new encoding per day -----------------------------------------------------------

SENTENCE = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: deft-blanket-clover-43"
ANSWER = "deft-blanket-clover-43"
B = SENTENCE.encode()


def _hexdump_c(data):
    rows = []
    for at in range(0, len(data), 16):
        chunk = data[at:at + 16]
        cells = " ".join(f"{b:02x}" for b in chunk[:8]) + "  " + " ".join(f"{b:02x}" for b in chunk[8:])
        rows.append(f"{at:08x}  {cells:<48}  |{''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)}|")
    return "\n".join(rows + [f"{len(data):08x}"])


def _xxd(data):
    rows = []
    for at in range(0, len(data), 16):
        chunk = data[at:at + 16]
        cells = " ".join(chunk[i:i + 2].hex() for i in range(0, len(chunk), 2))
        rows.append(f"{at:08x}: {cells:<39}  {''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)}")
    return "\n".join(rows)


def _number(data, alphabet):
    value, out = int.from_bytes(data, "big"), ""
    while value:
        value, digit = divmod(value, len(alphabet))
        out = alphabet[digit] + out
    return out


# The next step of each series the course is in: compression (Day 21 gzip, Day 22 zlib), bases
# (64, 32, 85), character encodings (Day 19-20 UTF-16, Day 25 code points), dumps and mail.
ENCODINGS = {
    "bzip2": lambda: base64.b64encode(bz2.compress(B)).decode(),
    "xz": lambda: base64.b64encode(lzma.compress(B)).decode(),
    "lzma_alone": lambda: base64.b64encode(lzma.compress(B, format=lzma.FORMAT_ALONE)).decode(),
    "raw_deflate": lambda: base64.b64encode(zlib.compress(B)[2:-4]).decode(),
    "base36": lambda: _number(B, "0123456789abcdefghijklmnopqrstuvwxyz"),
    "decimal_bigint": lambda: str(int.from_bytes(B, "big")),
    "base32hex": lambda: base64.b32hexencode(B).decode(),
    "utf32_bom_hex": lambda: SENTENCE.encode("utf-32").hex(),
    "ebcdic_hex": lambda: SENTENCE.encode("cp037").hex(),
    "ebcdic_base64": lambda: base64.b64encode(SENTENCE.encode("cp037")).decode(),
    "utf7": lambda: "+" + base64.b64encode(SENTENCE.encode("utf-16-be")).decode().rstrip("=") + "-",
    "xxd": lambda: _xxd(B),
    "hexdump_c": lambda: _hexdump_c(B),
    "mime_b": lambda: "=?utf-8?B?" + base64.b64encode(B).decode() + "?=",
    "mime_q": lambda: "=?utf-8?Q?" + codecs.encode(B, "quopri").decode().replace(" ", "_").replace("=\n", "") + "?=",
    "netstrings": lambda: "".join(f"{len(word) + 1}:{word} ," for word in SENTENCE.split(" ")),
    # Already covered before the forecast; kept so a later change cannot lose them.
    "base58": lambda: _number(B, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"),
    "ascii85": lambda: "<~" + base64.a85encode(B).decode() + "~>",
    "uuencode": lambda: codecs.encode(B, "uu").decode(),
    "quoted_printable": lambda: codecs.encode(B, "quopri").decode(),
    "octal_escapes": lambda: "".join(f"\\{b:03o}" for b in B),
}


class WarmupForecastTests(unittest.TestCase):
    def test_each_forecast_encoding_decodes_to_one_answer(self):
        for name, encode in ENCODINGS.items():
            with self.subTest(encoding=name):
                found = peel(encode().encode())
                self.assertEqual({answer for _, _, answer in found}, {ANSWER})


if __name__ == "__main__":
    unittest.main()
