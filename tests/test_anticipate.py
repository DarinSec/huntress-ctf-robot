"""Days 27-31 anticipation, generated data only: the packaging and structure real artifacts use where
the synthetic Day 1-25 fixtures were plain (Day 26 broke on a compressed Prefetch and a split APK).

Mobile: an Android App Bundle (.aab, protobuf manifest), code and native libraries in splits, and an
APK signed only with a v2/v3 signing block. Metadata: the registry below its root key (NTUSER,
SYSTEM, SOFTWARE, SAM and Amcache artifacts), the other Windows compressions (LZNT1, plain Xpress)
and Firefox's LZ4, and readers for the forecast families' real shapes: thumbcache, hiberfil, WIM,
ext2/3/4, FAT and exFAT boot sectors, legacy EVT, INDX, $LogFile, PKCS#7 and Authenticode.
"""

from io import BytesIO
import base64
import json
import struct
import unittest
import zipfile

from huntress_ctf import dexvm, formats, formats_dfir
from huntress_ctf.formats import describe
from huntress_ctf.formats_dfir import formats as dfir_formats
from huntress_ctf.containers import Member
from huntress_ctf.solvers.mobile_puzzle import MobilePuzzleSolver
from tests.test_day26 import CODE, PACKAGE, mobile_context
from tests.test_dexvm import apk, expected, release_dex
from tests.test_forecast import first_untimed_answer
from tests.test_formats_dfir import CERT_B64, filetime, prefetch
from huntress_ctf.suggest import formatted


def varint(value):
    out = b""
    while value >= 0x80:
        out += bytes([value & 0x7F | 0x80])
        value >>= 7
    return out + bytes([value])


def pb(number, payload):
    """One length-delimited protobuf field."""
    return varint(number << 3 | 2) + varint(len(payload)) + payload


def proto_manifest(package, version_code="27"):
    """aapt2's proto XmlNode: <manifest package=.. versionCode=..><application/></manifest>."""
    attributes = (pb(4, pb(1, b"http://schemas.android.com/apk/res/android") + pb(2, b"versionCode") + pb(3, version_code.encode()))
                  + pb(4, pb(2, b"package") + pb(3, package.encode())))
    return pb(1, pb(3, b"manifest") + attributes + pb(5, pb(1, pb(3, b"application"))))


def aab(modules):
    out = BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("BundleConfig.pb", b"")
        for module, files in modules.items():
            archive.writestr(f"{module}/manifest/AndroidManifest.xml", proto_manifest(PACKAGE))
            for name, data in files.items():
                archive.writestr(f"{module}/{name}", data)
    return out.getvalue()


def lp(blob):
    return struct.pack("<I", len(blob)) + blob


def signed_apk(certificate, version=2):
    """A plain APK with an APK Signing Block (v2 or v3 signer, one certificate) and no META-INF."""
    out = BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("classes.dex", b"dex\n035\0")
    data = bytearray(out.getvalue())
    if version == 2:
        signed = lp(b"") + lp(lp(certificate)) + lp(b"")
        signer = lp(signed) + lp(b"") + lp(b"")
        kind = 0x7109871A
    else:  # v3: bare u32 min/max SDK after the certificates, and again after the signed data.
        signed = lp(b"") + lp(lp(certificate)) + struct.pack("<II", 24, 0x7FFFFFFF) + lp(b"")
        signer = lp(signed) + struct.pack("<II", 24, 0x7FFFFFFF) + lp(b"") + lp(b"")
        kind = 0xF05368C0
    value = lp(lp(signer))
    pair = struct.pack("<QI", 4 + len(value), kind) + value
    size = len(pair) + 8 + 16
    block = struct.pack("<Q", size) + pair + struct.pack("<Q", size) + b"APK Sig Block 42"
    end = data.rfind(b"PK\x05\x06")
    directory = struct.unpack_from("<I", data, end + 16)[0]
    struct.pack_into("<I", data, end + 16, directory + len(block))
    return bytes(data[:directory] + block + data[directory:])


class MobileAnticipationTests(unittest.TestCase):
    def test_an_app_bundle_module_is_read_as_an_apk(self):
        puzzle = json.dumps({"schema": "huntress.mobile.puzzle.v1", "codec": "split", "data": "",
                             "parts": ["", "ANS-", "01234567"], "order": [2, 0, 1]})
        feature = json.dumps({"codec": "split", "part": "89ABCDEF", "part_index": 0})
        bundle = aab({"base": {"assets/huntress_puzzle.json": puzzle, "dex/classes.dex": b"dex\n035\0"},
                      "feature": {"assets/huntress_feature.json": feature}})
        members = [Member(name, b"") for name in zipfile.ZipFile(BytesIO(bundle)).namelist()]  # Unpacked, no APKs.
        answers = {c.answer_id: c.answer for c in MobilePuzzleSolver().solve(mobile_context(bundle, members, "app.aab"))}
        self.assertEqual(answers, {"answer": CODE})

    def test_a_proto_manifest_gives_the_apk_fields(self):
        module = BytesIO()
        with zipfile.ZipFile(module, "w") as archive:
            archive.writestr("AndroidManifest.xml", proto_manifest(PACKAGE, "31"))
        fields = formats.apk(module.getvalue())
        self.assertEqual((fields["package_name"], fields["version_code"]), (PACKAGE, "31"))
        self.assertEqual(formats.proto_xml(proto_manifest(PACKAGE))[1], ("application", {}))

    def test_v2_and_v3_signing_blocks_give_the_certificate(self):
        certificate = b"\x30\x03\x02\x01\x07"
        for version in (2, 3):
            with self.subTest(version=version):
                (signature,) = dexvm._signers(signed_apk(certificate, version))
                self.assertEqual(signature.data, certificate)
        with self.assertRaises(dexvm.Unsupported):  # Neither v1 nor a signing block.
            dexvm._signers(apk(release_dex(), {}))

    def test_code_in_a_split_is_loaded(self):
        base = BytesIO()
        with zipfile.ZipFile(base, "w") as archive:
            archive.writestr("assets/huntress_puzzle.json", "{}")
        self.assertIsNone(dexvm.answer_code(base.getvalue()))
        self.assertEqual(dexvm.answer_code(base.getvalue(), splits=[apk(release_dex(), {})]), expected())
        broken = BytesIO()
        with zipfile.ZipFile(broken, "w") as archive:
            archive.writestr("classes.dex", b"not a dex")
        # A damaged split is left out; the base's code still answers.
        self.assertEqual(dexvm.answer_code(apk(release_dex(), {}), splits=[broken.getvalue()]), expected())


# --- Registry -------------------------------------------------------------------------------------

def utf16(text):
    return text.encode("utf-16-le") + b"\0\0"


def hive(paths, root_name="ROOT"):
    """A registry hive with the keys `paths` names ({"A\\B": {value: (type, bytes)}}), one hbin."""
    tree = {}
    for path, values in paths.items():
        node = tree
        for part in path.split("\\"):
            node = node.setdefault("keys", {}).setdefault(part, {})
        node.setdefault("values", {}).update(values)
    cells = bytearray()

    def cell(body):
        offset, size = 0x20 + len(cells), (len(body) + 4 + 7) // 8 * 8
        cells.extend(struct.pack("<i", -size) + body + bytes(size - 4 - len(body)))
        return offset

    def key(name, node, written):
        vks = []
        for label, (kind, raw) in node.get("values", {}).items():
            size, where = ((0x80000000 | len(raw), int.from_bytes(raw.ljust(4, b"\0"), "little")) if len(raw) <= 4
                           else (len(raw), cell(raw)))
            encoded = label.encode("latin-1")
            vks.append(cell(b"vk" + struct.pack("<HIIIHH", len(encoded), size, where, kind, 1, 0) + encoded))
        listing = cell(b"".join(struct.pack("<I", offset) for offset in vks)) if vks else 0
        children = [key(child, sub, written + 1) for child, sub in node.get("keys", {}).items()]
        subkeys = cell(b"lf" + struct.pack("<H", len(children)) + b"".join(struct.pack("<I4x", o) for o in children)) \
            if children else 0
        encoded = name.encode("latin-1")
        body = b"nk" + struct.pack("<HQIIIIIIIIII", 0x20, written, 0, 0, len(children), 0, subkeys, 0, len(vks), listing,
                                   0, 0xFFFFFFFF)
        return cell(body + bytes(0x48 - len(body)) + struct.pack("<HH", len(encoded), 0) + encoded)

    root = key(root_name, tree, 133_000_000_000_000_000)
    size = (0x20 + len(cells) + 4095) // 4096 * 4096
    block = b"hbin" + struct.pack("<III", 0, size, 0) + bytes(16) + bytes(cells)
    base = bytearray(0x1000)
    base[:4] = b"regf"
    struct.pack_into("<IIQIIIIIII", base, 4, 1, 1, 0, 1, 5, 0, 1, root, size, 1)
    checksum = 0
    for (word,) in struct.iter_unpack("<I", bytes(base[:508])):
        checksum ^= word
    struct.pack_into("<I", base, 0x1FC, checksum)
    return bytes(base) + block + bytes(size - len(block))


ROT13 = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                      "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")
LAST_RUN = 133_100_000_000_000_000  # 2022-10-11


def userassist(count):
    return bytes(4) + struct.pack("<I", count) + bytes(52) + struct.pack("<Q", LAST_RUN) + bytes(4)


EXPLORER = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
ARTIFACTS = hive({
    # NTUSER.DAT
    EXPLORER + "\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count": {
        "C:\\Windows\\System32\\cmd.exe".translate(ROT13): (3, userassist(7)),
        "C:\\Tools\\nc.exe".translate(ROT13): (3, userassist(2))},
    EXPLORER + "\\TypedPaths": {"url2": (1, utf16("C:\\Temp")), "url1": (1, utf16("\\\\fileserver\\loot"))},
    EXPLORER + "\\RunMRU": {"MRUList": (1, utf16("ba")), "a": (1, utf16("cmd\\1")), "b": (1, utf16("powershell -nop\\1"))},
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run": {"Updater": (1, utf16("C:\\Users\\Public\\upd.exe"))},
    # SYSTEM
    "Select": {"Current": (4, struct.pack("<I", 1))},
    "ControlSet001\\Control\\ComputerName\\ComputerName": {"ComputerName": (1, utf16("WS-0427"))},
    "ControlSet001\\Control\\TimeZoneInformation": {"TimeZoneKeyName": (1, utf16("W. Europe Standard Time"))},
    "ControlSet001\\Services\\Spooler": {"ImagePath": (2, utf16("%SystemRoot%\\System32\\spoolsv.exe"))},
    "ControlSet001\\Services\\evilsvc": {"ImagePath": (2, utf16("C:\\ProgramData\\e.exe"))},
    "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_Kingston&Prod_DT&Rev_1.00\\0019E06B9C85F0A0&0": {
        "FriendlyName": (1, utf16("Kingston DT USB Device"))},
    "MountedDevices": {"\\DosDevices\\C:": (3, bytes(12)), "\\DosDevices\\E:": (3, bytes(12))},
    # SOFTWARE
    "Microsoft\\Windows NT\\CurrentVersion": {"ProductName": (1, utf16("Windows 10 Pro")),
                                              "CurrentBuild": (1, utf16("19045")),
                                              "RegisteredOwner": (1, utf16("analyst")),
                                              "InstallDate": (4, struct.pack("<I", 1700000000))},
    "Microsoft\\Windows\\CurrentVersion\\Uninstall\\7-Zip": {"DisplayName": (1, utf16("7-Zip 23.01"))},
    # SAM
    "SAM\\Domains\\Account\\Users\\Names\\Administrator": {},
    "SAM\\Domains\\Account\\Users\\Names\\backdoor": {},
    # Amcache.hve
    "Root\\InventoryApplicationFile\\nc.exe|1a2b": {"LowerCaseLongPath": (1, utf16("c:\\tools\\nc.exe")),
                                                    "FileId": (1, utf16("0000" + "ab" * 20)),
                                                    "Name": (1, utf16("nc.exe"))},
}, root_name="CMI-CreateHive{2A7FB991-7BBE-4F9D-B91E-7CB51D4737F5}")

REGISTRY_PROPERTIES = (
    ("registry.userassist_entry_count", "userassist_entry_count", 2),
    ("userassist.entry_count", "userassist_entry_count", 2),
    ("registry.run_value_names", "run_value_names", ["Updater"]),
    ("registry.computer_name", "computer_name", "WS-0427"),
    ("registry.time_zone_name", "time_zone_name", "W. Europe Standard Time"),
    ("registry.service_count", "service_count", 2),
    ("registry.usb_serial_numbers", "usb_serial_numbers", ["0019E06B9C85F0A0"]),
    ("registry.product_name", "product_name", "Windows 10 Pro"),
    ("registry.current_build", "current_build", "19045"),
    ("registry.registered_owner", "registered_owner", "analyst"),
    ("registry.installed_programs", "installed_programs", ["7-Zip 23.01"]),
    ("registry.sam_user_names", "sam_user_names", ["Administrator", "backdoor"]),
    ("sam.user_names", "sam_user_names", ["Administrator", "backdoor"]),
    ("amcache.entry_count", "amcache_entry_count", 1),
    ("registry.typed_paths", "typed_paths", ["\\\\fileserver\\loot", "C:\\Temp"]),
    ("registry.run_mru", "run_mru", ["powershell -nop", "cmd"]),
    ("registry.key_count", "key_count", None),
)


class RegistryTreeTests(unittest.TestCase):
    def fields(self):
        return next(fields for label, fields in dfir_formats(ARTIFACTS) if label == "regf")

    def test_artifacts_below_the_root(self):
        f = self.fields()
        self.assertNotIn("tree_damaged", f)
        self.assertEqual(f["userassist_entries"], ["C:\\Windows\\System32\\cmd.exe", "C:\\Tools\\nc.exe"])
        self.assertEqual(f["userassist_run_counts"]["C:\\Tools\\nc.exe"], 2)
        self.assertTrue(f["userassist_last_run"]["C:\\Tools\\nc.exe"].startswith("2022-"))
        self.assertEqual(f["run_values"], {"Updater": "C:\\Users\\Public\\upd.exe"})
        self.assertEqual(f["service_image_paths"]["evilsvc"], "C:\\ProgramData\\e.exe")
        self.assertEqual(f["usbstor_devices"], ["Disk&Ven_Kingston&Prod_DT&Rev_1.00"])
        self.assertEqual(f["usb_friendly_names"], ["Kingston DT USB Device"])
        self.assertEqual(f["mounted_devices"], ["\\DosDevices\\C:", "\\DosDevices\\E:"])
        self.assertEqual(f["install_date_utc"], "2023-11-14T22:13:20Z")
        self.assertEqual((f["amcache_paths"], f["amcache_sha1s"]), (["c:\\tools\\nc.exe"], ["ab" * 20]))
        self.assertEqual(f["root_key_name"], "CMI-CreateHive{2A7FB991-7BBE-4F9D-B91E-7CB51D4737F5}")
        self.assertIn("ControlSet001\\Services\\Spooler", f["key_paths"])
        self.assertEqual(f["key_count"], len(f["key_paths"]) + 1)  # The root has no path.

    def test_the_first_untimed_answer_is_the_right_field(self):
        values = {key: value for _, found in describe(ARTIFACTS) for key, value in found.items()}
        for prop, field, expected_value in REGISTRY_PROPERTIES:
            with self.subTest(prop=prop):
                if expected_value is not None:
                    self.assertEqual(values[field], expected_value)
                self.assertEqual(first_untimed_answer(prop, ARTIFACTS), formatted(prop, values[field]))

    def test_a_damaged_tree_keeps_the_header(self):
        broken = bytearray(ARTIFACTS)
        root = 0x1000 + struct.unpack_from("<I", ARTIFACTS, 0x24)[0]
        broken[root:root + 4] = b"\xff\xff\xff\x7f"  # The root cell's size: free and past the end.
        f = next(fields for label, fields in dfir_formats(bytes(broken)) if label == "regf")
        self.assertIn("file_type_name", f)
        self.assertNotIn("userassist_entries", f)


# --- Compression and the new readers ----------------------------------------------------------------

def raw_lznt1(data):
    """LZNT1 with every chunk stored uncompressed (header bit 15 clear)."""
    return b"".join(struct.pack("<H", 0x3000 | (len(data[i:i + 4096]) - 1)) + data[i:i + 4096]
                    for i in range(0, len(data), 4096)) + b"\0\0"


def literal_xpress(data):
    """Plain Xpress with only literals: a zero flag word before every 32 bytes."""
    return b"".join(b"\0\0\0\0" + data[i:i + 32] for i in range(0, len(data), 32))


def literal_lz4(data):
    extra, rest = (b"", len(data)) if len(data) < 15 else (None, len(data) - 15)
    if extra is None:
        extra = b"\xff" * (rest // 255) + bytes([rest % 255])
    return bytes([min(len(data), 15) << 4]) + extra + data


def mam(method, data, body):
    return b"MAM" + bytes([method]) + struct.pack("<I", len(data)) + body


def fields_of(data, label):
    return next(fields for name, fields in dfir_formats(data) if name == label)


def der(tag, body):
    size = len(body)
    length = bytes([size]) if size < 128 else bytes([0x80 | (size.bit_length() + 7) // 8]) + size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + body


def pkcs7_signed(cert):
    """A CMS SignedData: the certificate, and one signer naming it by issuer and serial, with a signingTime."""
    _, start, end = formats_dfir.der(cert, 0)
    _, tbs_start, tbs_end = formats_dfir.der(cert, start)
    parts, at = [], tbs_start
    while at < tbs_end:
        stop = formats_dfir.der(cert, at)[2]
        parts.append(cert[at:stop])
        at = stop
    serial, issuer = parts[1], parts[3]  # [0] version, serial, signature algorithm, issuer, ...
    sha256 = der(0x30, der(0x06, bytes.fromhex("608648016503040201")))
    signing_time = der(0x30, der(0x06, bytes.fromhex("2a864886f70d010905")) + der(0x31, der(0x17, b"261020120000Z")))
    signer = der(0x30, der(0x02, b"\x01") + der(0x30, issuer + serial) + sha256 + der(0xA0, signing_time)
                 + der(0x30, der(0x06, bytes.fromhex("2a8648ce3d040302"))) + der(0x04, b"sig"))
    signed = der(0x30, der(0x02, b"\x01") + der(0x31, sha256) + der(0x30, der(0x06, bytes.fromhex("2a864886f70d010701")))
                 + der(0xA0, cert) + der(0x31, signer))
    return der(0x30, der(0x06, formats_dfir.PKCS7_SIGNED_DATA) + der(0xA0, signed))


def signed_pe(pkcs7):
    """A PE32 whose certificate table (data directory 4, a file offset) holds one WIN_CERTIFICATE."""
    data = bytearray(0x200)
    data[:2], data[0x3C:0x40] = b"MZ", struct.pack("<I", 0x40)
    data[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<H", data, 0x40 + 24, 0x10B)
    entry = struct.pack("<IHH", 8 + len(pkcs7), 0x0200, 2) + pkcs7
    struct.pack_into("<II", data, 0x40 + 24 + 96 + 32, len(data), len(entry))
    return bytes(data) + entry


def ntfs_page(magic, size, usa_offset, body):
    """An NTFS multi-sector page with its update sequence applied the way the disk stores it."""
    page = bytearray(size)
    page[:4] = magic
    struct.pack_into("<HH", page, 4, usa_offset, size // 512 + 1)
    page[0x08:0x08 + len(body)] = body
    page[usa_offset:usa_offset + 2] = b"\x07\x00"
    for sector in range(1, size // 512 + 1):
        page[usa_offset + 2 * sector:usa_offset + 2 * sector + 2] = page[sector * 512 - 2:sector * 512]
        page[sector * 512 - 2:sector * 512] = b"\x07\x00"
    return bytes(page)


class CompressionTests(unittest.TestCase):
    def test_lznt1_and_xpress_back_references(self):
        chunk = b"\x08abc" + struct.pack("<H", 2 << 12 | 6)  # 3 literals, then offset 3, length 9.
        self.assertEqual(formats_dfir.lznt1(struct.pack("<H", 0xB000 | len(chunk) - 1) + chunk + b"\0\0"), b"abc" * 4)
        self.assertEqual(formats_dfir.xpress(struct.pack("<I", 1 << 28) + b"abc" + struct.pack("<H", 2 << 3 | 6), 12),
                         b"abc" * 4)
        self.assertEqual(formats_dfir.lz4_block(b"\x35abc\x03\x00", 12), b"abc" * 4)
        for broken in (lambda: formats_dfir.lznt1(struct.pack("<H", 0xB003) + b"\x01\xff\xff\x00"),
                       lambda: formats_dfir.xpress(struct.pack("<I", 1 << 31) + struct.pack("<H", 0xFF), 4),
                       lambda: formats_dfir.lz4_block(b"\x10a\x05\x00", 8)):
            with self.assertRaises((ValueError, IndexError)):  # Both read as "damaged" (formats_dfir._guarded).
                broken()

    def test_mam_lznt1_and_xpress_prefetch(self):
        inner = prefetch()
        for method, body, name in ((2, raw_lznt1(inner), "lznt1"), (3, literal_xpress(inner), "xpress")):
            with self.subTest(name=name):
                f = fields_of(mam(method, inner, body), "prefetch")
                self.assertEqual((f["executable_name"], f["compressed"], f["compression"]), ("CMD.EXE", True, name))

    def test_firefox_session_store(self):
        session = {"version": ["sessionrestore", 1], "windows": [{"tabs": [
            {"entries": [{"url": "https://a.example/", "title": "A"}, {"url": "https://b.example/x", "title": "B"}],
             "index": 2},
            {"entries": [{"url": "https://c.example/", "title": "C"}], "index": 1}]}]}
        text = json.dumps(session).encode()
        f = fields_of(b"mozLz40\0" + struct.pack("<I", len(text)) + literal_lz4(text), "mozlz4")
        self.assertEqual((f["window_count"], f["tab_count"]), (1, 2))
        self.assertEqual(f["tab_urls"], ["https://b.example/x", "https://c.example/"])
        self.assertEqual(f["tab_titles"], ["B", "C"])


class NewReaderTests(unittest.TestCase):
    def test_thumbcache_hiberfil_and_wim(self):
        cache = b"CMMM" + struct.pack("<II", 32, 1) + bytes(12) + (b"CMMM" + bytes(28)) * 3
        self.assertEqual(fields_of(cache, "thumbcache")["entry_count"], 3)
        hiber = bytearray(0x100)
        hiber[:4] = b"HIBR"
        struct.pack_into("<I", hiber, 0x0C, 0x168)
        struct.pack_into("<I", hiber, 0x18, 4096)
        struct.pack_into("<Q", hiber, 0x20, filetime(2026, 10, 20))
        f = fields_of(bytes(hiber), "hiberfil")
        self.assertEqual((f["page_size"], f["system_time_utc"], f["resumable"]), (4096, "2026-10-20T00:00:00Z", True))
        xml = ('﻿<WIM><IMAGE INDEX="1"><NAME>Windows 11 Pro</NAME><DESCRIPTION>Pro</DESCRIPTION></IMAGE>'
               '<IMAGE INDEX="2"><NAME>Windows 11 Home</NAME></IMAGE></WIM>').encode("utf-16-le")
        wim = bytearray(0xD0)
        wim[:8] = b"MSWIM\0\0\0"
        struct.pack_into("<IIII", wim, 8, 0xD0, 0x10D00, 2 | 0x40000, 32768)
        struct.pack_into("<HHI", wim, 40, 1, 1, 2)
        wim[0x48:0x4F] = len(xml).to_bytes(7, "little")
        struct.pack_into("<QQ", wim, 0x50, 0xD0, len(xml))
        struct.pack_into("<I", wim, 0x78, 1)
        f = fields_of(bytes(wim) + xml, "wim")
        self.assertEqual((f["compression"], f["image_count"], f["boot_index"]), ("lzx", 2, 1))
        self.assertEqual(f["image_names"], ["Windows 11 Pro", "Windows 11 Home"])

    def test_ext4_superblock(self):
        image = bytearray(4096)
        sb = 1024
        struct.pack_into("<7I", image, sb, 65536, 262144, 0, 1000, 60000, 0, 2)
        struct.pack_into("<5I", image, sb + 32, 32768, 32768, 8192, 1760000000, 1760000100)
        struct.pack_into("<HhHH", image, sb + 52, 3, -1, 0xEF53, 1)
        struct.pack_into("<H", image, sb + 88, 256)
        struct.pack_into("<3I", image, sb + 92, 0x3C, 0x2C2, 0x7B)
        image[sb + 104:sb + 120] = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
        image[sb + 120:sb + 126] = b"rootfs"
        image[sb + 136:sb + 137] = b"/"
        struct.pack_into("<I", image, sb + 0x108, 1750000000)
        f = fields_of(bytes(image), "ext")
        self.assertEqual((f["filesystem_type"], f["volume_name"], f["last_mounted_path"]), ("ext4", "rootfs", "/"))
        self.assertEqual((f["uuid"], f["block_size_bytes"], f["block_count"]), ("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", 4096, 262144))
        self.assertEqual((f["created_utc"], f["last_mount_utc"]), ("2025-06-15T15:06:40Z", "2025-10-09T08:53:20Z"))

    def test_fat32_and_exfat_boot_sectors(self):
        boot = bytearray(512)
        boot[:11] = b"\xeb\x58\x90MSDOS5.0"
        struct.pack_into("<HBHBHHBH", boot, 11, 512, 8, 32, 2, 0, 0, 0xF8, 0)
        struct.pack_into("<III", boot, 32, 2097152, 2041, 0)
        struct.pack_into("<I", boot, 44, 2)
        struct.pack_into("<I", boot, 67, 0x1A2B3C4D)
        boot[71:90] = b"EVIDENCE   FAT32   "
        boot[510:512] = b"\x55\xaa"
        f = fields_of(bytes(boot), "fat")
        self.assertEqual((f["volume_label"], f["volume_serial_number"], f["filesystem_type"]), ("EVIDENCE", "1A2B-3C4D", "FAT32"))
        self.assertEqual((f["cluster_size_bytes"], f["total_sectors"], f["sectors_per_fat"]), (4096, 2097152, 2041))
        ex = bytearray(8192)
        ex[:11] = b"\xeb\x76\x90EXFAT   "
        struct.pack_into("<QQ", ex, 64, 2048, 1048576)
        struct.pack_into("<6I", ex, 80, 128, 64, 4, 131000, 2, 0xCAFE1234)
        struct.pack_into("<HH", ex, 104, 0x0100, 0)
        ex[108:113] = bytes([9, 3, 1, 0x80, 7])
        ex[510:512] = b"\x55\xaa"
        ex[2048:2048 + 2 + 10] = b"\x83\x05" + "USB01".encode("utf-16-le")
        f = fields_of(bytes(ex), "exfat")
        self.assertEqual((f["volume_label"], f["volume_serial_number"], f["filesystem_revision"]), ("USB01", "CAFE-1234", "1.00"))
        self.assertEqual((f["cluster_size_bytes"], f["percent_in_use"]), (4096, 7))

    def test_legacy_evt(self):
        def record(number, event, source, computer, when):
            names = (source + "\0" + computer + "\0").encode("utf-16-le")
            length = 0x38 + len(names) + 4
            body = struct.pack("<I4s4IHHHH6I", length, b"LfLe", number, when, when, 0x40000000 | event, 4, 0, 0, 0,
                               0, 0, 0, 0, 0, 0)
            return body + names + struct.pack("<I", length)
        records = record(1, 7045, "Service Control Manager", "WS-01", 1760000000) + record(2, 4624, "Security", "WS-01", 1760000600)
        header = struct.pack("<I4s10I", 0x30, b"LfLe", 1, 1, 0x30, 0x30 + len(records), 3, 1, 0x80000, 1, 0, 0x30)
        f = fields_of(header + records, "evt")
        self.assertEqual((f["record_count"], f["header_record_count"], f["event_ids"]), (2, 2, [7045, 4624]))
        self.assertEqual((f["source_names"], f["computer_names"]), (["Service Control Manager", "Security"], ["WS-01"]))
        self.assertEqual((f["first_time_utc"], f["dirty"]), ("2025-10-09T08:53:20Z", True))

    def test_indx_and_logfile(self):
        def entry(name, created, namespace=1):
            raw = name.encode("utf-16-le")
            stream = struct.pack("<QQQQQQQII", 5, created, created, created, created, 0, 0, 0x20, 0) + bytes([len(name), namespace]) + raw
            length = (16 + len(stream) + 7) // 8 * 8
            return (struct.pack("<QHHI", 0x1000 + len(name), length, len(stream), 0) + stream).ljust(length, b"\0")
        entries = entry("secrets.docx", filetime(2026, 10, 1)) + entry("SECRET~1.DOC", filetime(2026, 10, 1), 2) \
            + entry("notes.txt", filetime(2026, 10, 2)) + struct.pack("<QHHI", 0, 16, 0, 2)
        header = struct.pack("<QQIIIB", 0, 0, 0x28, 0x28 + len(entries), 4072, 0)
        f = fields_of(ntfs_page(b"INDX", 4096, 0x28, header[:16] + header[16:] + bytes(0x40 - 0x08 - len(header)) + entries), "indx")
        self.assertEqual((f["file_names"], f["entry_count"]), (["secrets.docx", "notes.txt"], 3))
        self.assertEqual(f["created_times_utc"][1], "2026-10-02T00:00:00Z")
        restart = struct.pack("<QIIHhh", 0, 4096, 4096, 0x30, 1, 2)
        area = struct.pack("<QHHHHIHHQ", 0x5A5A, 1, 0xFFFF, 0, 2, 44, 0x40, 0x30, 0x400000)
        logfile = ntfs_page(b"RSTR", 4096, 0x1E, restart + bytes(0x30 - 0x08 - len(restart)) + area)
        f = fields_of(logfile + (b"RCRD" + bytes(4092)) * 2, "ntfs_logfile")
        self.assertEqual((f["version"], f["current_lsn"], f["log_file_size"]), ("2.1", 0x5A5A, 0x400000))
        self.assertEqual((f["clean_dismount"], f["record_page_count"]), (True, 2))

    def test_pkcs7_and_authenticode_signer(self):
        cert = base64.b64decode(CERT_B64)
        signed = pkcs7_signed(cert)
        for data, label in ((signed, "pkcs7"), (b"-----BEGIN PKCS7-----\n" + base64.encodebytes(signed) + b"-----END PKCS7-----\n", "pkcs7"),
                            (signed_pe(signed), "pe_signature")):
            with self.subTest(label=label, pem=data[:1] == b"-"):
                f = fields_of(data, label)
                self.assertEqual((f["certificate_count"], f["signer_subject_cn"]), (1, "anticipate.example.invalid"))
                self.assertEqual((f["digest_algorithm"], f["signing_time_utc"]), ("sha256", "2026-10-20T12:00:00Z"))
        self.assertTrue(fields_of(signed_pe(signed), "pe_signature")["signed"])
        self.assertEqual(first_untimed_answer("pe.signer_subject_cn", signed_pe(signed)), "anticipate.example.invalid")
        unsigned = signed_pe(signed)[:0x200]
        self.assertNotIn("pe_signature", [label for label, _ in dfir_formats(unsigned)])

    def test_damaged_new_formats_never_raise(self):
        for data in (b"CMMM" + bytes(20), b"HIBR" + bytes(60), b"MSWIM\0\0\0" + bytes(0xC8), b"mozLz40\0" + b"\xff" * 8,
                     b"INDX" + bytes(60), b"RSTR" + b"\xff" * 60, b"\x30\0\0\0LfLe" + b"\xff" * 40,
                     mam(2, b"x" * 64, b"\xff" * 16), mam(3, b"x" * 64, b"\xff" * 16)):
            with self.subTest(data=data[:8]):
                dfir_formats(data)  # A damaged file is "damaged" or no format, never an exception.


if __name__ == "__main__":
    unittest.main()
