import gzip
from io import BytesIO
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib

from huntress_ctf import containers
from huntress_ctf.containers import UnzipTool, passwords_from, unwrap, unzip_tool
from huntress_ctf.solvers import LayeredDecodeSolver, SolveContext
from huntress_ctf.workspace import write_workspace

def _crc_table():
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        table.append(c)
    return table


_CRC_TABLE = _crc_table()


def _crc_byte(crc, byte):
    return (crc >> 8) ^ _CRC_TABLE[(crc ^ byte) & 0xFF]


def zipcrypto(name: str, data: bytes, password: bytes) -> bytes:
    """A one-entry ZIP with PKWARE traditional encryption (stdlib can only decrypt)."""
    keys = [0x12345678, 0x23456789, 0x34567890]

    def update(byte):
        keys[0] = _crc_byte(keys[0], byte)
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = _crc_byte(keys[2], keys[1] >> 24)

    def encrypt(plain: bytes) -> bytes:
        out = bytearray()
        for byte in plain:
            temp = (keys[2] | 2) & 0xFFFF
            out.append(byte ^ (((temp * (temp ^ 1)) >> 8) & 0xFF))
            update(byte)
        return bytes(out)

    for byte in password:
        update(byte)
    crc = zlib.crc32(data)
    body = encrypt(os.urandom(11) + bytes([crc >> 24])) + encrypt(data)
    raw_name = name.encode()
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 1, 0, 0, 0x21, crc,
                        len(body), len(data), len(raw_name), 0) + raw_name + body
    central = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 1, 0, 0, 0x21, crc,
                          len(body), len(data), len(raw_name), 0, 0, 0, 0, 0, 0) + raw_name
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


def zipped(entries):
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return buffer.getvalue()


class ContainerTests(unittest.TestCase):
    def test_zipcrypto_with_published_password(self):
        archive = zipcrypto("sample.ps1", b"Write-Host 'hi'", b"infected")
        result = unwrap(archive)
        self.assertEqual([(m.name, m.data) for m in result.members], [("sample.ps1", b"Write-Host 'hi'")])
        wrong = unwrap(archive, ("nope",))
        self.assertEqual(wrong.members, ())
        self.assertIn("could not be decrypted", wrong.notes[0])

    @unittest.skipUnless(unzip_tool(), "no bsdtar, 7-Zip, or unzip on this machine")
    def test_large_encrypted_zip_uses_the_external_tool(self):
        data = os.urandom(64 * 1024)
        archive = zipcrypto("sample.bin", data, b"infected")
        calls = []
        real = containers._run_bounded

        def spy(command, limit):
            calls.append(command)
            return real(command, limit)

        with patch("huntress_ctf.containers._run_bounded", spy):
            result = unwrap(archive, ("wrong", "infected"))
        self.assertEqual([(m.name, m.data) for m in result.members], [("sample.bin", data)])
        self.assertEqual(len(calls), 2)  # the wrong password fails, the published one works
        self.assertEqual(result.notes, ())

    def test_unverified_tool_output_falls_back_to_the_standard_library(self):
        archive = zipcrypto("note.txt", b"answer: flag{fallback}", b"infected")
        wrong_bytes = lambda command, limit: b"x" * limit  # right length, wrong CRC
        for tool, runner in ((UnzipTool("bsdtar", "tar"), wrong_bytes), (None, None)):
            with self.subTest(tool=tool), \
                 patch("huntress_ctf.containers.FAST_UNZIP_MIN_BYTES", 0), \
                 patch("huntress_ctf.containers.unzip_tool", lambda: tool), \
                 patch("huntress_ctf.containers._run_bounded", runner):
                result = unwrap(archive)
            self.assertEqual([m.data for m in result.members], [b"answer: flag{fallback}"])

    def test_tool_commands_stream_to_stdout(self):
        for kind, expected in (("bsdtar", "-xOf"), ("7z", "-so"), ("unzip", "-p")):
            command = UnzipTool(kind, "tool").command("a.zip", "infected")
            self.assertIn(expected, command)
            self.assertIn("a.zip", command)

    def test_passwords_from_instructions_come_first(self):
        self.assertEqual(passwords_from("The archive password is hunter2."), ("hunter2", "infected"))
        self.assertEqual(passwords_from("No secrets here."), ("infected",))

    def test_nested_gzip_tar_and_zip(self):
        inner = zipped([("a/flag.txt", b"x"), ("b.txt", b"y")])
        tar_buffer = BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
            info = tarfile.TarInfo("inner.zip")
            info.size = len(inner)
            archive.addfile(info, BytesIO(inner))
        result = unwrap(gzip.compress(tar_buffer.getvalue()))
        self.assertEqual(
            sorted(member.name for member in result.members),
            ["gunzip/inner.zip/a/flag.txt", "gunzip/inner.zip/b.txt"],
        )

    def test_size_and_member_limits(self):
        archive = zipped([("one", b"1" * 100), ("two", b"2" * 100), ("three", b"3")])
        with patch("huntress_ctf.containers.MAX_TOTAL_BYTES", 150):
            result = unwrap(archive)
        self.assertEqual([member.name for member in result.members], ["one", "three"])
        self.assertEqual(result.notes, ("Size limit: skipped 'two'.",))
        with patch("huntress_ctf.containers.MAX_MEMBERS", 2):
            self.assertEqual(len(unwrap(archive).members), 2)

    def test_packages_stay_whole_so_later_samples_are_reached(self):
        # Day 23 Binary: one JAR's 3,134 classes filled the member limit before d08-d23.
        jar = zipped([("META-INF/MANIFEST.MF", b"Main-Class: a.B\n")] + [(f"c{i}.class", b"\xca\xfe") for i in range(9)])
        mislabeled = zipped([("AndroidManifest.xml", b"\x03\x00"), ("classes.dex", b"dex\n")])
        bundle = zipped([("d07--sample.jar", jar), ("d08--app.bin", mislabeled),
                         ("d09--inner.zip", zipped([("x.txt", b"x")])), ("d10--sample.elf", b"\x7fELF")])
        with patch("huntress_ctf.containers.MAX_MEMBERS", 4):
            result = unwrap(bundle)
        self.assertEqual([member.name for member in result.members],
                         ["d07--sample.jar", "d08--app.bin", "d09--inner.zip/x.txt", "d10--sample.elf"])
        self.assertEqual(result.members[0].data, jar)

    def test_plain_bytes_have_no_members(self):
        self.assertEqual(unwrap(b"just text").members, ())

    def test_workspace_names_stay_inside_and_are_not_executable(self):
        archive = zipped([("../../evil.exe", b"MZ"), ("CON", b"x")])
        result = unwrap(archive)
        with tempfile.TemporaryDirectory() as directory:
            folder = write_workspace(
                Path(directory), "../c", challenge={}, attempt={}, artifact=archive,
                members=result.members,
            )
            self.assertEqual(folder.parent, Path(directory).resolve())
            names = sorted(path.name for path in (folder / "members").iterdir())
            self.assertEqual(names, ["000-evil.exe.bin", "001-CON.bin"])
            self.assertIn("Unpacked members", (folder / "triage.md").read_text(encoding="utf-8"))

    def test_layered_solver_reads_members(self):
        phrase = b"Well done. Submit this exact answer to the Game Master: amber-fox-7"
        archive = zipcrypto("note.txt", phrase.hex().encode(), b"infected")
        context = SolveContext("c", {}, {"answer_ids": ["a"]}, archive, Path("x"), ("a",),
                               members=unwrap(archive).members)
        answers = LayeredDecodeSolver().solve(context)
        self.assertEqual([a.answer for a in answers], ["amber-fox-7"])
        self.assertEqual(answers[0].chain, ("hex",))


if __name__ == "__main__":
    unittest.main()


try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    Cipher = None


def aes_zip(name, content, password, *, tamper=False):
    """One WinZip AES-256 (AE-2) deflated entry, built byte by byte like 7-Zip writes it."""
    import hashlib
    import hmac
    salt = bytes(range(16))
    keys = hashlib.pbkdf2_hmac("sha1", password.encode(), salt, 1000, 66)
    deflater = zlib.compressobj(9, zlib.DEFLATED, -15)
    plain = deflater.compress(content) + deflater.flush()
    blocks = b"".join(n.to_bytes(16, "little") for n in range(1, len(plain) // 16 + 2))
    stream = Cipher(algorithms.AES(keys[:32]), modes.ECB()).encryptor().update(blocks)
    cipher_text = bytes(a ^ b for a, b in zip(plain, stream))
    if tamper:
        cipher_text = bytes([cipher_text[0] ^ 1]) + cipher_text[1:]
    code = hmac.new(keys[32:64], cipher_text, hashlib.sha1).digest()[:10]
    data = salt + keys[64:] + cipher_text + code
    extra = struct.pack("<HHH2sBH", 0x9901, 7, 2, b"AE", 3, 8)
    encoded = name.encode()
    local = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 51, 1, 99, 0, 0, 0, len(data), len(content),
                        len(encoded), len(extra)) + encoded + extra + data
    central = struct.pack("<4sHHHHHHIIIHHHHHII", b"PK\x01\x02", 51, 51, 1, 99, 0, 0, 0, len(data),
                          len(content), len(encoded), len(extra), 0, 0, 0, 0, 0) + encoded + extra
    end = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


@unittest.skipIf(Cipher is None, "the cryptography package is not installed")
class AesZipTests(unittest.TestCase):
    def setUp(self):
        patcher = patch("huntress_ctf.containers.unzip_tool", return_value=None)  # Python path only.
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_aes_entries_unpack_in_python(self):
        content = b"<?php // descriptor ...\n" * 50
        result = unwrap(aes_zip("polyglot-php-stager.php", content, "infected"))
        self.assertEqual(result.members, (containers.Member("polyglot-php-stager.php", content),))
        self.assertEqual(result.notes, ())

    def test_wrong_password_or_tampered_bytes_give_a_note_not_data(self):
        for archive in (aes_zip("a.ps1", b"x" * 100, "other"), aes_zip("a.ps1", b"x" * 100, "infected", tamper=True)):
            result = unwrap(archive)
            self.assertEqual(result.members, ())
            self.assertIn("AES-encrypted entry", result.notes[0])


class CounterBlockTests(unittest.TestCase):
    def test_counter_blocks_match_packing_each_block(self):
        for first, count in ((1, 0), (1, 1), (1, 4097), (65537, 300), ((1 << 64) - 2, 4)):
            expected = b"".join(n.to_bytes(16, "little") for n in range(first, first + count))
            self.assertEqual(containers.winzip_counter_blocks(first, count), expected)
