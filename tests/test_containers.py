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

from huntress_ctf.containers import passwords_from, unwrap
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
