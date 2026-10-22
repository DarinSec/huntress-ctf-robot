"""Generated instruction/data layouts for the narrow HCFG array-reference reader."""
import struct
import unittest

from huntress_ctf.solvers.binary import BinarySolver
from huntress_ctf.solvers._binary_formats import ELF
from huntress_ctf.solvers._binary_native import array_decoder_reference
from tests.test_binary_assignment import archive_context, config_record


def native_fixture(code_address=0x401000, record_address=0x405000):
    data = bytearray(0x700)
    data[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 62, 1, code_address, 0, 0x500, 0, 64, 0, 0, 64, 4, 3)
    names = b"\0.text\0.data\0.shstrtab\0"
    data[0x400:0x400 + len(names)] = names
    record = config_record()
    data[0x300:0x300 + len(record)] = record
    rows = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            (1, 1, 6, code_address, 0x100, 0x180, 0, 0, 16, 0),
            (7, 1, 3, record_address, 0x300, len(record), 0, 0, 16, 0),
            (13, 3, 0, 0, 0x400, len(names), 0, 0, 1, 0)]
    for i, row in enumerate(rows):
        struct.pack_into("<IIQQQQIIQQ", data, 0x500 + 64 * i, *row)
    # Generate a saved-register routine loading HCFG key/length, then its XOR loop.
    routine = bytearray.fromhex("53 41 54 41 55 41 56 48 8d 64 24 f8 48 89 fb")
    routine += bytes.fromhex("44 8a 24 25") + struct.pack("<I", record_address + 5)
    routine += b"\x48\xb8" + struct.pack("<Q", record_address)
    routine += bytes.fromhex("44 0f b6 68 07 41 c1 e5 08 0f b6 40 06 41 09 c5")
    routine += bytes.fromhex("49 63 f5 48 89 df 31 d2 e8")
    allocate = len(routine)
    routine += bytes(4)
    routine += bytes.fromhex("41 83 ed 01 45 85 ed 7c")
    empty = len(routine)
    routine += b"\0" + bytes.fromhex("41 be ff ff ff ff 0f 1f 00")
    loop = len(routine)
    routine += bytes.fromhex("41 83 c6 01 48 89 df e8")
    output = len(routine)
    routine += bytes(4) + bytes.fromhex("49 63 d6 48 8d 72 01 49 63 d6 8a 8a")
    payload_address = len(routine)
    routine += struct.pack("<I", record_address + 12)
    routine += bytes.fromhex("44 88 e2 30 ca 88 54 30 ff 45 39 f5 7f")
    back = len(routine)
    routine += b"\0"
    end = len(routine)
    routine += bytes.fromhex("48 8d 64 24 08 41 5e 41 5d 41 5c 5b c3")
    struct.pack_into("b", routine, empty, end - (empty + 1))
    struct.pack_into("b", routine, back, loop - (back + 1))
    for at in (allocate, output):
        struct.pack_into("<i", routine, at, code_address + 0x170 - (code_address + 0x10 + at + 4))
    data[0x110:0x110 + len(routine)] = routine
    data[0x270] = 0xc3  # Synthetic runtime function; never executed.
    return bytes(data), {"allocate": 0x110 + allocate, "output": 0x110 + output,
                         "empty": 0x110 + empty, "back": 0x110 + back, "payload_address": 0x110 + payload_address}


class NativeReferenceTests(unittest.TestCase):
    def test_addresses_and_calls_are_derived_from_each_synthetic_image(self):
        for code, record in ((0x401000, 0x405000), (0x501000, 0x612000), (0x101000, 0x201000)):
            with self.subTest(code=code, record=record):
                data, _ = native_fixture(code, record)
                self.assertEqual(array_decoder_reference(ELF(data), 0x300), 0x110)
        self.assertIsNone(array_decoder_reference(ELF(data), 0x301))

    def test_mapped_data_alone_or_similar_instruction_bytes_are_insufficient(self):
        data, offsets = native_fixture()
        for at in (0x110, offsets["empty"], offsets["back"], offsets["payload_address"]):
            changed = bytearray(data)
            changed[at] ^= 1
            with self.subTest(at=at):
                self.assertIsNone(array_decoder_reference(ELF(bytes(changed)), 0x300))
        for at in (offsets["allocate"], offsets["output"]):
            changed = bytearray(data)
            struct.pack_into("<i", changed, at, 0x100000)
            self.assertIsNone(array_decoder_reference(ELF(bytes(changed)), 0x300))
        for section, flags in ((1, 2), (2, 0)):
            changed = bytearray(data)
            struct.pack_into("<Q", changed, 0x500 + section * 64 + 8, flags)
            self.assertIsNone(array_decoder_reference(ELF(bytes(changed)), 0x300))

    def test_storage_requires_valid_config_and_recognized_native_reference(self):
        data, offsets = native_fixture()
        rule = ("Use all unit-- members in ZIP central-directory order. Scan for literal HCFG and use the first record. "
                "Submit the exact string value of the decoded HCFG JSON object's top-level domain property.")
        storage = "Locate HCFG. Apply these mutually exclusive rules: base64, raw_hcfg_section, raw_const_array or raw."
        prompts = [("unit_analysis_domain", rule), ("unit_analysis_storage", storage)]
        def answers(blob):
            return {c.answer_id:c.answer for c in BinarySolver().solve(archive_context({"unit--native.elf": blob}, prompts))}
        self.assertEqual(answers(data)["unit_analysis_storage"], "raw_const_array")
        damaged = bytearray(data)
        damaged[offsets["payload_address"]] ^= 1
        self.assertNotIn("unit_analysis_storage", answers(bytes(damaged)))
        damaged = bytearray(data)
        damaged[0x308] ^= 1
        self.assertEqual(answers(bytes(damaged)), {})

    def test_overlapping_allocated_virtual_mapping_is_not_evidence(self):
        data, _ = native_fixture()
        changed = bytearray(data)
        struct.pack_into("<QQ", changed, 0x500 + 3 * 64 + 8, 2, 0x405000)
        struct.pack_into("<Q", changed, 0x500 + 3 * 64 + 32, 0x100)
        self.assertIsNone(array_decoder_reference(ELF(bytes(changed)), 0x300))
