"""Synthetic regression coverage for the selectively combined Binary implementation."""
import base64
from dataclasses import replace
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import struct
import unittest
from unittest.mock import patch
import zipfile
import zlib

from huntress_ctf.containers import Member
from huntress_ctf.autopilot import build_context
from huntress_ctf.solvers._binary_answers import valid_answer
from huntress_ctf.solvers._binary_archive import aes_member, aes_members
from huntress_ctf.solvers._binary_assignment import AssignedArchive, config_at
from huntress_ctf.solvers._binary_files import BinaryFiles
from huntress_ctf.solvers.base import SolveContext
from huntress_ctf.solvers._binary_formats import ELF, ParseError
from huntress_ctf.solvers._binary_wasm import Wasm
from huntress_ctf.solvers.binary import BinarySolver
from huntress_ctf.solvers.metadata import Files
from tests.test_binary import bundle, context, elf_fixture, pe_fixture, solve
from tests.test_binary_assignment import archive_context, config_record
from tests.test_binary_payloads import section, uleb


def aes_fixture(data=b"synthetic bytes" * 100, *, method=8, version=2, strength=3,
                declared=None, compressed_plain=None):
    """Deterministic WinZip fixture, never event bytes or credentials."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    keysize = {1: 16, 2: 24, 3: 32}[strength]
    salt = bytes(range(keysize // 2))
    keys = hashlib.pbkdf2_hmac("sha1", b"fixture-password", salt, 1000, keysize * 2 + 2)
    if compressed_plain is None:
        compressor = zlib.compressobj(wbits=-15)
        plain = compressor.compress(data) + compressor.flush() if method == 8 else data
    else:
        plain = compressed_plain
    encryptor = Cipher(algorithms.AES(keys[:keysize]), modes.ECB()).encryptor()
    counters = b"".join(n.to_bytes(16, "little") for n in range(1, (len(plain) + 15) // 16 + 1))
    stream = encryptor.update(counters) + encryptor.finalize()
    cipher = bytes(a ^ b for a, b in zip(plain, stream))
    import hmac
    body = salt + keys[-2:] + cipher + hmac.new(keys[keysize:2 * keysize], cipher, "sha1").digest()[:10]
    name = b"unit--sample.bin"
    extra = struct.pack("<HHH2sBH", 0x9901, 7, version, b"AE", strength, method)
    crc = zlib.crc32(data) if version == 1 else 0
    size = len(data) if declared is None else declared
    local = struct.pack("<4s5H3I2H", b"PK\x03\x04", 51, 1, 99, 0, 0, crc, len(body), size, len(name), len(extra)) + name + extra + body
    central = struct.pack("<4s6H3I5H2I", b"PK\x01\x02", 51, 51, 1, 99, 0, 0, crc, len(body), size,
                          len(name), len(extra), 0, 0, 0, 0, 0) + name + extra
    return local + central + struct.pack("<4s4H2IH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local), 0)


def info(blob):
    with zipfile.ZipFile(BytesIO(blob)) as archive:
        return archive.infolist()[0]


def elf_extra(bits=64, endian="<", *, notes=None):
    data = bytearray(elf_fixture(bits, endian))
    interpreter = b"/lib/fixture-loader.so\0"
    note = struct.pack(endian + "III", 4, 4, 3) + b"GNU\0" + b"\x01\x02\xfe\xff"
    note = note if notes is None else notes
    data[0x380:0x380 + len(note)] = note
    data[0x3c0:0x3c0 + len(interpreter)] = interpreter
    phoff, width = (64, 56) if bits == 64 else (52, 32)
    if bits == 64:
        struct.pack_into(endian + "Q", data, 32, phoff)
        struct.pack_into(endian + "HH", data, 54, width, 2)
    else:
        struct.pack_into(endian + "I", data, 28, phoff)
        struct.pack_into(endian + "HH", data, 42, width, 2)
    for number, (kind, offset, size) in enumerate(((3, 0x3c0, len(interpreter)), (4, 0x380, len(note)))):
        fields = (kind, 0, offset, 0, 0, size, size, 4) if bits == 64 else (kind, offset, 0, 0, size, size, 0, 4)
        struct.pack_into(endian + ("IIQQQQQQ" if bits == 64 else "IIIIIIII"), data, phoff + number * width, *fields)
    # Reuse the validated .dynstr value as this synthetic object's SONAME.
    layout, shwidth, dynwidth = ("IIQQQQIIQQ", 64, 16) if bits == 64 else ("IIIIIIIIII", 40, 8)
    dynamic = list(struct.unpack_from(endian + layout, data, 0x400 + 4 * shwidth))
    dynamic[5] = 3 * dynwidth
    struct.pack_into(endian + layout, data, 0x400 + 4 * shwidth, *dynamic)
    struct.pack_into(endian + ("qQ" if bits == 64 else "iI"), data, 0x300 + dynwidth, 14, 1)
    return bytes(data)


def wasm_interface():
    def name(text):
        raw = text.encode()
        return uleb(len(raw)) + raw
    types = section(1, b"\x01\x60\x00\x00")
    imports = section(2, b"\x02" + name("env") + name("read") + b"\x00\x00"
                      + name("host") + name("memory") + b"\x02\x00\x01")
    exports = section(7, b"\x02" + name("run") + b"\x00\x00" + name("mem") + b"\x02\x00")
    return b"\0asm\x01\0\0\0" + types + imports + exports


class AnswerContractsTests(unittest.TestCase):
    def test_enum_and_integer_are_checks_not_answer_sources(self):
        self.assertFalse(valid_answer("a", {"kind": "enum", "accepted_values": ["b"]}))
        for value in ("1.0", "+1", " 1", "0x10", "١"):
            self.assertFalse(valid_answer(value, {"kind": "integer"}))
        self.assertTrue(valid_answer("-12", {"kind": "integer"}))

    def test_json_shape_compaction_and_duplicate_keys(self):
        contract = {"kind": "json", "syntax": "compact valid JSON array"}
        for value in ("{}", "[1, 2]", "[NaN]", "[1e999]", '[{"x":1,"x":2}]', "garbage"):
            self.assertFalse(valid_answer(value, contract))
        self.assertTrue(valid_answer('[1,"two"]', contract))
        self.assertTrue(valid_answer('[{"x":1}]', {"kind": "json", "syntax": "compact JSON array of objects"}))

    def test_hex_padding_and_exact_text_are_preserved(self):
        contract = {"kind": "pattern", "syntax": "0x plus exactly 8 lowercase hexadecimal digits"}
        self.assertTrue(valid_answer("0x000000af", contract))
        for value in ("0xaf", "0x000000AF", "000000af"):
            self.assertFalse(valid_answer(value, contract))
        self.assertTrue(valid_answer("  exact text\n", {"kind": "exact_text"}))
        self.assertFalse(valid_answer(None, {"kind": "exact_text"}))

    def test_solver_rejects_conflicting_public_enum(self):
        ctx = context(pe_fixture(), ["Determine binary.architecture."])
        ctx.attempt["questions"][0]["answer_format"] = {"kind": "enum", "accepted_values": ["arm64"]}
        self.assertEqual(BinarySolver().solve(ctx), [])

    def test_core_solver_needs_no_optional_analysis_or_archive_library(self):
        import builtins
        original = builtins.__import__
        def unavailable(name, *args, **kwargs):
            if name.split('.')[0] in {"cryptography", "pefile", "capstone"}:
                raise ImportError("optional dependency absent")
            return original(name, *args, **kwargs)
        entry = zipfile.ZipInfo("synthetic.bin")
        entry.file_size = 1
        entry.compress_type = 99
        with patch("builtins.__import__", side_effect=unavailable):
            self.assertEqual(solve(pe_fixture(), "Determine binary.architecture."), {"0": "x86_64"})
            self.assertEqual(aes_members(b"", [entry], ("fixture",), 100, 100, {0}), {})


class CombinedSelectionTests(unittest.TestCase):
    selector = "Use the unique unit-- primary managed assembly whose basename starts unit--variant- and ends .dll. "

    def test_single_member_still_must_match_prefix_and_suffix(self):
        for name in ("unit--sample.dll", "unit--variant-one.exe"):
            ctx = archive_context({name: pe_fixture()}, [("u_analysis_arch", self.selector + "Identify the processor architecture.")])
            self.assertEqual(BinarySolver().solve(ctx), [])

    def test_ordinal_hash_is_not_filtered_by_primary_predicate(self):
        ctx = archive_context({"nested/unit--sample.dll": pe_fixture()}, [
            ("u_analysis_arch", self.selector + "Identify the processor architecture."),
            ("u_artifact_sha256_1", "Use all unit-- members in ZIP central-directory order. Compute SHA-256 over the exact bytes of member 1.")])
        self.assertEqual([v.answer_id for v in BinarySolver().solve(ctx)], ["u_artifact_sha256_1"])

    def test_duplicate_basenames_are_ambiguous_but_ordinal_order_is_kept(self):
        ctx = archive_context({"z/unit--variant-one.dll": pe_fixture(), "a/unit--variant-one.dll": pe_fixture(32)}, [
            ("u_analysis_arch", self.selector + "Identify the processor architecture."),
            ("u_artifact_sha256_2", "Use all unit-- members in ZIP central-directory order. Compute SHA-256 over the exact bytes of member 2.")])
        got = BinarySolver().solve(ctx)
        self.assertEqual([(v.answer_id, v.answer) for v in got], [("u_artifact_sha256_2", hashlib.sha256(pe_fixture(32)).hexdigest())])

    def test_mastery_deliveries_with_identical_names_remain_separate(self):
        archives = [bundle(**{"dir/unit--variant-x.dll": pe_fixture(bits)}) for bits in (32, 64)]
        questions = [{"id": f"set{i}.u_analysis_arch", "question": self.selector + "Identify the processor architecture.",
                      "artifact": f"delivery {i}: evidence.zip"} for i in (1, 2, 3)]
        ctx = replace(context(archives[0], []), attempt={"artifacts": [{"filename": "evidence.zip"}] * 2, "questions": questions},
            answer_ids=tuple(q["id"] for q in questions),
            members=tuple(Member(f"delivery {i}: evidence.zip", data) for i, data in enumerate(archives, 1)))
        self.assertEqual([v.answer for v in BinarySolver().solve(ctx)], ["x86", "x86_64"])

    def test_mastery_does_not_eagerly_unpack_the_primary_delivery(self):
        archives = [bundle(**{"unit--variant-x.dll": pe_fixture(bits)}) for bits in (32, 64)]
        prompts = [{'id': f'set{i}.u_analysis_arch', 'question': self.selector + 'Identify the processor architecture.',
                    'artifact': f'delivery {i}: evidence.zip'} for i in (1, 2)]
        assignment = {'questions': prompts, 'artifacts': [{'filename': 'evidence.zip'}] * 2}
        extra = tuple(Member(f'delivery {i}: evidence.zip', data) for i, data in enumerate(archives, 1))
        ctx, lazy = build_context('binary-day-synthetic', {'lane': 'binary'}, assignment, archives[0],
                                  Path('synthetic.bin'), tuple(q['id'] for q in prompts), None, extra)
        with patch('huntress_ctf.containers.unwrap', side_effect=AssertionError('unexpected eager unpack')):
            self.assertEqual([v.answer for v in BinarySolver().solve(ctx)], ['x86', 'x86_64'])
            self.assertIsNone(lazy._members)

    def test_complete_nested_archive_reference_is_respected(self):
        inner = bundle(**{"path/unit--variant-x.dll": pe_fixture(32)})
        ctx = archive_context({"dir/evidence.zip": inner, "unit--variant-x.dll": pe_fixture(64)}, [
            ("u_analysis_arch", self.selector + "Identify the processor architecture.")])
        ctx.attempt["questions"][0]["artifact"] = "outer.zip -> dir/evidence.zip"
        self.assertEqual([v.answer for v in BinarySolver().solve(ctx)], ["x86"])

    def test_full_member_path_overrides_duplicate_basename(self):
        ctx = archive_context({"a/unit--variant-x.dll": pe_fixture(32), "b/unit--variant-x.dll": pe_fixture(64)}, [
            ("u_analysis_arch", self.selector + "Identify the processor architecture.")])
        ctx.attempt["questions"][0]["artifact"] = "evidence.zip -> b/unit--variant-x.dll"
        self.assertEqual([v.answer for v in BinarySolver().solve(ctx)], ["x86_64"])

    def test_missing_named_archive_does_not_become_root_delivery(self):
        ctx = archive_context({"unit--variant-x.dll": pe_fixture()}, [("u_analysis_arch", self.selector + "Identify the processor architecture.")])
        ctx.attempt['artifacts'] = [{'filename': 'actual.zip'}]
        self.assertEqual(BinarySolver().solve(ctx), [])

    def test_unnamed_single_delivery_uses_public_question_archive_name(self):
        ctx = archive_context({"unit--variant-x.dll": pe_fixture()}, [("u_analysis_arch", self.selector + "Identify the processor architecture.")])
        ctx.attempt['download'] = '/synthetic-assigned-bytes'
        self.assertEqual([v.answer for v in BinarySolver().solve(ctx)], ['x86_64'])

    def test_identical_empty_bytes_do_not_share_member_name_predicates(self):
        qs = [{'id': f'u_artifact_sha256_{i}', 'question': 'Use all unit-- members. Compute SHA-256 over the exact bytes of member 1.',
               'artifact': f'evidence.zip -> {name}'} for i, name in enumerate(('unit--empty', 'other--empty'))]
        ctx = replace(context(bundle(**{'unit--empty': b'', 'other--empty': b''}), []),
                      attempt={'questions': qs}, answer_ids=tuple(q['id'] for q in qs))
        self.assertEqual([v.answer_id for v in BinarySolver().solve(ctx)], ['u_artifact_sha256_0'])

    def test_hash_and_validated_config_are_cached(self):
        raw = pe_fixture() + config_record()
        ctx = archive_context({"unit--x.exe": raw}, [("u_analysis_x", "Use all unit-- members.")])
        reader = AssignedArchive(ctx, Files(ctx))
        data = reader.resolve(reader.questions[0])
        with patch("huntress_ctf.solvers._binary_assignment.hashlib.new", wraps=hashlib.new) as hashing:
            self.assertEqual(reader.digest(data), reader.digest(data))
            self.assertEqual(hashing.call_count, 1)
        with patch("huntress_ctf.solvers._binary_assignment.config_at", wraps=config_at) as parsing:
            self.assertEqual(reader.record(data, len(pe_fixture())), reader.record(data, len(pe_fixture())))
            self.assertEqual(parsing.call_count, 1)


class ExtraHcfgTests(unittest.TestCase):
    def candidates(self, encoded, directive, timed=False):
        prompt = "Use all unit-- members. " + directive + " Submit the exact string value of the decoded HCFG JSON object's top-level campaign property."
        ctx = archive_context({"unit--file.exe": pe_fixture() + b"\0" + encoded + b"\0"}, [("u_analysis_campaign", prompt)])
        if timed:
            ctx = replace(ctx, attempt={**ctx.attempt, "run_for_time": True, "deadline": "2026-10-24T13:01:00Z"})
        return BinarySolver().solve(ctx)

    def test_question_directed_base64url_and_hex(self):
        record = config_record({"campaign": "  exact fixture  "})
        for encoded, directive in ((base64.urlsafe_b64encode(record).rstrip(b"="), "Base64url-decode the unique valid HCFG carrier."),
                                   (record.hex().upper().encode(), "Hex-decode the unique hex-encoded HCFG carrier.")):
            self.assertEqual([v.answer for v in self.candidates(encoded, directive)], ["  exact fixture  "])

    def test_multiple_valid_carriers_are_ambiguous_unless_first_is_explicit(self):
        a, b = (config_record({"campaign": text}).hex().encode() for text in ("one", "two"))
        self.assertEqual(self.candidates(a + b"\0" + b, "Hex-decode the unique hex-encoded HCFG carrier."), [])
        self.assertEqual([v.answer for v in self.candidates(a + b"\0" + b, "Hex-decode the first valid hex-encoded HCFG carrier.")], ["one"])

    def test_invalid_json_and_nonstandard_constants_are_rejected(self):
        for payload in (b'{"x":1,"x":2}', b'{"x":NaN}', b'not JSON', b'[]'):
            record = struct.pack("<4sBBHI", b"HCFG", 1, 0, len(payload), zlib.crc32(payload)) + payload
            self.assertIsNone(config_at(record, 0))
            self.assertEqual(self.candidates(record.hex().encode(), "Hex-decode the unique hex-encoded HCFG carrier."), [])

    def test_no_implicit_encoded_scan_without_public_rule(self):
        # Timed races keep to the public storage rules; untimed runs search every carrier for
        # one CRC-valid record (a new day's wording), where a wrong guess costs one resent kind.
        self.assertEqual(self.candidates(config_record().hex().encode(), "Read the HCFG.", timed=True), [])
        self.assertEqual([c.answer for c in self.candidates(config_record().hex().encode(), "Read the HCFG.")],
                         ["synthetic-campaign"])

    def test_literal_precedes_explicit_encoded_fallback(self):
        literal = config_record({'campaign': 'literal'})
        encoded = config_record({'campaign': 'encoded'}).hex().encode()
        directive = 'First test literal HCFG occurrences, then Hex-decode the first valid hex-encoded HCFG carrier.'
        self.assertEqual([v.answer for v in self.candidates(literal + b'\0' + encoded, directive)], ['literal'])
        self.assertEqual([v.answer for v in self.candidates(encoded, directive)], ['encoded'])


class ExtraElfTests(unittest.TestCase):
    def test_interpreter_soname_notes_and_build_id_all_endians_and_widths(self):
        for bits in (32, 64):
            for endian in ("<", ">"):
                image = ELF(elf_extra(bits, endian))
                self.assertEqual(image.interpreter, "/lib/fixture-loader.so")
                self.assertEqual(image.soname, "libfixture.so")
                self.assertEqual(image.notes, [("GNU", 3, b"\x01\x02\xfe\xff")])
                self.assertEqual(image.build_id, "0102feff")

    def test_absent_fields_remain_unanswered(self):
        image = ELF(elf_fixture())
        self.assertIsNone(image.interpreter)
        self.assertIsNone(image.soname)
        self.assertIsNone(image.build_id)
        self.assertEqual(solve(elf_fixture(), "Determine elf.interpreter.", "Determine elf.build_id."), {})

    def test_metadata_names_are_not_offsets_or_hashes(self):
        self.assertEqual(solve(elf_extra(), "Report the interpreter file offset.", "Report the SONAME length.",
                               "Report the GNU build-id hash digest."), {})

    def test_duplicate_section_and_segment_note_range_is_read_once(self):
        data = bytearray(elf_extra())
        struct.pack_into("<H", data, 60, 7)
        struct.pack_into("<IIQQQQIIQQ", data, 0x580, 0, 7, 0, 0, 0x380, 20, 0, 0, 4, 0)
        self.assertEqual(ELF(bytes(data)).build_id, "0102feff")

    def test_question_properties_and_natural_queries(self):
        values = solve(elf_extra(), "Determine elf.interpreter.", "Determine elf.soname.", "Determine elf.build_id.",
                       "List the ELF note owner names as JSON.", "Report the GNU build-id.")
        self.assertEqual(values, {"0": "/lib/fixture-loader.so", "1": "libfixture.so", "2": "0102feff", "3": '["GNU"]', "4": "0102feff"})

    def test_truncated_notes_and_ambiguous_build_id_are_rejected(self):
        for note in (b"\0", struct.pack("<III", 4, 0xffff, 3) + b"GNU\0",
                     (struct.pack("<III", 4, 4, 3) + b"GNU\0abcd") * 2):
            self.assertEqual(solve(elf_extra(notes=note), "Determine elf.build_id."), {})

    def test_bad_interpreter_and_duplicate_soname(self):
        data = bytearray(elf_extra())
        data[0x3c0] = 0
        self.assertEqual(solve(bytes(data), "Determine elf.interpreter."), {})
        data = bytearray(elf_extra())
        struct.pack_into("<Q", data, 0x400 + 4 * 64 + 32, 4 * 16)
        struct.pack_into("<qQ", data, 0x320, 14, 1)
        self.assertEqual(solve(bytes(data), "Determine elf.soname."), {})


class ExtraWasmTests(unittest.TestCase):
    def test_import_export_metadata_and_question_routing(self):
        data = wasm_interface()
        self.assertEqual(Wasm(data).imports, [("env", "read", "function"), ("host", "memory", "memory")])
        self.assertEqual(Wasm(data).exports, [("run", "function", 0), ("mem", "memory", 0)])
        self.assertEqual(solve(data, "Determine wasm.imported_module_names.", "Determine wasm.exported_function_names.",
                               "List imported function names as JSON."), {"0": '["env","host"]', "1": '["run"]', "2": '["read"]'})

    def test_invalid_indices_duplicate_exports_and_truncation_fail_closed(self):
        data = wasm_interface()
        for malformed in (data[:-1], data[:-1] + b"\x01", data + section(7, b"\0")):
            self.assertEqual(solve(malformed, "Determine wasm.imports."), {})

    def test_empty_module_has_empty_interface(self):
        self.assertEqual(solve(b"\0asm\x01\0\0\0", "Determine wasm.imports.", "Determine wasm.exports."), {"0": "[]", "1": "[]"})


try:
    import cryptography
except ImportError:
    cryptography = None


@unittest.skipUnless(cryptography, "optional cryptography is unavailable")
class AesFallbackTests(unittest.TestCase):
    def test_generic_full_member_reference_uses_shared_aes_reader(self):
        blob = aes_fixture(pe_fixture())
        ctx = context(blob, ['Determine binary.architecture.'], reference='evidence.zip -> unit--sample.bin')
        ctx = replace(ctx, challenge={**ctx.challenge, 'instructions': 'The archive password is fixture-password.'})
        with patch('huntress_ctf.solvers._binary_files._external_unzip', return_value={}):
            self.assertEqual([v.answer for v in BinarySolver().solve(ctx)], ['x86_64'])

    def test_mastery_unpacks_one_delivery_window_at_a_time(self):
        # Day 27: eleven ~90 MB AES sets held at once got the solver killed on the 1.9 GB Homebase.
        blobs = [aes_fixture(data) for data in (pe_fixture(32), pe_fixture(64), elf_fixture())]
        questions = [dict(id=f"set{n}.arch", question="Determine binary.architecture.",
                          artifact=f"delivery {n}: evidence.zip -> unit--sample.bin") for n in (1, 2, 3)]
        attempt = {"questions": questions, "artifacts": [{"filename": "evidence.zip"}] * 3}
        members = tuple(Member(f"delivery {n}: evidence.zip", blob) for n, blob in enumerate(blobs, 1))
        ctx = SolveContext("binary-day-synthetic", {"lane": "binary", "instructions": "The archive password is fixture-password."},
                           attempt, blobs[0], Path("synthetic.bin"), tuple(q["id"] for q in questions), members)
        held, read_index = [], BinaryFiles.read_index

        def spy(files, blob, index):
            data = read_index(files, blob, index)
            held.append(len(files.decrypted))
            return data

        with patch('huntress_ctf.solvers._binary_files._external_unzip', side_effect=lambda *args: {}):
            with patch.dict(os.environ, {"HUNTRESS_BINARY_WINDOW": "1"}), patch.object(BinaryFiles, "read_index", spy):
                lean = {v.answer_id: v.answer for v in BinarySolver().solve(ctx)}
            with patch.dict(os.environ, {"HUNTRESS_BINARY_WINDOW": "8"}):
                wide = {v.answer_id: v.answer for v in BinarySolver().solve(ctx)}
        self.assertEqual(lean, wide)
        self.assertEqual((lean["set1.arch"], lean["set2.arch"]), ("x86", "x86_64"))
        self.assertIn("set3.arch", lean)
        self.assertEqual(max(held), 1)

    def test_both_methods_versions_and_strengths(self):
        data = bytes(range(256)) * 700
        for method in (0, 8):
            for version in (1, 2):
                for strength in (1, 2, 3):
                    blob = aes_fixture(data, method=method, version=version, strength=strength)
                    self.assertEqual(aes_member(blob, info(blob), "fixture-password", len(data)), data)

    def test_wrong_password_and_manipulated_authentication(self):
        blob = aes_fixture()
        with self.assertRaises(ParseError):
            aes_member(blob, info(blob), "wrong", 10000)
        entry = info(blob)
        start = entry.header_offset + 30 + len(entry.filename) + len(entry.extra)
        for at in (start, start + 16, start + 18, start + entry.compress_size - 1):
            mutated = bytearray(blob)
            mutated[at] ^= 1
            with patch("huntress_ctf.solvers._binary_archive.zlib.decompressobj") as decompression:
                with self.assertRaises(ParseError):
                    aes_member(bytes(mutated), entry, "fixture-password", 10000)
                decompression.assert_not_called()

    def test_local_metadata_disagreement_and_ae1_crc_mismatch(self):
        blob = aes_fixture(version=1)
        entry = info(blob)
        malformed = bytearray(blob)
        malformed[30] ^= 1
        with self.assertRaises(ParseError):
            aes_member(bytes(malformed), entry, "fixture-password", 10000)
        # Both directory and local CRC may agree yet still disagree with plaintext.
        entry.CRC ^= 1
        malformed = bytearray(blob)
        struct.pack_into("<I", malformed, 14, entry.CRC)
        with self.assertRaises(ParseError):
            aes_member(bytes(malformed), entry, "fixture-password", 10000)

    def test_truncation_stream_trailing_bytes_and_expansion_limit(self):
        blob = aes_fixture()
        with self.assertRaises((ParseError, zipfile.BadZipFile)):
            aes_member(blob[:50], info(blob), "fixture-password", 10000)
        cases = [aes_fixture(declared=1), aes_fixture(compressed_plain=b"\x03"),
                 aes_fixture(compressed_plain=zlib.compress(b"x")[2:-4] + b"trailing")]
        for malformed in cases:
            with self.assertRaises(ParseError):
                aes_member(malformed, info(malformed), "fixture-password", 10000)
        with self.assertRaises(ParseError):
            aes_member(blob, info(blob), "fixture-password", 1)

    def test_fallback_is_cached_once_and_external_backend_stays_default(self):
        blob = aes_fixture(pe_fixture())
        ctx = archive_context({}, [("u_analysis_arch", "Use all unit-- members. Identify the processor architecture."),
                                  ("u_analysis_bits", "Use all unit-- members. Report the bitness.")])
        ctx = replace(ctx, artifact=blob)
        with patch("huntress_ctf.solvers._binary_files._external_unzip", return_value={0: pe_fixture()}) as primary, \
             patch("huntress_ctf.solvers._binary_files.aes_members") as fallback:
            self.assertEqual(len(BinarySolver().solve(ctx)), 2)
            self.assertEqual(primary.call_count, 1)
            fallback.assert_not_called()
        with patch("huntress_ctf.solvers._binary_files._external_unzip", return_value={}) as primary, \
             patch("huntress_ctf.solvers._binary_files.aes_members", return_value={}) as fallback:
            self.assertEqual(BinarySolver().solve(ctx), [])
            self.assertEqual(primary.call_count, 1)
            self.assertEqual(fallback.call_count, 1)

    def test_aliases_of_one_delivery_do_not_repeat_decryption(self):
        blob = aes_fixture(pe_fixture())
        qs = [{'id': f'u_analysis_{i}', 'question': 'Use all unit-- members. Identify the processor architecture.',
               'artifact': reference} for i, reference in enumerate(('evidence.zip', 'artifact'))]
        ctx = replace(context(blob, []), attempt={'artifacts': [{'filename': 'evidence.zip'}], 'questions': qs},
                      answer_ids=tuple(q['id'] for q in qs))
        with patch('huntress_ctf.solvers._binary_files._external_unzip', return_value={0: pe_fixture()}) as decrypt:
            self.assertEqual([v.answer for v in BinarySolver().solve(ctx)], ['x86_64', 'x86_64'])
            self.assertEqual(decrypt.call_count, 1)

    def test_actual_fallback_and_external_reader_produce_identical_bytes(self):
        from huntress_ctf.containers import _external_unzip
        data = pe_fixture()
        blob = aes_fixture(data)
        entry = info(blob)
        result = aes_members(blob, [entry], ("wrong", "fixture-password"), 10000, 10000, {0})
        self.assertEqual(result, {0: data})
        external = _external_unzip(blob, [entry], ("fixture-password",), 10000)
        if external:
            self.assertEqual(result, external)

    def test_missing_optional_library_is_a_clean_unknown(self):
        import builtins
        original = builtins.__import__
        def unavailable(name, *args, **kwargs):
            if name.startswith("cryptography"):
                raise ImportError("optional dependency absent")
            return original(name, *args, **kwargs)
        blob = aes_fixture()
        with patch("builtins.__import__", side_effect=unavailable):
            self.assertEqual(aes_members(blob, [info(blob)], ("fixture-password",), 10000, 10000, {0}), {})


if __name__ == "__main__":
    unittest.main()
