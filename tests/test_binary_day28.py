"""Day 28 Binary: kinds the battery added to old blocks, and the d28 family/false-friend pair.

Generated data only, never event artifacts or answers. The wording is the issued question's.
"""
from io import BytesIO
import hashlib
import struct
from types import SimpleNamespace
import unittest
import zipfile

from huntress_ctf.solvers.binary import BinarySolver
from huntress_ctf.solvers._binary_assignment import sorted_lf_sha256, symbol_names
from huntress_ctf.solvers._binary_managed import Jar
from tests.test_binary import elf_fixture, pe_fixture
from tests.test_binary_assignment import archive_context, config_record, java_fixture
from tests.test_binary_payloads import packed_overlay

PREFIX = "In evidence.zip, Use all unit-- members in ZIP central-directory order. "
PRIMARY = ("In evidence.zip, Use the unique unit-- primary managed assembly whose basename starts unit-- and ends .dll; "
           ".runtimeconfig.json and dependency DLL members are delivery support only. ")
CAMPAIGN = ("Scan backward from the end of the member for literal HCFG magic and accept the first CRC32-valid decoded "
            "JSON record. Locate the unique CRC32-valid HCFG record: bytes 0..3 are ASCII HCFG, byte 4 is version, "
            "byte 5 is the XOR key, bytes 6..7 are the little-endian payload length, bytes 8..11 are the little-endian "
            "CRC32 of the decoded payload, and the payload begins at byte 12. XOR every payload byte with the one-byte "
            "key, verify CRC32, then parse the decoded UTF-8 JSON. Submit the exact string value of the decoded HCFG "
            "JSON object's top-level campaign property, without JSON quotes.")
SORTED = "sort strings by ascending code-unit order, join with one LF byte and no trailing LF, then SHA-256 those UTF-8 bytes."


def solve(files, prompts):
    return {c.answer_id: c.answer for c in BinarySolver().solve(archive_context(files, prompts))}


def managed_pe(text=b""):
    data = bytearray(pe_fixture())
    struct.pack_into("<II", data, 0x98 + 112 + 14 * 8, 0x1700, 72)    # CLR directory -> file 0x900.
    struct.pack_into("<IHHII", data, 0x900, 72, 2, 5, 0x1750, 40)     # cb, runtime 2.5, metadata.
    version = b"v4.0.30319\0"
    struct.pack_into("<4sHHII", data, 0x950, b"BSJB", 1, 1, 0, len(version))
    data[0x960:0x960 + len(version)] = version
    data[0x980:0x980 + len(text)] = text
    return bytes(data)


class Day28BinaryTests(unittest.TestCase):
    def test_member_count_and_colon_joined_digest_read_the_directory(self):
        files = {"unit--a.elf": b"first", "other--x.elf": b"not ours", "unit--b.elf": b"second"}
        prompts = [("unit_structural_artifact_count", PREFIX + "Count the unit-- members in the ZIP central directory."),
                   ("unit_structural_ordered_set_sha256", PREFIX + "Compute each unit-- member's lowercase SHA-256 in "
                    "ZIP central-directory order, join those digests with ASCII colon characters and no trailing "
                    "newline, then SHA-256 the resulting UTF-8 bytes.")]
        joined = ":".join(hashlib.sha256(blob).hexdigest() for blob in (b"first", b"second"))
        self.assertEqual(solve(files, prompts), {"unit_structural_artifact_count": "2",
                                                 "unit_structural_ordered_set_sha256": hashlib.sha256(joined.encode()).hexdigest()})

    def test_cli_runtime_and_latin1_or_utf16_text(self):
        prompts = [("unit_analysis_cli_runtime", PRIMARY + "Read the CLI header major and minor runtime bytes and submit "
                    "major.minor in base-10 with one dot."),
                   ("unit_analysis_has_decoy_branch", PRIMARY + "Evaluate this public predicate and submit lowercase true "
                    "or false: true exactly when the final bytes interpreted as Latin-1 or UTF-16LE contain the "
                    "case-sensitive text decoy.")]
        support = {"unit--app.runtimeconfig.json": b"{}", "unit--Dependency.dll": pe_fixture()}
        for text, expected in ((b"", "false"), ("decoy".encode("utf-16-le"), "true"), (b"decoy", "true"), (b"Decoy", "false")):
            with self.subTest(text=text):
                got = solve({"unit--app.dll": managed_pe(text), **support}, prompts)
                self.assertEqual(got, {"unit_analysis_cli_runtime": "2.5", "unit_analysis_has_decoy_branch": expected})

    def test_byte_or_symbol_predicates(self):
        elf = elf_fixture() + b"NimMain"
        ask = PREFIX + "Evaluate this public predicate and submit lowercase true or false: true exactly when the final bytes contain "
        prompts = [("unit_analysis_has_nim", ask + "NimString or NimMain."),
                   ("unit_analysis_has_symbol", ask + "FPC or any nonempty ELF symbol name contains demo_exp."),
                   # libfixture is in .dynstr bytes but names no symbol: the symbol clause reads names only.
                   ("unit_analysis_has_library", ask + "QQQ or any nonempty ELF symbol name contains libfixture.")]
        self.assertEqual(solve({"unit--native.elf": elf}, prompts), {
            "unit_analysis_has_nim": "true", "unit_analysis_has_symbol": "true", "unit_analysis_has_library": "false"})
        unknown = [("unit_analysis_has_odd", ask + "NimMain and also something else entirely.")]
        self.assertEqual(solve({"unit--native.elf": elf}, unknown), {})

    def test_symbol_counts_and_sorted_digest(self):
        prompts = [("unit_analysis_symbol_count", PREFIX + "Count ELF symbol-table entries whose resolved name is nonempty, "
                    "across the parsed symbol tables used by the ELF parser. Submit the count in base 10."),
                   ("unit_analysis_d_count", PREFIX + "From ELF symbol-table entries with nonempty resolved names, count "
                    "names that match /^demo_r|\\b_d_/. Submit the count in base 10."),
                   ("unit_analysis_handler_count", PREFIX + "Count the nonempty ELF symbol names matching /demo_(read|export)/."),
                   ("unit_analysis_handler_sha", PREFIX + "Collect every nonempty ELF symbol name matching "
                    "/demo_(read|export)/, " + SORTED)]
        self.assertEqual(solve({"unit--native.elf": elf_fixture()}, prompts), {  # .dynsym only: it is the table.
            "unit_analysis_symbol_count": "2", "unit_analysis_d_count": "1", "unit_analysis_handler_count": "2",
            "unit_analysis_handler_sha": hashlib.sha256(b"demo_export\ndemo_read").hexdigest()})

    def test_symtab_wins_over_dynsym_when_both_exist(self):
        # Day 28 d13: the grader counted .symtab alone (771 accepted, .symtab + .dynsym 1255 refused).
        name = lambda text: SimpleNamespace(name=text)
        both = SimpleNamespace(sections=[SimpleNamespace(kind=2), SimpleNamespace(kind=11)],
                               static_symbols=[name("local"), name("")], all_symbols=[name("local"), name(""), name("dyn")])
        self.assertEqual(symbol_names(both), ["local"])
        dynamic = SimpleNamespace(sections=[SimpleNamespace(kind=11)], static_symbols=[], all_symbols=[name("dyn")])
        self.assertEqual(symbol_names(dynamic), ["dyn"])
        self.assertEqual(sorted_lf_sha256(["b", "a", "b"]), hashlib.sha256(b"a\nb\nb").hexdigest())

    def test_conditional_branch_opcodes_in_text(self):
        data = bytearray(elf_fixture())
        data[0x100:0x108] = b"\x74\x0f\x84\x7f\x0f\x0f\x85\x90"
        data[0x120:0x124] = b"\x74\x75\x0f\x80"  # Past .text (0x100, 0x20 bytes): not counted.
        text = bytes(data[0x100:0x120])
        expected = sum(0x70 <= b <= 0x7f for b in text) + sum(
            text[i] == 0x0f and 0x80 <= text[i + 1] <= 0x8f for i in range(len(text) - 1))
        self.assertEqual(expected, 4)
        prompt = PREFIX + ("In the ELF .text bytes, count every 0x70..0x7f byte and every two-byte sequence 0x0f "
                           "followed by 0x80..0x8f; overlapping byte positions are considered by a single left-to-right byte scan.")
        self.assertEqual(solve({"unit--native.elf": bytes(data)}, [("unit_analysis_jcc", prompt)]), {"unit_analysis_jcc": str(expected)})

    def test_pk19_packing_keys_by_answer_id(self):
        blob = elf_fixture() + packed_overlay(config_record(), k1=0x2b, k2=0x05)
        prompt = PREFIX + ("Locate the final PK19 overlay directory. Render the requested one-byte packing key as 0x plus "
                           "exactly two lowercase hexadecimal digits.")
        prompts = [("unit_analysis_packing_key_1_hex", prompt), ("unit_analysis_packing_key_2_hex", prompt),
                   ("unit_analysis_packing_key_3_hex", prompt)]
        self.assertEqual(solve({"unit--packed.elf": blob}, prompts),
                         {"unit_analysis_packing_key_1_hex": "0x2b", "unit_analysis_packing_key_2_hex": "0x05"})
        self.assertEqual(solve({"unit--packed.elf": blob[:-1]}, prompts[:1]), {})  # A damaged overlay answers nothing.

    def test_jar_class_count_this_class_and_method_digest(self):
        blob = BytesIO()
        with zipfile.ZipFile(blob, "w") as archive:
            archive.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\nMain-Class: com.example.Fixture\r\n\r\n")
            archive.writestr("com/example/Fixture.class", java_fixture("com/example/Fixture", None))
            archive.writestr("com/example/Fixture$Result.class", java_fixture("com/example/Fixture$Result", None))
            archive.writestr("notes.txt", b"not a class")
        jar = blob.getvalue()
        self.assertEqual(Jar(jar).main.this_class, "com/example/Fixture")
        prompts = [("unit_analysis_class_count", PREFIX + "Count JAR central-directory entries whose names end .class."),
                   ("unit_analysis_class_name", PREFIX + "Read Main-Class from META-INF/MANIFEST.MF, locate that .class entry, "
                    "resolve its this_class constant-pool name, and submit the exact internal class name."),
                   ("unit_analysis_method_names_sha256", PREFIX + "Take the primary classfile's unique method names, " + SORTED)]
        self.assertEqual(solve({"unit--app.jar": jar}, prompts), {
            "unit_analysis_class_count": "2", "unit_analysis_class_name": "com/example/Fixture",
            "unit_analysis_method_names_sha256": hashlib.sha256(b"<init>\nmain").hexdigest()})

    def test_named_family_pair_ignores_the_false_friend_and_scans_backward(self):
        old, new = config_record({"campaign": "old-build"}), config_record({"campaign": "family-build"})
        family = elf_fixture() + old + new  # Two valid records: the backward scan takes the last one.
        prompts = [("unit_analysis_config_campaign", "In evidence.zip, Decode family-a.elf and family-b.elf and require their "
                    "config objects to be byte-for-byte equal before using the common family value; do not use "
                    "false-friend.elf. " + CAMPAIGN),
                   ("unit_analysis_false_friend_config_campaign", "In evidence.zip, Use the unique unit-- member whose "
                    "basename ends false-friend.elf. " + CAMPAIGN)]
        friend = elf_fixture() + config_record({"campaign": "look-alike"})
        files = {"unit--sample-false-friend.elf": friend, "unit--sample-family-a.elf": family, "unit--sample-family-b.elf": family}
        self.assertEqual(solve(files, prompts), {"unit_analysis_config_campaign": "family-build",
                                                 "unit_analysis_false_friend_config_campaign": "look-alike"})
        files["unit--sample-family-b.elf"] = elf_fixture() + old  # The family disagrees: no common value.
        self.assertEqual(solve(files, prompts), {"unit_analysis_false_friend_config_campaign": "look-alike"})


if __name__ == "__main__":
    unittest.main()
