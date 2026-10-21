from io import BytesIO
from pathlib import Path
import struct
import unittest
import zipfile

from huntress_ctf.artifacts import artifact_kind
from huntress_ctf.containers import unwrap
from huntress_ctf.macho import field, slices
from huntress_ctf.solvers import SolveContext
from huntress_ctf.solvers.metadata import MetadataSolver
from huntress_ctf.workspace import render_triage

ARM64, X86_64, PPC = 0x0100000C, 0x01000007, 18


def thin(cputype, *, bits=64, order="<", filetype=2):
    magic = 0xFEEDFACF if bits == 64 else 0xFEEDFACE
    header = struct.pack(order + "7I", magic, cputype, 0, filetype, 0, 0, 0)
    return header + (b"\x00" * 4 if bits == 64 else b"")


def fat(*entries, wide=False):
    """entries: (claimed cputype, bytes) or (claimed cputype, bytes, forced offset)."""
    size = 32 if wide else 20
    position = 8 + size * len(entries)
    table, body = b"", b""
    for entry in entries:
        claimed, data = entry[:2]
        position += -position % 16
        body = body.ljust(position - 8 - size * len(entries), b"\x00")
        offset = entry[2] if len(entry) > 2 else position
        if wide:
            table += struct.pack(">IIQQII", claimed, 0, offset, len(data), 4, 0)
        else:
            table += struct.pack(">IIIII", claimed, 0, offset, len(data), 4)
        body += data
        position += len(data)
    return struct.pack(">II", 0xCAFEBABF if wide else 0xCAFEBABE, len(entries)) + table + body


def ar_member(name, data):
    header = f"{name:<16}{0:<12}{0:<6}{0:<6}{644:<8}{len(data):<10}".encode() + b"`\n"
    return header + data + (b"\n" if len(data) % 2 else b"")


def bsd_ar(**members):
    out = b"!<arch>\n" + ar_member("__.SYMDEF SORTED", b"\x00" * 8)
    for name, data in members.items():
        encoded = name.encode().ljust(-(-len(name) // 8) * 8, b"\x00")
        out += ar_member(f"#1/{len(encoded)}", encoded + data)
    return out


def zipped(**files):
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


class ParserTests(unittest.TestCase):
    def test_thin_both_byte_orders_and_widths(self):
        self.assertEqual(field("cpu_type_set", slices(thin(ARM64))), '["0x0100000c"]')
        self.assertEqual(field("cpu_type_set", slices(thin(PPC, bits=32, order=">"))), '["0x00000012"]')

    def test_fat_and_fat64_are_unique_and_ascending(self):
        for wide in (False, True):
            data = fat((ARM64, thin(ARM64)), (X86_64, thin(X86_64)), (ARM64, thin(ARM64)), wide=wide)
            self.assertEqual(field("cpu_type_set", slices(data)), '["0x01000007","0x0100000c"]')

    def test_slice_header_wins_over_fat_table_claim(self):
        found = slices(fat((ARM64, thin(X86_64))))
        self.assertEqual(field("cpu_type_set", found), '["0x01000007"]')
        self.assertEqual(found[0].claimed_cputype, ARM64)

    def test_truncated_and_non_macho_slices_do_not_count(self):
        data = fat((X86_64, thin(X86_64)), (ARM64, thin(ARM64), 10_000), (PPC, b"not a binary" * 4))
        found = slices(data)
        self.assertEqual([item.valid for item in found], [True, False, False])
        self.assertEqual(field("cpu_type_set", found), '["0x01000007"]')

    def test_ar_archives_bsd_gnu_and_inside_fat(self):
        library = bsd_ar(**{"a.o": thin(ARM64, filetype=1), "b.o": thin(X86_64, filetype=1)})
        self.assertEqual([item.path for item in slices(library)], ["a.o", "b.o"])
        gnu = (b"!<arch>\n" + ar_member("/", b"\x00" * 4)
               + ar_member("//", b"a_very_long_object_name.o/\n")
               + ar_member("/0", thin(PPC, bits=32, order=">")))
        self.assertEqual([item.path for item in slices(gnu)], ["a_very_long_object_name.o"])
        found = slices(fat((ARM64, bsd_ar(**{"a.o": thin(ARM64)}))))
        self.assertEqual([item.path for item in found], ["fat[0]/a.o"])

    def test_java_class_and_other_data_are_not_macho(self):
        java = b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 200
        for data in (java, b"MZ" + b"\x00" * 100, b""):
            self.assertEqual(slices(data), [])
        self.assertIsNone(field("cpu_type_set", []))
        self.assertIsNone(field("unknown_field", slices(thin(ARM64))))

    def test_artifact_kind_and_triage(self):
        self.assertIn("Mach-O 64-bit (arm64)", artifact_kind(thin(ARM64)))
        self.assertIn("universal", artifact_kind(fat((ARM64, thin(ARM64)))))
        artifact = zipped(**{"macos-001.bin": fat((ARM64, thin(X86_64)))})
        report = render_triage(artifact, unwrap(artifact).members)
        self.assertIn("## Mach-O slices", report)
        self.assertIn("fat table claims 0x0100000c", report)


class MetadataPropertyTests(unittest.TestCase):
    """Live question shape: the file is named in `artifact` as "<archive> -> <member>"."""

    def test_each_named_file_in_a_bundle(self):
        evidence = zipped(**{
            "macos-001.bin": thin(ARM64),
            "macos-002.bin": fat((X86_64, thin(X86_64)), (ARM64, thin(ARM64))),
            "macos-003.bin": bsd_ar(**{"x.o": thin(PPC, bits=32, order=">")}),
            "macos-004.bin": fat((ARM64, thin(X86_64)), (ARM64, thin(ARM64), 10_000)),
        })
        # Another evidence ZIP with the same member names must not leak into the answers.
        other = zipped(**{"macos-001.bin": thin(X86_64)})
        bundle = zipped(**{"metadata-day-20-evidence.zip": evidence, "other.zip": other})
        questions = [
            {"id": f"d20-macho-{n}-macho-cpu-type-set", "question": f"Determine macho.cpu_type_set for macos-{n}.bin.",
             "artifact": f"metadata-day-20-evidence.zip -> macos-{n}.bin"}
            for n in ("001", "002", "003", "004")
        ]
        questions.append({"id": "other", "question": "Determine macho.cpu_type_set for macos-001.bin.",
                          "artifact": "other.zip -> macos-001.bin"})
        ids = tuple(q["id"] for q in questions)
        context = SolveContext(
            "metadata-forensics-day-20-universal-appeal/mastery", {"lane": "metadata-forensics"},
            {"answer_ids": list(ids), "questions": questions}, bundle, Path("x"), ids,
        )
        answers = {a.answer_id: a.answer for a in MetadataSolver().solve(context)}
        self.assertEqual(answers, {
            "d20-macho-001-macho-cpu-type-set": '["0x0100000c"]',
            "d20-macho-002-macho-cpu-type-set": '["0x01000007","0x0100000c"]',
            "d20-macho-003-macho-cpu-type-set": '["0x00000012"]',
            "d20-macho-004-macho-cpu-type-set": '["0x01000007"]',
            "other": '["0x01000007"]',
        })

    def test_non_macho_file_gets_no_answer(self):
        question = {"id": "a", "question": "Determine macho.cpu_type_set for x.bin.", "artifact": "e.zip -> x.bin"}
        context = SolveContext(
            "metadata-forensics-day-20-x", {"lane": "metadata-forensics"},
            {"answer_ids": ["a"], "questions": [question]},
            zipped(**{"e.zip": zipped(**{"x.bin": b"MZ" + b"\0" * 64})}), Path("x"), ("a",),
        )
        self.assertEqual(MetadataSolver().solve(context), [])


if __name__ == "__main__":
    unittest.main()
