"""Static reverse engineering (Day 30's traditional route): one `flag`, read from the bytes.

Every fixture is synthetic: the flag, the "binary" and its encodings are built here.
"""

import base64
import codecs
import io
from pathlib import Path
import shutil
import unittest
import zipfile
import zlib

from huntress_ctf.autopilot import build_context
from huntress_ctf.solvers import SOLVERS
from huntress_ctf.solvers.static_re import StaticFlagSolver, flag_pattern, flag_questions

FLAG = "flag{" + "5f0c1e2d3b4a69788796a5b4c3d2e1f0" + "}"
OTHER = "flag{" + "00112233445566778899aabbccddeeff" + "}"
ELF = b"\x7fELF\x02\x01\x01" + b"\0" * 9 + b"\x02\0\x3e\0" + bytes(range(256)) * 4
FORMAT = {"kind": "pattern", "syntax": "flag{...} with 32 lowercase hexadecimal characters"}


def context(data, questions=True, answer_ids=("flag",), answer_format=FORMAT, lane="reverse-engineering"):
    challenge = {"id": f"{lane}-day-30-crackme", "lane": lane, "day": 30, "mode": "single_solve",
                 "prompt": "Reverse the binary and recover the flag."}
    if questions:
        challenge["questions"] = [{"id": answer_id, "question": "What is the flag?", "artifact": "crackme",
                                   "answer_format": answer_format} for answer_id in answer_ids]
    attempt = {"answer_ids": list(answer_ids), "mode": "single_solve"}
    built, _ = build_context(challenge["id"], challenge, attempt, data, Path("crackme"), tuple(answer_ids), None)
    return built


def answers(data, **options):
    return [(c.answer_id, c.answer) for c in StaticFlagSolver().solve(context(data, **options))]


def stack_bytes(text, base=-0x40):
    """mov byte [rbp+d8], imm8 per character, as gcc -O0 builds a local char array."""
    return b"".join(b"\xc6\x45" + (base + i).to_bytes(1, "little", signed=True) + bytes([c])
                    for i, c in enumerate(text.encode()))


class StaticFlagTests(unittest.TestCase):
    def test_registered_with_the_lanes(self):
        self.assertIn("static-flag", [solver.name for solver in SOLVERS])

    def test_plain_flag_with_and_without_questions(self):
        data = ELF + b"Enter the password:\0" + FLAG.encode() + b"\0Wrong!\0"
        self.assertEqual(answers(data), [("flag", FLAG)])
        # Read the Rules' shape: answer_ids ["flag"] and no questions[] at all.
        self.assertEqual(answers(data, questions=False), [("flag", FLAG)])

    def test_decoys_and_ambiguity(self):
        decoy = ELF + b"flag{this_is_not_the_flag}\0" + FLAG.encode()
        self.assertEqual(answers(decoy), [("flag", FLAG)])
        self.assertEqual(answers(ELF + FLAG.encode() + b"\0" + OTHER.encode()), [])
        self.assertEqual(answers(ELF + b"Correct!\0Wrong!\0"), [])

    def test_single_byte_operations(self):
        raw = FLAG.encode()
        cases = {
            "xor": bytes(b ^ 0x5A for b in raw),
            "add": bytes((b + 0x21) & 0xFF for b in raw),
            "sub": bytes((b - 7) & 0xFF for b in raw),
            "rol": bytes(((b << 3) | (b >> 5)) & 0xFF for b in raw),
            "not": bytes(b ^ 0xFF for b in raw),
            "xor index": bytes(b ^ i for i, b in enumerate(raw)),
            "add index": bytes((b + i) & 0xFF for i, b in enumerate(raw)),
        }
        for name, encoded in cases.items():
            with self.subTest(name):
                self.assertEqual(answers(ELF + b"Wrong!\0" + encoded + b"\0"), [("flag", FLAG)])

    def test_text_and_encoded_strings(self):
        raw = FLAG.encode()
        cases = {
            "utf-16le (.NET user string)": FLAG.encode("utf-16-le"),
            "utf-16be": FLAG.encode("utf-16-be"),
            "rot13": codecs.encode(FLAG, "rot13").encode(),
            "reversed": FLAG[::-1].encode(),
            "base64": base64.b64encode(raw),
            "hex": raw.hex().encode(),
            "base32": base64.b32encode(raw),
            "base64 of base64": base64.b64encode(base64.b64encode(raw)),
            "rot13 of base64": codecs.encode(base64.b64encode(raw).decode(), "rot13").encode(),
        }
        for name, encoded in cases.items():
            with self.subTest(name):
                self.assertEqual(answers(ELF + b"\0" + encoded + b"\0"), [("flag", FLAG)])

    def test_stack_strings(self):
        self.assertEqual(answers(ELF + stack_bytes(FLAG) + b"\xc3"), [("flag", FLAG)])
        xored = "".join(chr(ord(c) ^ 0x11) for c in FLAG)
        self.assertEqual(answers(ELF + stack_bytes(xored) + b"\xc3"), [("flag", FLAG)])
        raw = FLAG.encode() + b"\0" * (-len(FLAG) % 8)
        movabs = b"".join(b"\x48\xb8" + raw[i:i + 8] + b"\x48\x89\x45" + bytes([0xC0 + i])
                          for i in range(0, len(raw), 8))
        self.assertEqual(answers(ELF + movabs + b"\xc3"), [("flag", FLAG)])

    def test_compiled_string_literals(self):
        # gcc -O0, char s[] = "flag{...}": movabs rax/rdx, imm64 then mov [rbp+d], rax/rdx,
        # the last qword overlapping the one before (39 bytes stored at 0, 8, 16, 24, 31).
        raw = (FLAG + "\0").encode()
        code = b""
        for start in (0, 8, 16, 24, len(raw) - 8):
            code += b"\x48\xb8" + raw[start:start + 8] + b"\x48\x89\x45" + bytes([0xD0 + start])
        self.assertEqual(answers(ELF + code + b"\xc3"), [("flag", FLAG)])
        # gcc -O2: the first 32 bytes are two 16-byte constants in .rodata (movdqa xmm0,
        # [rip+d]; movaps [rsp+d], xmm0) and the tail a movabs stored over the 32nd byte.
        base, code_at, data_at = 0x400000, 0x100, 0x200
        loads = b""
        for index, (disp, target) in enumerate(((b"\x04\x24", 0), (b"\x44\x24\x10", 16))):
            here = code_at + len(b"\x48\xba" + raw[31:39]) + len(loads) + 8
            loads += b"\x66\x0f\x6f\x05" + (data_at + target - here).to_bytes(4, "little", signed=True)
            loads += b"\x0f\x29" + disp
        code = b"\x48\xba" + raw[31:39] + loads + b"\x48\x89\x54\x24\x1f\xc3"
        image = bytearray(0x300)
        image[:4] = b"\x7fELF"
        image[4:7] = b"\x02\x01\x01"
        image[0x20:0x28] = (0x40).to_bytes(8, "little")  # e_phoff
        image[0x36:0x38], image[0x38:0x3a] = (56).to_bytes(2, "little"), (1).to_bytes(2, "little")
        image[0x40:0x44], image[0x44:0x48] = (1).to_bytes(4, "little"), (5).to_bytes(4, "little")  # PT_LOAD, R+X
        image[0x50:0x58] = base.to_bytes(8, "little")  # p_vaddr (p_offset 0)
        image[0x60:0x68] = len(image).to_bytes(8, "little")  # p_filesz
        image[code_at:code_at + len(code)] = code
        image[data_at:data_at + 32] = raw[:32]  # .rodata alone holds no whole flag.
        self.assertNotIn(FLAG.encode(), bytes(image))
        self.assertEqual(answers(bytes(image)), [("flag", FLAG)])

    def test_zlib_stream_and_zip_member(self):
        packed = zlib.compress(b"\xe3\0\0\0" + FLAG.encode() + b"\0" * 64)  # PyInstaller-style entry.
        self.assertEqual(answers(ELF + b"MEI\x0c\x0b\x0a\x0b\x0e" + packed), [("flag", FLAG)])
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as out:
            out.writestr("crackme", ELF + bytes(b ^ 0x42 for b in FLAG.encode()))
        self.assertEqual(answers(archive.getvalue()), [("flag", FLAG)])

    @unittest.skipUnless(shutil.which("upx"), "upx is not installed")
    def test_upx_packing_is_not_run(self):
        # Not a real UPX file: `upx -d` refuses it and the bytes alone answer nothing.
        self.assertEqual(answers(ELF + b"UPX!" + b"\0" * 64), [])

    def test_flag_shape_follows_the_format(self):
        self.assertEqual(flag_pattern("").pattern, r"flag\{[0-9a-f]{32}\}")
        self.assertEqual(flag_pattern("huntress{...} with 32 hex characters").pattern, r"huntress\{[0-9a-f]{32}\}")
        loose = {"kind": "pattern", "syntax": "flag{...} containing any printable characters"}
        self.assertEqual(answers(ELF + b"flag{R3v3rs1ng_1s_fun}\0", answer_format=loose),
                         [("flag", "flag{R3v3rs1ng_1s_fun}")])
        self.assertEqual(answers(ELF + b"flag{R3v3rs1ng_1s_fun}\0"), [])  # Huntress shape by default.

    def test_daily_lanes_are_left_alone(self):
        # Binary's d06/d07 "access_flags" and every other lane ID never reach the scan.
        data = ELF + FLAG.encode()
        self.assertEqual(flag_questions(context(data, answer_ids=("d06_analysis_access_flags",),
                                                answer_format={"kind": "exact_text"})), [])
        self.assertEqual(answers(data, answer_ids=("message",), answer_format={"kind": "pattern"}), [])
        many = tuple(f"set{i}.flag" for i in range(20))
        self.assertEqual(answers(data, answer_ids=many), [])


if __name__ == "__main__":
    unittest.main()
