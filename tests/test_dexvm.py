"""Synthetic DEX files for dexvm.py: Day 23's computed Release.code(), built instruction by instruction.

The builder writes a minimal classes.dex (one class, its methods and code items) so the
emulator is checked against Python's own 64-bit arithmetic, never against a real app.
"""

from io import BytesIO
import json
import struct
import unittest
import zipfile

from huntress_ctf import dexvm
from huntress_ctf.solvers.mobile_puzzle import answer_code

M64 = (1 << 64) - 1
K1, K2 = 0x2F0E43A1C59B7D13, 0x9E3779B97F4A7C15


def uleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def build_dex(strings, types, protos, methods, class_type, direct_methods):
    """types: string indexes; protos: (return type, [param types]); methods: (class, proto, name)."""
    header = 0x70
    sizes = [len(strings), len(types), len(protos), 0, len(methods), 1]
    offsets, at = [], header
    for count, width in zip(sizes, (4, 4, 12, 8, 8, 32)):
        offsets.append(at if count else 0)
        at += count * width
    data = bytearray(at)
    blobs = []

    def place(blob, align=1):
        nonlocal data
        while len(data) % align:
            data.append(0)
        start = len(data)
        data += blob
        return start

    for index, text in enumerate(strings):
        raw = text.encode()
        struct.pack_into("<I", data, offsets[0] + 4 * index, place(uleb(len(text)) + raw + b"\0"))
    for index, string in enumerate(types):
        struct.pack_into("<I", data, offsets[1] + 4 * index, string)
    for index, (ret, params) in enumerate(protos):
        params_at = place(struct.pack("<I", len(params)) + b"".join(struct.pack("<H", p) for p in params), 4) if params else 0
        struct.pack_into("<III", data, offsets[2] + 12 * index, 0, ret, params_at)
    for index, (cls, proto, name) in enumerate(methods):
        struct.pack_into("<HHI", data, offsets[4] + 8 * index, cls, proto, name)
    codes = []
    for method_index, flags, registers, ins, insns in direct_methods:
        body = struct.pack("<HHHHII", registers, ins, 4, 0, 0, len(insns)) + struct.pack(f"<{len(insns)}H", *insns)
        codes.append((method_index, flags, place(body, 4)))
    class_data = uleb(0) + uleb(0) + uleb(len(codes)) + uleb(0)
    previous = 0
    for method_index, flags, code_at in codes:
        class_data += uleb(method_index - previous) + uleb(flags) + uleb(code_at)
        previous = method_index
    class_at = place(class_data)
    struct.pack_into("<8I", data, offsets[5], class_type, 1, 0xFFFFFFFF, 0, 0xFFFFFFFF, 0, class_at, 0)
    data[:8] = b"dex\n035\0"
    struct.pack_into("<12I", data, 0x38, *[value for pair in zip(sizes, offsets) for value in pair])
    return bytes(data)


def release_dex():
    strings = ["ANS-", "J", "LRelease;", "Landroid/content/Context;", "Ljava/lang/Long;",
               "Ljava/lang/String;", "Ljava/lang/StringBuilder;", "V", "<init>", "append", "code",
               "mix", "toHexString", "toString", "toUpperCase", "rotateLeft", "I"]
    s = {text: index for index, text in enumerate(strings)}
    types = [s[name] for name in ("J", "LRelease;", "Landroid/content/Context;", "Ljava/lang/Long;",
                                  "Ljava/lang/String;", "Ljava/lang/StringBuilder;", "V", "I")]
    t = {strings[string]: index for index, string in enumerate(types)}
    protos = [(t["J"], [t["J"]]), (t["Ljava/lang/String;"], [t["Landroid/content/Context;"]]),
              (t["V"], []), (t["Ljava/lang/StringBuilder;"], [t["Ljava/lang/String;"]]),
              (t["Ljava/lang/String;"], [t["J"]]), (t["Ljava/lang/String;"], []), (t["J"], [t["J"], t["I"]])]
    methods = [(t["LRelease;"], 1, s["code"]), (t["LRelease;"], 0, s["mix"]),
               (t["Ljava/lang/StringBuilder;"], 2, s["<init>"]), (t["Ljava/lang/StringBuilder;"], 3, s["append"]),
               (t["Ljava/lang/Long;"], 4, s["toHexString"]), (t["Ljava/lang/StringBuilder;"], 5, s["toString"]),
               (t["Ljava/lang/String;"], 5, s["toUpperCase"]), (t["Ljava/lang/Long;"], 6, s["rotateLeft"])]

    def wide(register, value):
        value &= M64
        return [0x18 | register << 8] + [(value >> shift) & 0xFFFF for shift in (0, 16, 32, 48)]

    # static long mix(long j) { j ^= K1; j *= K2; j = Long.rotateLeft(j, 23); return j ^ (j >>> 29) + 7; }  (j in v4/v5)
    mix = (wide(0, K1) + [0xC2 | 0x04 << 8]                              # xor-long/2addr v4, v0
           + wide(0, K2) + [0xBD | 0x04 << 8]                            # mul-long/2addr v4, v0
           + [0x13 | 2 << 8, 23]                                         # const/16 v2, 23
           + [0x71 | 3 << 12, 7, 0x0254]                                 # invoke-static {v4, v5, v2}, rotateLeft
           + [0x0B | 4 << 8]                                             # move-result-wide v4
           + [0x13 | 2 << 8, 29, 0x04 | (0 | 4 << 4) << 8]               # const/16 v2, 29; move-wide v0, v4
           + [0xA5 | 0 << 8, 0x0200 | 0]                                 # ushr-long v0, v0, v2
           + [0x16 | 2 << 8, 7, 0xBB | 0x20 << 8]                        # const-wide/16 v2, 7; add-long/2addr v0, v2
           + [0xC2 | 0x04 << 8, 0x10 | 4 << 8])                          # xor-long/2addr v4, v0; return-wide v4
    # static String code(Context c) { long v = mix(0x0123456789ABCDEF); return "ANS-" + Long.toHexString(v).toUpperCase(); }
    code = (wide(0, 0x0123456789ABCDEF)
            + [0x71 | 2 << 12, 1, 0x0010, 0x0B | 0 << 8]                 # invoke-static {v0, v1}, mix; move-result-wide v0
            + [0x22 | 2 << 8, 5, 0x70 | 1 << 12, 2, 0x0002]              # new-instance v2, StringBuilder; <init>
            + [0x1A | 3 << 8, 0, 0x6E | 2 << 12, 3, 0x0032]              # const-string v3, "ANS-"; append
            + [0x71 | 2 << 12, 4, 0x0010, 0x0C | 3 << 8]                 # toHexString(v0, v1); move-result-object v3
            + [0x6E | 1 << 12, 6, 0x0003, 0x0C | 3 << 8]                 # toUpperCase; move-result-object v3
            + [0x6E | 2 << 12, 3, 0x0032]                                # append(v2, v3)
            + [0x6E | 1 << 12, 5, 0x0002, 0x0C | 3 << 8, 0x11 | 3 << 8])  # toString; return-object v3
    return build_dex(strings, types, protos, methods, t["LRelease;"],
                     [(0, 0x9, 5, 1, code), (1, 0x8, 6, 2, mix)])


def expected():
    j = (0x0123456789ABCDEF ^ K1) * K2 & M64
    j = ((j << 23) | (j >> 41)) & M64
    j ^= ((j >> 29) + 7) & M64
    return f"ANS-{j:016X}"


def apk(dex, puzzle):
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("classes.dex", dex)
        archive.writestr("assets/huntress_puzzle.json", json.dumps(puzzle))
    return buffer.getvalue()


class DexVmTests(unittest.TestCase):
    def test_release_code_is_computed_like_java(self):
        self.assertEqual(len(expected()), 20)
        self.assertEqual(dexvm.answer_code(apk(release_dex(), {})), expected())

    def test_day23_analysis_puzzle_goes_through_the_emulator(self):
        puzzle = {"schema": "huntress.mobile.puzzle.v2", "day": 23, "codec": "analysis", "build": "x"}
        self.assertEqual(answer_code(apk(release_dex(), puzzle)), expected())

    def test_platform_calls_outside_the_allow_list_stop_the_run(self):
        with self.assertRaises(dexvm.Unsupported):
            dexvm._platform("Ljava/lang/System;", "currentTimeMillis", "()J", [], None)
        with self.assertRaises(dexvm.Unsupported):
            dexvm._platform("Ljava/io/File;", "<init>", "(Ljava/lang/String;)V", [None, "/x"], None)

    def test_java_integer_semantics(self):
        self.assertEqual(dexvm._binary(3, -7, 2), -3)            # div-int truncates toward zero
        self.assertEqual(dexvm._binary(4, -7, 2), -1)            # rem-int keeps the dividend's sign
        self.assertEqual(dexvm._binary(10, -1, 28), 0xF)         # ushr-int
        self.assertEqual(dexvm._binary(21, -1, 60), 0xF)         # ushr-long
        self.assertEqual(dexvm._binary(0, 0x7FFFFFFF, 1), -0x80000000)
        self.assertEqual(dexvm._java_hash("ANS"), 64966)       # 65*31*31 + 78*31 + 83
        self.assertEqual(dexvm._format("ANS-%016X", [0x1A]), "ANS-000000000000001A")

    def test_x86_64_jni_subset(self):
        # Day 15 libarena.so's shape: mov rax,rdx; movabs rcx,K; add; xor; rol; shr; imul; ret.
        def movabs_rcx(value):
            return b"\x48\xb9" + value.to_bytes(8, "little")
        code = (b"\x48\x89\xd0" + movabs_rcx(K1) + b"\x48\x01\xc8" + movabs_rcx(K2) + b"\x48\x31\xc8"
                + b"\x48\xc1\xc0\x25" + b"\x48\x89\xc1" + b"\x48\xc1\xe9\x15" + b"\x48\x31\xc8"
                + movabs_rcx(K2) + b"\x48\x0f\xaf\xc1" + b"\xc3")
        argument = 0x0123456789ABCDEF
        value = ((argument + K1) & M64) ^ K2
        value = ((value << 37) | (value >> 27)) & M64
        value ^= value >> 21
        value = value * K2 & M64
        self.assertEqual(dexvm.run_x64(code, [0, 0, argument]), value)
        with self.assertRaises(dexvm.Unsupported):
            dexvm.run_x64(b"\x48\x8b\x07\xc3", [0, 0, 0])        # mov rax,[rdi]: memory is never modeled

    def test_jni_names(self):
        self.assertEqual(dexvm.jni_name("Lcom/a_b/C;", "f"), "Java_com_a_1b_C_f")

    def test_not_an_apk(self):
        self.assertIsNone(dexvm.answer_code(b"PK\x05\x06" + bytes(18)))
        self.assertIsNone(dexvm.answer_code(b"plain"))


if __name__ == "__main__":
    unittest.main()
