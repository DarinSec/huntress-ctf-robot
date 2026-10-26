"""Day 26 kinds, with generated data only: a JAR's crash trace and .apks split bundles.

Binary "Crash Course" adds crash/trace.json to its JAR block; Mobile "Split Decision" splits the
evidence between a base APK and a feature split, either as puzzle parts or as an asset the app's code
opens through ApplicationInfo.splitSourceDirs. (Metadata's MAM Prefetch: test_formats_dfir.py.)
"""

from io import BytesIO
import json
import struct
import unittest
import zipfile

from huntress_ctf.solvers.binary import BinarySolver
from tests.test_binary_assignment import archive_context


def classfile(name, methods):
    strings = [name, "java/lang/Object", "()V", *methods]
    constants, index = [], {}
    for text in strings:
        index[text] = len(constants) + 1
        constants.append(b"\x01" + struct.pack(">H", len(text)) + text.encode())
    constants.append(b"\x07" + struct.pack(">H", index[name]))
    constants.append(b"\x07" + struct.pack(">H", index["java/lang/Object"]))
    this, parent = len(constants) - 1, len(constants)
    body = struct.pack(">HHHHHH", 0x21, this, parent, 0, 0, len(methods))
    body += b"".join(struct.pack(">HHHH", 9, index[method], index["()V"], 0) for method in methods)
    return struct.pack(">IHHH", 0xCAFEBABE, 0, 52, len(constants) + 1) + b"".join(constants) + body + b"\0\0"


def crash_jar(frames, methods=("<init>", "stageThree", "stageTwo", "stageOne", "main"), trace=None):
    out = BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nMain-Class: Crash\r\n\r\n")
        archive.writestr("Crash.class", classfile("Crash", list(methods)))
        archive.writestr("Crash$_closure1.class", classfile("Crash$_closure1", ["<init>", "doCall"]))
        archive.writestr("crash/trace.json", trace if trace is not None else
                         json.dumps({"schema": "huntress.synthetic_crash.v1", "kind": "IllegalStateException",
                                     "frames": frames}))
    return out.getvalue()


PREFIX = "In evidence.zip, Use all unit-- members in ZIP central-directory order. "
CRASH = [("unit_analysis_crash_fault_method", PREFIX + "Parse crash/trace.json and submit the exact first string in "
          "its frames array."),
         ("unit_analysis_crash_frames_match_methods", PREFIX + "Evaluate this public predicate and submit lowercase "
          "true or false: true exactly when every string in crash/trace.json frames is present in the primary "
          "classfile method-name set.")]


def crash_answers(jar):
    return {c.answer_id: c.answer for c in BinarySolver().solve(archive_context({"unit--sample.jar": jar}, CRASH))}


class CrashTraceTests(unittest.TestCase):
    def test_fault_method_and_frames_predicate(self):
        self.assertEqual(crash_answers(crash_jar(["stageThree", "stageTwo", "stageOne"])),
                         {"unit_analysis_crash_fault_method": "stageThree",
                          "unit_analysis_crash_frames_match_methods": "true"})
        # A frame only the closure class has is not in the primary (Main-Class) method set.
        self.assertEqual(crash_answers(crash_jar(["doCall", "stageOne"]))["unit_analysis_crash_frames_match_methods"],
                         "false")

    def test_missing_or_malformed_trace_is_no_answer(self):
        for trace in ("{not json", json.dumps({"frames": []}), json.dumps({"frames": ["a", 3]}), json.dumps([1])):
            self.assertEqual(crash_answers(crash_jar([], trace=trace)), {}, trace)


if __name__ == "__main__":
    unittest.main()
