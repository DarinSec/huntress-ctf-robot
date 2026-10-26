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
from pathlib import Path

from huntress_ctf import dexvm
from huntress_ctf.containers import Member
from huntress_ctf.solvers.base import SolveContext
from huntress_ctf.solvers.binary import BinarySolver
from huntress_ctf.solvers.mobile_puzzle import MobilePuzzleSolver
from tests.test_binary_assignment import archive_context
from tests.test_dexvm import manifest


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


PACKAGE = "com.huntress.mobile.d26.vsynthetic"
CODE = "ANS-0123456789ABCDEF"


def split_apk(files, package=PACKAGE):
    out = BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest(package, 26, "1.0"))
        for name, data in files.items():
            archive.writestr(name, data)
    return out.getvalue()


def apks(**apks_by_name):
    out = BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for name, data in apks_by_name.items():
            archive.writestr(name, data)
    return out.getvalue()


def mobile_context(artifact, members, reference):
    question = {"id": "answer", "artifact": reference,
                "question": f"For case MOB-26-X in package {PACKAGE}: Reassemble evidence distributed across base "
                            "and configuration splits. Submit only the exact backend answer code returned for this case.",
                "answer_format": {"kind": "pattern", "syntax": "ANS- followed by exactly 16 uppercase hexadecimal characters"}}
    return SolveContext("mobile-android-day-26-synthetic", {"lane": "mobile-android"}, {"questions": [question]},
                        artifact, Path("synthetic.apks"), ("answer",), tuple(members))


class SplitApkTests(unittest.TestCase):
    def bundle(self, part="89ABCDEF", index=0):
        base = split_apk({"assets/huntress_puzzle.json": json.dumps(
            {"schema": "huntress.mobile.puzzle.v1", "day": 26, "codec": "split", "data": "",
             "parts": ["", "ANS-", "01234567"], "order": [2, 0, 1]})})
        feature = split_apk({"assets/huntress_feature.json": json.dumps(
            {"codec": "split", "day": 26, "part": part, "part_index": index})})
        return base, feature

    def answer(self, context):
        return {c.answer_id: c.answer for c in MobilePuzzleSolver().solve(context)}

    def test_single_solve_apks_fills_parts_from_the_feature_split(self):
        base, feature = self.bundle()
        bundle = apks(**{"base.apk": base, "feature.apk": feature})
        unpacked = [Member("base.apk", base), Member("feature.apk", feature)]
        self.assertEqual(self.answer(mobile_context(bundle, unpacked, "split_decision.apks")), {"answer": CODE})

    def test_mastery_delivery_keeps_the_apks_whole(self):
        base, feature = self.bundle()
        member = Member("delivery 10: split_decision_mastery_10.apks", apks(**{"base.apk": base, "feature.apk": feature}))
        self.assertEqual(self.answer(mobile_context(b"", [member], "delivery 10: split_decision_mastery_10.apks")),
                         {"answer": CODE})

    def test_no_feature_split_or_other_package_is_no_answer(self):
        base, feature = self.bundle()
        self.assertEqual(self.answer(mobile_context(apks(**{"base.apk": base}), [Member("base.apk", base)],
                                                    "split_decision.apks")), {})
        stranger = split_apk({"assets/huntress_feature.json": json.dumps({"part": "89ABCDEF", "part_index": 0})},
                             package="com.example.other")
        self.assertEqual(self.answer(mobile_context(apks(**{"base.apk": base, "feature.apk": stranger}),
                                                    [Member("base.apk", base), Member("feature.apk", stranger)],
                                                    "split_decision.apks")), {})

    def test_split_source_dirs_open_the_feature_split(self):
        # The "analysis" variant: getApplicationInfo().splitSourceDirs -> new ZipFile(path) -> getEntry(asset).
        secret = bytes(range(16))
        feature = split_apk({"assets/huntress_feature.bin": secret})
        base = split_apk({"assets/huntress_puzzle.json": "{}"})
        vm = dexvm.Machine([], package=PACKAGE, apk=base, splits=[feature])
        call = lambda cls, name, sig, *args: dexvm._platform(cls, name, sig, list(args), vm)
        info = call("Landroid/content/Context;", "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;", vm.context)
        (path,) = info.fields["splitSourceDirs"]
        archive = dexvm.ApkZip()
        call("Ljava/util/zip/ZipFile;", "<init>", "(Ljava/lang/String;)V", archive, path)
        entry = call("Ljava/util/zip/ZipFile;", "getEntry", "", archive, "assets/huntress_feature.bin")
        stream = call("Ljava/util/zip/ZipFile;", "getInputStream", "", archive, entry)
        chunk = [0] * 16
        self.assertEqual(call("Ljava/io/InputStream;", "read", "([BII)I", stream, chunk, 0, 16), 16)
        self.assertEqual(dexvm._bytes(chunk), secret)
        self.assertIsNone(call("Ljava/util/zip/ZipFile;", "getEntry", "", archive, "assets/missing.bin"))
        alone = dexvm.Machine([], package=PACKAGE, apk=base)  # A plain APK has no splits: null, as on Android.
        info = dexvm._platform("Landroid/content/Context;", "getApplicationInfo", "", [alone.context], alone)
        self.assertIsNone(info.fields["splitSourceDirs"])


if __name__ == "__main__":
    unittest.main()
