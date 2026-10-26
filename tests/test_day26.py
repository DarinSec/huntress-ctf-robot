"""Day 26 kinds, with generated data only: a JAR's crash trace and .apks split bundles, plus the
Binary Mastery speed-ups (magic-first encoded HCFG scan, parallel AES delivery unpack).

Binary "Crash Course" adds crash/trace.json to its JAR block; Mobile "Split Decision" splits the
evidence between a base APK and a feature split, either as puzzle parts or as an asset the app's code
opens through ApplicationInfo.splitSourceDirs. (Metadata's MAM Prefetch: test_formats_dfir.py.)
"""

import base64
from io import BytesIO
import json
import struct
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from huntress_ctf import dexvm
from huntress_ctf.containers import Member
from huntress_ctf.solvers.base import SolveContext
from huntress_ctf.solvers._binary_assignment import AssignedArchive
from huntress_ctf.solvers._binary_files import BinaryFiles
from huntress_ctf.solvers._binary_formats import ParseError
from huntress_ctf.solvers.binary import BinarySolver
from huntress_ctf.solvers.mobile_puzzle import MobilePuzzleSolver
from tests.test_binary import bundle
from tests.test_binary_assignment import archive_context, config_record
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

    def test_any_named_json_member_of_the_jar(self):
        # A later day may ship another JSON member: the same "Parse <member>.json and submit ..." wording.
        info = {"stages": ["load", "verify", "run"], "meta": {"owner": "unit", "retries": 3, "debug": False}}
        out = BytesIO(crash_jar(["stageThree"]))
        with zipfile.ZipFile(out, "a") as archive:
            archive.writestr("build/info.json", json.dumps(info))
        asks = {
            "last": ("the exact last string in its stages array.", "run"),
            "count": ("the number of strings in its stages array.", "3"),
            "owner": ("the exact value of its meta.owner field.", "unit"),
            "array": ("its stages array as compact JSON.", '["load","verify","run"]'),
            "debug": ("lowercase true or false for its meta.debug field.", "false"),
            "retries": ("the integer value of its meta.retries field.", "3"),
        }
        questions = [(f"unit_analysis_{key}", f"{PREFIX}Parse build/info.json and submit {text}")
                     for key, (text, _) in asks.items()]
        questions += [("unit_analysis_kind", PREFIX + "Parse crash/trace.json and submit the exact value of its kind field."),
                      ("unit_analysis_missing", PREFIX + "Parse build/none.json and submit the exact value of its kind field."),
                      ("unit_analysis_unknown", PREFIX + "Parse build/info.json and submit its SHA-256.")]
        answers = {c.answer_id: c.answer
                   for c in BinarySolver().solve(archive_context({"unit--sample.jar": out.getvalue()}, questions))}
        self.assertEqual(answers, {**{f"unit_analysis_{key}": value for key, (_, value) in asks.items()},
                                   "unit_analysis_kind": "IllegalStateException"})


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


VALUES = {"campaign": "synthetic-campaign", "domain": "example.invalid", "note": "x" * 60}


def assigned():
    context = archive_context({"unit--a.bin": b"x"}, [("unit_analysis_format", PREFIX + "Identify it.")])
    return AssignedArchive(context, BinaryFiles(context))


def aes_flagged(**files):
    """A ZIP whose entries claim WinZip AES (method 99); zipfile lists them, only the tool reads them."""
    raw = bytearray(bundle(**files))
    for signature, offset in ((b"PK\x03\x04", 8), (b"PK\x01\x02", 10)):
        at = raw.find(signature)
        while at >= 0:
            struct.pack_into("<H", raw, at + offset, 99)
            at = raw.find(signature, at + 4)
    return bytes(raw)


class BinarySpeedTests(unittest.TestCase):
    def test_encoded_record_behind_many_look_alike_runs(self):
        carrier = base64.b64encode(config_record(VALUES))
        self.assertTrue(carrier.startswith(b"SENG") and len(carrier) >= 100)
        noise = b"\0".join([b"QUFB" * 30] * 5000)  # 5000 Base64-looking runs: past the old 4096-run bound.
        node = assigned().encoded_config(noise + b"\0" + carrier + b"\0", "base64", True)
        self.assertEqual(node.values["campaign"], "synthetic-campaign")
        hexed = config_record(VALUES).hex().encode()
        self.assertEqual(assigned().encoded_config(b"zz" + hexed + b"zz", "hex", True).values["domain"], "example.invalid")

    def test_only_whole_runs_that_start_with_the_magic_count(self):
        carrier = base64.b64encode(config_record(VALUES))
        self.assertIsNone(assigned().encoded_config(b"\0QQQQ" + carrier + b"\0", "base64", True))  # Mid-run.
        self.assertIsNone(assigned().encoded_config(b"\0" + carrier[:60] + b"\0", "base64", True))  # Too short.
        with self.assertRaises(ParseError):  # Two valid carriers are ambiguous, as before.
            assigned().encoded_config(b"\0" + carrier + b"\0" + carrier + b"\0", "base64", False)

    def test_the_scan_stays_bounded(self):
        fakes = b"\0".join([b"SENG" + b"A" * 120] * 4097)  # Magic-led runs that are not records.
        with self.assertRaises(ParseError):
            assigned().encoded_config(fakes, "base64", True)
        with self.assertRaises(ParseError):
            assigned().encoded_config(b"48434647" + b"0" * (1024 * 1024), "hex", True)
        self.assertIsNone(assigned().encoded_config(fakes[:5000], "base64", True))  # A few fakes: no record.

    def test_warm_unpacks_each_aes_delivery_once(self):
        first, second = aes_flagged(**{"a.bin": b"alpha"}), aes_flagged(**{"b.bin": b"beta"})
        files = BinaryFiles(archive_context({"unit--a.bin": b"x"}, [("unit_analysis_format", PREFIX + "Identify it.")]))
        payload = {id(first): {0: b"alpha"}, id(second): {0: b"beta"}}
        with patch("huntress_ctf.solvers._binary_files.unzip_tool", return_value=object()), \
                patch("huntress_ctf.solvers._binary_files._external_unzip",
                      side_effect=lambda blob, *rest: dict(payload[id(blob)])) as unzip:
            files.warm([first, second, first])
            self.assertEqual(unzip.call_count, 2)
            self.assertEqual((files.read_index(first, 0), files.read_index(second, 0)), (b"alpha", b"beta"))
            self.assertEqual(unzip.call_count, 2)  # read_index used the warmed results.
            files.warm([aes_flagged(**{"c.bin": b"c"})])  # One delivery: nothing to overlap, left lazy.
            self.assertEqual(unzip.call_count, 2)


if __name__ == "__main__":
    unittest.main()
