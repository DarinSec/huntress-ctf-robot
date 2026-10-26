"""Fuzzing (ROBUSTNESS.md workstream 3): a broken input ends in a clean "no answer".

The harness's own behaviour on synthetic solvers (a hang, a raise, a dead process), the bugs
it found (each kept as a test), and a fuzz run of synthetic seeds for every non-web lane
through every solver: zero hangs, zero uncaught exceptions. Synthetic fixtures only; the
deeper run over the local corpus is scripts/fuzz.py.
"""

from io import BytesIO
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import time
import unittest
import zipfile

from huntress_ctf import formats, fuzz
from huntress_ctf.containers import Member
from huntress_ctf.solvers import SOLVERS
from huntress_ctf.solvers.mobile_puzzle import answer_code

FORK = "fork" in multiprocessing.get_all_start_methods()
CODE = "ANS-0123456789ABCDEF"


def apk(members, method=zipfile.ZIP_STORED):
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", method) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def damage(data, name, at, byte):
    """`data` with the byte `at` into member `name`'s stored bytes replaced."""
    with zipfile.ZipFile(BytesIO(data)) as archive:
        info = archive.getinfo(name)
    local = info.header_offset
    start = local + 30 + int.from_bytes(data[local + 26:local + 28], "little") \
        + int.from_bytes(data[local + 28:local + 30], "little")
    out = bytearray(data)
    out[start + at] = byte
    return bytes(out)


class DamagedArchiveTests(unittest.TestCase):
    """Found by scripts/fuzz.py on the Day 23 Mobile corpus: a damaged APK raised."""

    def test_an_apk_member_that_fails_its_crc_is_no_answer(self):
        data = apk({"AndroidManifest.xml": b"\x03\x00\x08\x00" + b"m" * 64,
                    "assets/huntress_puzzle.json": json.dumps({"codec": "analysis"})})
        broken = damage(data, "AndroidManifest.xml", 10, ord("x"))
        self.assertIn("damaged", formats.apk(broken))  # Was zipfile.BadZipFile: Bad CRC-32.
        self.assertIsNone(answer_code(broken))

    def test_a_corrupt_deflate_stream_is_no_answer(self):
        data = apk({"AndroidManifest.xml": b"\x03\x00\x08\x00",
                    "assets/huntress_puzzle.json": json.dumps({"codec": "analysis"}),
                    "res/raw/strings.bin": b"no code here " * 200}, zipfile.ZIP_DEFLATED)
        for member in ("res/raw/strings.bin", "assets/huntress_puzzle.json", "AndroidManifest.xml"):
            with self.subTest(member=member):
                broken = damage(data, member, 0, 0xFF)  # Block type 3: "invalid block type" (zlib.error).
                self.assertIsNone(answer_code(broken))
                formats.apk(broken)  # Returns whatever it could read; never raises.


def unicode_lnk(terminated=True, path="C:\\Tools\\collector.exe"):
    """A shell link whose LinkInfo carries the Unicode base path (header size 0x24)."""
    import struct

    header = bytearray(0x4C)
    header[:4] = b"\x4c\0\0\0"
    struct.pack_into("<I", header, 0x14, 0x2)  # HasLinkInfo only
    volume, ansi = struct.pack("<IIII", 0x10, 3, 0, 0x10), b"C:\\x\0"
    base_at = 0x24 + len(volume)
    suffix_at = base_at + len(ansi)
    wide = path.encode("utf-16-le") + (b"\0\0" if terminated else b"")
    body = volume + ansi + b"\0" + wide
    info = struct.pack("<IIIIIIIII", 0x24 + len(body), 0x24, 1, 0x24, base_at, 0, suffix_at, suffix_at + 1, 0)
    return bytes(header) + info + body


class Calls:
    """Runs one function under the watchdog: a regression that hangs again fails, not freezes."""

    name = "calls"

    def __init__(self, function, *args):
        self.function, self.args = function, args

    def solve(self, context):
        return [self.function(*self.args)]


def bounded(function, *args):
    from huntress_ctf.watchdog import run_solvers

    found, outcomes = run_solvers([Calls(function, *args)], None, budget=5)
    return outcomes[0].status, (found[0] if found else outcomes[0].detail)


class FoundByFuzzTests(unittest.TestCase):
    """Each place scripts/fuzz.py and the lane run found, rebuilt from synthetic bytes."""

    def test_a_unicode_lnk_path_without_its_terminator_is_no_answer_not_a_hang(self):
        from huntress_ctf.solvers.metadata import lnk_target_path_windows

        self.assertEqual(lnk_target_path_windows(unicode_lnk()), "C:\\Tools\\collector.exe")
        status, result = bounded(lnk_target_path_windows, unicode_lnk(terminated=False))
        self.assertEqual(status, "crashed", result)  # Looped forever before: data[end:end + 2] was b"".
        self.assertIn("ValueError", result)  # As ansi()'s missing NUL; metadata skips that question.

    def test_a_filetime_past_the_year_9999_is_no_timestamp(self):
        from huntress_ctf.formats_dfir import _filetime

        self.assertIsNone(_filetime(0x7FFFFFFFFFFFFFFE))  # OverflowError: date value out of range.
        self.assertEqual(_filetime(116444736000000000), "1970-01-01T00:00:00Z")

    def test_a_docx_cut_at_the_start_is_no_office_metadata(self):
        from huntress_ctf.evidence import _office_and_zip

        docx = apk({"[Content_Types].xml": b"<Types/>", "docProps/core.xml":
                    b"<cp:coreProperties><dc:creator>J. Doe</dc:creator></cp:coreProperties>"})
        _office_and_zip(docx[:11] + docx[130:], {})  # ValueError: negative seek value.

    def test_a_zip_that_needs_an_unknown_version_is_a_damaged_zip(self):
        from huntress_ctf.containers import unwrap

        data = bytearray(apk({"loader.ps1": b"Write-Host 'x'\n"}))
        central = data.index(b"PK\x01\x02")
        data[central + 6:central + 8] = b"\xff\xff"  # Version needed to extract: 6553.5.
        self.assertIn("damaged ZIP", " ".join(unwrap(bytes(data)).notes))  # Was NotImplementedError.

    def test_a_forged_64_bit_offset_is_damage_not_a_crash(self):
        from test_formats import tiny_elf

        data = bytearray(tiny_elf())  # ELF64, little-endian.
        data[32:40] = (1 << 63).to_bytes(8, "little")  # e_phoff past any index Python can use.
        self.assertIn("damaged", formats.elf(bytes(data)))  # Was OverflowError from struct.unpack_from.

    def test_an_ole_code_page_python_has_no_codec_for_is_no_value(self):
        import struct
        from test_formats_dfir import cfb, fields, summary_information

        stream = summary_information("Q3 plan", "J. Doe", "Microsoft Office Word")
        unknown = stream.replace(struct.pack("<HHH2x", 2, 0, 1252), struct.pack("<HHH2x", 2, 0, 5348))
        self.assertNotEqual(unknown, stream)
        f = fields(cfb([("\x05SummaryInformation", unknown), ("WordDocument", b"\xec\xa5")]), "ole")
        self.assertNotIn("title", f)  # Was LookupError: unknown encoding: cp5348.
        self.assertEqual(f["document_type"], "word")  # The rest still reads.

    def test_an_unknown_zip_version_is_no_answer_in_every_lane(self):
        """The evidence ZIP, or a ZIP inside it (a DOCX, an APK), needing "version 6553.5"."""
        def unknown_version(data):
            out = bytearray(data)
            central = out.index(b"PK\x01\x02")
            out[central + 6:central + 8] = b"\xff\xff"
            return bytes(out)
        failures = []
        for seed in lane_seeds():
            entries = fuzz._read_zip(seed.artifact)
            inner = [(info, unknown_version(data)) if fuzz.is_zip(data) else (info, data) for info, data in entries]
            for label, artifact in (("archive", unknown_version(seed.artifact)), ("member", fuzz._zip(inner))):
                broken = fuzz.Seed(seed.name, seed.challenge, seed.attempt, artifact)
                for solver in SOLVERS:
                    try:
                        list(solver.solve(fuzz.context(broken)))
                    except Exception as exc:
                        failures.append(f"{solver.name} on {seed.name} ({label}): {type(exc).__name__}: {exc}")
        self.assertEqual(failures, [])  # metadata.ooxml_external_relationship_targets, mobile _apks raised.

    def test_a_damaged_deflate_member_is_no_answer_in_every_lane(self):
        """Every lane's solvers on a seed whose one member's deflate stream is garbage."""
        failures = []
        for seed in lane_seeds():
            with zipfile.ZipFile(BytesIO(seed.artifact)) as archive:
                name = archive.namelist()[0]
            broken = fuzz.Seed(seed.name, seed.challenge, seed.attempt, damage(seed.artifact, name, 0, 0xFF))
            for solver in SOLVERS:
                try:
                    list(solver.solve(fuzz.context(broken)))
                except Exception as exc:
                    failures.append(f"{solver.name} on {seed.name}: {type(exc).__name__}: {exc}")
        self.assertEqual(failures, [])  # binary-static-facts raised zlib.error in _binary_files.read_index.


class Answers:
    name = "answers"

    def solve(self, context):
        return []


class HangsOnce:
    """Hangs on its first input only; the mark is a file because each input runs in a child."""

    name = "hangs-once"

    def __init__(self, mark):
        self.mark = mark

    def solve(self, context):
        if not self.mark.exists():
            self.mark.write_text("seen")
            while True:
                pass
        return []


class Raises:
    name = "raises"

    def solve(self, context):
        raise ValueError("never-seen header")


class Exits:
    name = "exits"

    def solve(self, context):
        os._exit(3)


def tiny_seed(name="seed", data=None):
    attempt = {"answer_ids": ["q"], "questions": [{"id": "q", "question": "What is it?", "artifact": "evidence.zip"}]}
    if data is None:
        data = apk({"a.txt": b"alpha " * 50, "b.bin": bytes(range(256))}, zipfile.ZIP_DEFLATED)
    return fuzz.Seed(name, {"id": "warmups-day-30-x", "lane": "warmups"}, attempt, data)


class MutationTests(unittest.TestCase):
    def test_a_mutant_is_the_same_every_time_and_differs_from_its_seed(self):
        seed = tiny_seed()
        self.assertEqual(fuzz.mutant(seed, 5), fuzz.mutant(seed, 5))
        self.assertNotEqual(fuzz.mutant(seed, 5), fuzz.mutant(seed, 6))
        self.assertNotEqual(fuzz.mutant(seed, 5, salt="other"), fuzz.mutant(seed, 5))
        self.assertTrue(all(fuzz.mutant(seed, i)[0].artifact != seed.artifact for i in range(30)))

    def test_a_zip_is_mostly_mutated_one_member_deep_and_stays_a_valid_zip(self):
        seed = tiny_seed()
        valid = 0
        for index in range(40):
            changed, how = fuzz.mutant(seed, index)
            try:
                with zipfile.ZipFile(BytesIO(changed.artifact)) as archive:
                    if archive.testzip() is None and archive.namelist() == ["a.txt", "b.bin"]:
                        valid += 1
                        self.assertTrue(how.startswith(("a.txt: ", "b.bin: ")), how)
            except zipfile.BadZipFile:
                pass
        self.assertGreater(valid, 20)  # ~80% go one member deep; the rest hit the archive itself.

    def test_deliveries_are_mutated_one_at_a_time(self):
        first, second = Member("delivery 1: one.apk", b"one" * 40), Member("delivery 2: two.apk", b"two" * 40)
        seed = fuzz.Seed("multi", {"lane": "mobile-android"}, {}, first.data, (first, second))
        changed, how = fuzz.mutant(seed, 0)
        self.assertEqual(sum(a.data != b.data for a, b in zip(changed.deliveries, seed.deliveries)), 1)
        self.assertTrue(how.startswith("delivery "))
        self.assertEqual(changed.artifact, changed.deliveries[0].data)

    def test_one_question_per_kind(self):
        questions = [{"id": f"q{i}", "question": f"What exact URL is embedded in {i:06x}.ps1?"} for i in range(50)]
        questions.append({"id": "other", "question": "What is its primary MITRE ATT&CK technique ID?"})
        kept = fuzz.one_per_kind({"questions": questions})
        self.assertEqual(kept["answer_ids"], ["q0", "other"])


@unittest.skipUnless(FORK, "needs fork")
class HarnessTests(unittest.TestCase):
    def test_a_hang_is_one_finding_and_the_other_inputs_still_run(self):
        with tempfile.TemporaryDirectory() as directory:
            began = time.monotonic()
            found = fuzz.run([HangsOnce(Path(directory) / "mark"), Answers()], [tiny_seed()], 6, budget=0.5)
        self.assertLess(time.monotonic() - began, 10)
        self.assertEqual([(f.solver, f.status, f.index) for f in found], [("hangs-once", "hang", 0)])

    def test_every_raise_is_a_finding_with_its_place(self):
        found = fuzz.run([Raises()], [tiny_seed("a"), tiny_seed("b")], 3, budget=2)
        self.assertEqual(sorted((f.seed, f.index) for f in found), [(s, i) for s in "ab" for i in range(3)])
        self.assertTrue(all(f.status == "crashed" and f.detail == "ValueError: never-seen header" for f in found))
        self.assertIn("in solve", found[0].where)
        self.assertIn(found[0].mutation, found[0].line())

    def test_a_dead_process_is_a_finding_and_the_run_goes_on(self):
        found = fuzz.run([Exits()], [tiny_seed()], 3, budget=2)
        self.assertEqual([(f.status, f.index) for f in found], [("died", 0), ("died", 1), ("died", 2)])
        self.assertIn("code 3", found[0].detail)


def evidence(name, data):
    return apk({name: data}, zipfile.ZIP_DEFLATED)


def ask(lane, name, data, prompts, answer_format=None):
    """One seed: `data` as evidence.zip -> name, asked `prompts` (with {name} filled in)."""
    questions = [{"id": f"q{i}", "question": prompt.format(name=name), "artifact": f"evidence.zip -> {name}",
                  "answer_format": answer_format or {"kind": "exact_text"}} for i, prompt in enumerate(prompts)]
    return fuzz.Seed(f"{lane}:{name}", {"id": f"{lane}-day-30-fuzz", "lane": lane},
                     {"answer_ids": [q["id"] for q in questions], "questions": questions}, evidence(name, data))


def lane_seeds():
    """Real-shaped synthetic seeds of every non-web lane, built by the lane tests' own fixtures."""
    from huntress_ctf.solvers import metadata
    from test_binary import elf_fixture, fat_fixture, macho_fixture, pe_fixture
    from test_binary_assignment import config_record, java_fixture
    from test_formats import macho_with_commands, tiny_axml, tiny_class, tiny_dex, tiny_elf, tiny_wasm
    from test_formats_dfir import cfb, evtx, prefetch, regf, summary_information, tiff
    from test_metadata import box, tiny_lnk, tiny_pe
    from test_script import specimen
    from test_script_descriptors import header
    from test_warmups import split_blob

    properties = sorted(metadata.PROPERTIES)
    meta = [f"Determine {key} for {{name}}." for key in properties] + [
        "Determine evtx.record_count for {name}.", "Determine registry.hive_root_name for {name}.",
        "Determine prefetch.executable_name for {name}.", "Determine tiff.image_width for {name}.",
        "Determine ole.summary_title for {name}.", "Inspect `{name}`. What is its exact size in bytes?",
        "Inspect `{name}`. What is its MD5 digest?", "What is the exact filename of the roster?",
        "What is the author of {name}?", "What URL is embedded in {name}?"]
    files = {
        "agent.exe": tiny_pe(), "collector.lnk": tiny_lnk(), "System.evtx": evtx(), "NTUSER.DAT": regf(),
        "TOOL.EXE-12345678.pf": prefetch(), "scan.tif": tiff(), "plan.doc": cfb([(
            "\x05SummaryInformation", summary_information("Q3 plan", "J. Doe", "Microsoft Office Word"))]),
        "tool.elf": tiny_elf(), "module.wasm": tiny_wasm(), "Main.class": tiny_class(), "classes.dex": tiny_dex(),
        "AndroidManifest.xml": tiny_axml(), "tool.macho": macho_with_commands(),
        "clip.mp4": box(b"ftyp", b"isom\x00\x00\x02\x00isomiso2") + box(b"moov", box(b"mvhd", bytes(100))),
        "report.docx": apk({"[Content_Types].xml": b"<Types/>", "docProps/core.xml":
                            b"<cp:coreProperties><dc:creator>J. Doe</dc:creator></cp:coreProperties>"}),
        "roster.csv": b"name,role\nana,lead\n",
    }
    seeds = [ask("metadata-forensics", name, data, meta) for name, data in files.items()]
    binary = ["What is the architecture?", "List imported function names as JSON.", "List imported symbol names as JSON.",
              "List imported library names.", "List the architectures as JSON.", "Determine pe.resource_paths for {name}.",
              "Determine binary.bitness for {name}.", "Determine elf.build_id for {name}.", "Determine macho.uuid for {name}.",
              "For the requested delivered binary, report the processor architecture identified by its "
              "executable-header machine field.",
              "For the bundled Day 1 ELF, submit the section names in section-header-table order as a JSON array of strings.",
              "In evidence.zip, Compute SHA-256 over the exact bytes of {name}.",
              "Base64-decode each candidate HCFG record. Submit the exact string value of the decoded HCFG JSON "
              "object's top-level campaign property."]
    for name, data in {"sample64.exe": pe_fixture(64, overlay=config_record()), "sample32.exe": pe_fixture(32),
                       "sample.elf": elf_fixture(), "sample.macho": macho_fixture(), "sample.fat": fat_fixture(),
                       "Fixture.class": java_fixture()}.items():
        seeds.append(ask("binary-reverse-engineering", name, data, binary))
    script = ["What scenario best describes {name}?", "What is its primary MITRE ATT&CK technique ID?",
              "What exact URL is embedded in {name}?", "campaign?",
              "Recover the secondary indicator of {name}: the wallet address for a resource-hijacking sample."]
    seeds += [ask("script-analysis", "stager.php", specimen(), script),
              ask("script-analysis", "loader.ps1", ("# " + header("B64") + "\nWrite-Host 'x'\n").encode(), script)]
    slug = ["What exact answer slug does it instruct you to submit?"]
    seeds.append(ask("warmups", "blob.txt", split_blob("amber-fox-tide-07"), slug,
                     {"kind": "pattern", "syntax": "lowercase words joined by hyphens"}))
    mobile = ["For case MOB-01-ABCDEF0123 in package com.example.robot: Submit the ANS- code the app computes."]
    seeds += [ask("mobile-android", "app.apk", apk({"AndroidManifest.xml": tiny_axml(),
                                                     "assets/huntress_puzzle.json": json.dumps(puzzle),
                                                     "classes.dex": tiny_dex()}, zipfile.ZIP_DEFLATED),
                  mobile, {"kind": "pattern", "syntax": "ANS- followed by exactly 16 uppercase hex"})
              for puzzle in ({"codec": "rot47", "data": CODE}, {"codec": "analysis"})]
    return seeds


@unittest.skipUnless(FORK, "needs fork")
class LaneFuzzTests(unittest.TestCase):
    """ROBUSTNESS.md acceptance: N mutants per seed and solver, zero hangs, zero uncaught exceptions."""

    MUTANTS = 40  # ~13,000 solver runs, ~1 s; scripts/fuzz.py and bigger counts go deeper locally.

    def test_every_solver_survives_broken_inputs_of_every_lane(self):
        seeds = lane_seeds()
        self.assertGreaterEqual(len({seed.challenge["lane"] for seed in seeds}), 5)
        found = fuzz.run(SOLVERS, seeds, self.MUTANTS, budget=10)
        self.assertEqual([finding.line() for finding in found], [])


if __name__ == "__main__":
    unittest.main()
