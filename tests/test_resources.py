"""Resource ceilings (ROBUSTNESS.md workstream 4): a huge or hostile artifact cannot exhaust memory.

Each forked solver has a memory ceiling and is the OOM killer's first choice; every read of an
archive member or compressed stream is bounded where it happens, not only at the unpacker.
Synthetic bombs only: small streams that inflate to hundreds of MiB, built in milliseconds.
"""

import base64
import bz2
import gzip
from io import BytesIO
import lzma
import multiprocessing
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import zipfile
import zlib

from huntress_ctf import fuzz, watchdog
from huntress_ctf.containers import TooLarge, ZIP_ERRORS, decompress, read_member
from huntress_ctf.solvers import SOLVERS, AnswerCandidate

FORK = "fork" in multiprocessing.get_all_start_methods()
LINUX_PROC = Path("/proc/self/oom_score_adj").exists()
BOMB = 64 << 20  # The unit tests' bombs: 64 MiB from under 100 KiB.
STDLIB = {"zlib": zlib.decompress, "raw": lambda data: zlib.decompress(data, -15), "gzip": gzip.decompress,
          "xz": lzma.decompress, "bz2": bz2.decompress}
PACK = {"zlib": zlib.compress, "raw": lambda data: zlib.compress(data, wbits=-15), "gzip": gzip.compress,
        "xz": lzma.compress, "bz2": bz2.compress}


class Allocates:
    name = "allocates"

    def __init__(self, size):
        self.size = size

    def solve(self, context):
        blob = bytearray(self.size)
        return [AnswerCandidate("a", str(len(blob)), self.name, "synthetic")]


class ReadsOomScore:
    name = "reads-oom-score"

    def solve(self, context):
        return [AnswerCandidate("a", Path("/proc/self/oom_score_adj").read_text().strip(), self.name, "synthetic")]


class Answers:
    name = "answers"

    def solve(self, context):
        return [AnswerCandidate("b", "hello", self.name, "synthetic")]


class Reads:
    """Runs `read` in the forked child: under a ceiling, a read's cost is what it holds at its peak."""

    def __init__(self, name, read):
        self.name, self.read = name, read

    def solve(self, context):
        return [AnswerCandidate("a", str(len(self.read())), self.name, "synthetic")]


class ReadsWhole:
    """What workstream 4 forbids: every ZIP member read whole, then any stream in it inflated whole."""

    name = "reads-whole"

    def solve(self, context):
        with zipfile.ZipFile(BytesIO(context.artifact)) as archive:
            for info in archive.infolist():
                data = archive.read(info)
                for magic, unpack in ((b"\x1f\x8b", gzip.decompress), (b"\xfd7zXZ", lzma.decompress),
                                      (b"BZh", bz2.decompress), (b"\x78\xda", zlib.decompress)):
                    if data.startswith(magic):
                        unpack(data)
        return []


def zip_of(members, method=zipfile.ZIP_DEFLATED):
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", method) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def flavour_of(how):
    """The flavour a bomb mutant's description names ("inner.zip: b.txt: a 64 MiB xz bomb")."""
    if "stated as" in how:
        return "zip-understated"
    return "zip-deflate" if "deflate bomb" in how else how.rsplit(" bomb", 1)[0].rsplit(" ", 1)[1]


def bomb_zip(size, understated=False):
    return fuzz._zip_bomb([(zipfile.ZipInfo("note.txt"), b"hello"), (zipfile.ZipInfo("bomb.bin"), b"")], 1, size,
                          understated)


@unittest.skipUnless(FORK and LINUX_PROC, "needs fork and /proc")
class SolverMemoryCeilingTests(unittest.TestCase):
    def test_a_solver_past_its_ceiling_gets_memory_error_and_the_others_answer(self):
        found, outcomes = watchdog.run_solvers([Allocates(1 << 30), Answers()], None, budget=20,
                                               memory=128 << 20, mode="fork")
        self.assertEqual([c.answer for c in found], ["hello"])
        crash = next(o for o in outcomes if o.solver == "allocates")
        self.assertEqual(crash.status, "crashed")
        self.assertIn("MemoryError", crash.detail)
        self.assertIn("128 MB memory ceiling", crash.detail)

    def test_a_solve_within_its_ceiling_is_untouched(self):
        found, outcomes = watchdog.run_solvers([Allocates(32 << 20)], None, budget=20, memory=128 << 20, mode="fork")
        self.assertEqual(([c.answer for c in found], outcomes[0].status), ([str(32 << 20)], "ok"))

    def test_the_oom_killer_takes_a_solver_before_the_robot(self):
        found, _ = watchdog.run_solvers([ReadsOomScore()], None, budget=20, mode="fork")
        self.assertEqual([c.answer for c in found], ["1000"])
        self.assertNotEqual(Path("/proc/self/oom_score_adj").read_text().strip(), "1000")  # Only the child.

    def test_the_ceiling_comes_from_the_environment(self):
        for value, expected in (("512", 512 << 20), ("0", 0), ("soon", watchdog.SOLVER_MEMORY_MB << 20)):
            with patch.dict(os.environ, {"HUNTRESS_SOLVER_MEMORY_MB": value}):
                self.assertEqual(watchdog.memory_headroom(), expected, value)


class BombTests(unittest.TestCase):
    def test_each_stream_bomb_inflates_to_its_size_from_a_small_blob(self):
        for flavour in ("gzip", "xz", "bz2", "zlib"):
            blob = fuzz.bomb_blob(flavour, BOMB)
            out = STDLIB[flavour](blob)
            self.assertEqual((len(out), out.strip(b"\0")), (BOMB, b""), flavour)
            self.assertLess(len(blob), BOMB // 500, flavour)

    def test_a_zip_bomb_states_its_size_or_understates_it_as_one_mib(self):
        with zipfile.ZipFile(BytesIO(bomb_zip(BOMB))) as archive:
            self.assertEqual(archive.getinfo("bomb.bin").file_size, BOMB)
            self.assertIsNone(archive.testzip())  # Valid sizes and CRCs: only its size is hostile.
            self.assertEqual(archive.read("note.txt"), b"hello")
        with zipfile.ZipFile(BytesIO(bomb_zip(BOMB, understated=True))) as archive:
            self.assertEqual(archive.getinfo("bomb.bin").file_size, 1 << 20)
            self.assertEqual(archive.read("bomb.bin"), bytes(1 << 20))  # zipfile cuts it there, CRC and all.

    def test_bomb_mutants_replace_one_member_and_are_reproducible(self):
        seed = fuzz.Seed("s", {"id": "warmups-day-30-x", "lane": "warmups"}, {"answer_ids": [], "questions": []},
                         zip_of({"a.txt": b"alpha", "inner.zip": zip_of({"b.txt": b"beta"})}))
        seen = set()
        for index in range(30):
            changed, how = fuzz.mutant(seed, index, "0", BOMB)
            self.assertEqual(fuzz.mutant(seed, index, "0", BOMB), (changed, how))
            self.assertIn("bomb", how)
            seen.add(flavour_of(how))
        self.assertEqual(seen, set(fuzz.BOMB_FLAVOURS))


class BoundedReadTests(unittest.TestCase):
    def test_read_member_reads_what_zipfile_reads(self):
        for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
            data = zip_of({"a.txt": b"alpha " * 1000, "empty": b""}, method)
            with zipfile.ZipFile(BytesIO(data)) as archive:
                for info in archive.infolist():
                    self.assertEqual(read_member(archive, info), archive.read(info), (method, info.filename))
                    self.assertEqual(read_member(archive, info.filename), archive.read(info.filename))

    def test_a_member_stated_past_the_limit_is_too_large_which_is_damage(self):
        with zipfile.ZipFile(BytesIO(bomb_zip(BOMB))) as archive:
            with self.assertRaises(TooLarge) as raised:
                read_member(archive, "bomb.bin", 32 << 20)
            self.assertIsInstance(raised.exception, ZIP_ERRORS)  # Every reader treats it as no data.
            self.assertEqual(read_member(archive, "note.txt", 32 << 20), b"hello")

    def test_a_damaged_member_still_fails_its_crc(self):
        data = bytearray(zip_of({"a.txt": b"alpha " * 100}, zipfile.ZIP_STORED))
        data[data.index(b"alpha") + 3] ^= 1
        with zipfile.ZipFile(BytesIO(bytes(data))) as archive, self.assertRaises(zipfile.BadZipFile):
            read_member(archive, "a.txt")

    @unittest.skipUnless(FORK and LINUX_PROC, "needs fork and /proc")
    def test_an_understated_bomb_costs_only_what_its_header_states(self):
        blob = bomb_zip(512 << 20, understated=True)

        def bounded():
            with zipfile.ZipFile(BytesIO(blob)) as archive:
                return read_member(archive, "bomb.bin")

        def whole():
            with zipfile.ZipFile(BytesIO(blob)) as archive:
                return archive.read("bomb.bin")  # Inflates all 512 MiB before it cuts to the 1 MiB stated.

        found, outcomes = watchdog.run_solvers([Reads("bounded", bounded), Reads("whole", whole)], None, budget=30,
                                               memory=128 << 20, mode="fork")
        self.assertEqual([c.answer for c in found], [str(1 << 20)])
        self.assertIn("MemoryError", next(o.detail for o in outcomes if o.solver == "whole"))

    def test_decompress_answers_as_the_standard_library_does(self):
        for kind, pack in PACK.items():
            blob = pack(b"abc" * 100)
            for name, data in (("one", blob), ("two", blob + blob), ("junk", blob + b"junk"), ("pad", blob + b"\0\0"),
                               ("cut", blob[:-4]), ("garbage", b"xyz" + blob), ("empty", b"")):
                try:
                    expected = STDLIB[kind](data)
                except Exception:  # noqa: BLE001 - whatever the stdlib raises, ours raises one of ZIP_ERRORS
                    with self.assertRaises(ZIP_ERRORS, msg=(kind, name)):
                        decompress(data, kind, 1000)
                    continue
                self.assertEqual(decompress(data, kind, 1000), expected, (kind, name))

    def test_decompress_stops_past_its_limit_or_keeps_the_head(self):
        for kind, pack in PACK.items():
            blob = pack(b"abc" * 1000)
            with self.assertRaises(TooLarge, msg=kind):
                decompress(blob, kind, 400)
            self.assertEqual(decompress(blob, kind, 400, head=True), (b"abc" * 1000)[:400], kind)
            self.assertEqual(decompress(blob, kind, 3000), b"abc" * 1000, kind)  # Exactly the limit is fine.

    @unittest.skipUnless(FORK and LINUX_PROC, "needs fork and /proc")
    def test_decompress_holds_its_limit_not_the_bomb(self):
        blobs = {kind: fuzz.bomb_blob(kind, 1 << 30) for kind in ("gzip", "xz", "bz2", "zlib")}
        readers = [Reads(kind, lambda kind=kind: decompress(blobs[kind], kind, 16 << 20, head=True)) for kind in blobs]
        found, outcomes = watchdog.run_solvers(readers, None, budget=60, memory=128 << 20, mode="fork")
        self.assertEqual({o.solver: o.status for o in outcomes}, dict.fromkeys(blobs, "ok"))
        self.assertEqual({c.answer for c in found}, {str(16 << 20)})


class UnreachedByMemberBombsTests(unittest.TestCase):
    """The streams a bomb in place of a member never reaches: inside script text and inside a binary."""

    def test_a_bomb_in_a_script_layer_is_no_record(self):
        from huntress_ctf.analysis import scriptrules

        for layer in ("zlib", "gzip"):
            packed = base64.b64encode(fuzz.bomb_blob(layer, BOMB)).decode()
            self.assertIsNone(scriptrules.analysis_header(f"# HUNTRESS_ANALYSIS_V1:LYR-{layer}_b64-{packed}\n"), layer)

    @unittest.skipUnless(FORK and LINUX_PROC, "needs fork and /proc")
    def test_a_compressed_carrier_bomb_does_not_hide_the_record(self):
        from huntress_ctf.solvers.binary import BinarySolver
        from tests.test_binary import pe_fixture
        from tests.test_binary_assignment import archive_context, config_record

        public = "Use all unit-- members in ZIP central-directory order. Locate the ZZ24 vault described in the lesson. "
        prompts = [("unit_analysis_campaign", public + "Submit the exact string value of the decoded HCFG JSON "
                    "object's top-level campaign property.")]
        for kind in ("xz", "bz2"):
            data = pe_fixture() + fuzz.bomb_blob(kind, 1 << 30) + b"ZZ24" + zlib.compress(config_record())
            found, outcomes = watchdog.run_solvers([BinarySolver()], archive_context({"unit--native.exe": data}, prompts),
                                                   budget=60, memory=512 << 20, mode="fork")
            self.assertEqual(([c.answer for c in found], outcomes[0].status), (["synthetic-campaign"], "ok"), kind)


@unittest.skipUnless(FORK and LINUX_PROC, "needs fork and /proc")
class BombFuzzTests(unittest.TestCase):
    """ROBUSTNESS.md acceptance: bombs past every cap through every solver, zero findings."""

    BOMBS = 6  # Per seed: ~2,200 solver runs, every flavour, ~10 s; scripts/fuzz.py --bomb goes deeper.

    def test_the_harness_names_a_whole_read_of_each_flavour(self):
        seed = fuzz.Seed("whole", {"id": "warmups-day-30-x", "lane": "warmups"}, {"answer_ids": [], "questions": []},
                         zip_of({"a.txt": b"alpha"}))
        found = fuzz.run([ReadsWhole()], [seed], 12, budget=30, memory=128 << 20, bomb=256 << 20, parallel=1)
        self.assertEqual(len(found), 12)
        self.assertTrue(all("MemoryError" in finding.detail for finding in found), [f.line() for f in found])

    def test_every_solver_holds_its_caps_against_bombs_of_every_lane(self):
        from test_fuzz import lane_seeds

        found = fuzz.run(SOLVERS, lane_seeds(), self.BOMBS, budget=30, memory=768 << 20, bomb=1 << 30, parallel=2)
        self.assertEqual([finding.line() for finding in found], [])


if __name__ == "__main__":
    unittest.main()
