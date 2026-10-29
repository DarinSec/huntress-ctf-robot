"""Warmups lane: the encoding course, split Mastery messages, and separate deliveries.

Every fixture is synthetic: the message, slug, and encodings are built here.
"""

import base64
from contextlib import redirect_stdout
from copy import deepcopy
import gzip
import hashlib
import html
from io import BytesIO, StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote
import zipfile
import zlib

from huntress_ctf.autopilot import COMPLETE
from huntress_ctf.containers import Member
from huntress_ctf.decoders import MORSE, decode_fragment, peel
from huntress_ctf.fastpath import run_fast
from huntress_ctf.solvers import SolveContext
from huntress_ctf.solvers.base import fits_format
from huntress_ctf.solvers.warmups import CURRICULUM, WarmupBlobSolver, _guesses, split_message
from huntress_ctf.client import GameMasterError
from huntress_ctf.state import deliveries

SLUG_FORMAT = {"kind": "pattern", "syntax": "three lowercase words separated by hyphens, followed by a hyphen and a two-digit number; submit the slug only"}
MESSAGE = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: {}"
_TO_MORSE = {letter: code for code, letter in MORSE.items()}


def _shift(text, by):
    def move(char):
        for base in ("A", "a"):
            if base <= char <= chr(ord(base) + 25):
                return chr((ord(char) - ord(base) + by) % 26 + ord(base))
        return char
    return "".join(map(move, text))


def _rail_fence(text, rails):
    rows = [[] for _ in range(rails)]
    row, step = 0, 1
    for char in text:
        rows[row].append(char)
        if row in (0, rails - 1):
            step = 1 if row == 0 else -1
        row += step
    return "".join("".join(r) for r in rows)


def _bacon_hex(text):
    return " ".join(format(int(d, 16), "05b").translate(str.maketrans("01", "ab")) for d in text.encode().hex())


ENCODE = {
    1: lambda t: base64.b64encode(t.encode()).decode(),
    2: lambda t: _shift(t, 13),
    3: lambda t: t.encode().hex(),
    4: lambda t: " ".join(format(b, "08b") for b in t.encode()),
    5: lambda t: " ".join(str(b) for b in t.encode()),
    6: lambda t: " ".join(format(b, "03o") for b in t.encode()),
    7: lambda t: "".join(f"%{b:02x}" for b in t.encode()),
    8: lambda t: "".join(f"&#{b};" for b in t.encode()),
    9: lambda t: '"' + "".join(f"\\u{ord(c):04x}" for c in t) + '"',
    10: lambda t: base64.b32encode(t.encode()).decode(),
    11: lambda t: base64.b64encode(t.encode()).decode().rstrip("="),
    12: lambda t: t[::-1],
    13: lambda t: t.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba")),
    14: lambda t: _shift(t, 7),
    15: lambda t: "".join(chr(33 + (ord(c) - 33 + 47) % 94) if "!" <= c <= "~" else c for c in t),
    16: lambda t: " ".join(_TO_MORSE[d.upper()] for d in t.encode().hex()),
    17: _bacon_hex,
    18: lambda t: _rail_fence(t, 3),
    19: lambda t: ("﻿" + t).encode("utf-16-le").hex(),
}


def _brainfuck(text):
    return "".join(">" + "+" * ord(char) + "." for char in text)


_BF_TO_OOK = {">": "Ook. Ook?", "+": "Ook. Ook.", ".": "Ook! Ook."}

# Days 20-27 as the Day 27 Mastery's lines showed them (line 24 run-length, 25 code points).
LATER_ENCODE = {
    20: lambda t: ("﻿" + t).encode("utf-16-be").hex(),
    21: lambda t: base64.b64encode(gzip.compress(t.encode())).decode(),
    22: lambda t: base64.b64encode(zlib.compress(t.encode())).decode(),
    23: lambda t: base64.a85encode(t.encode(), adobe=True).decode(),
    24: lambda t: "".join(f"1:{char}," for char in t),
    25: lambda t: " ".join(f"U+{ord(char):04X}" for char in t),
    26: _brainfuck,
    27: lambda t: " ".join(_BF_TO_OOK[op] for op in _brainfuck(t)),
    28: lambda t: t.encode().hex()[::-1],  # "Back in Sixteen": hex, walking backwards.
    29: lambda t: _shift(base64.b64encode(t.encode()).decode(), 13),  # "Sixty-four invited thirteen over".
}


def split_blob(slug, days=19):
    """The message cut into `days` numbered lines, line N encoded as Day N teaches."""
    encode = {**ENCODE, **LATER_ENCODE}
    message = MESSAGE.format(slug)
    size = -(-len(message) // days)
    chunks = [message[i * size:(i + 1) * size] for i in range(days)]
    return "\n".join(f"{n:02d}\t{encode[n](chunk)}" for n, chunk in enumerate(chunks, 1) if chunk).encode()


def context(artifact, questions, members=(), challenge_id="warmups-day-19/mastery"):
    ids = tuple(q["id"] for q in questions)
    return SolveContext(
        challenge_id, {"lane": "warmups"}, {"answer_ids": list(ids), "questions": questions},
        artifact, Path("x"), ids, members=tuple(members),
    )


def question(n, artifact):
    return {"id": f"q{n}", "question": "What exact answer slug does it instruct you to submit?",
            "artifact": artifact, "answer_format": SLUG_FORMAT}


class CourseTests(unittest.TestCase):
    def test_every_day_of_the_course_decodes_alone(self):
        for day, encode in ENCODE.items():
            with self.subTest(day=day):
                blob = encode(MESSAGE.format("amber-fox-tide-07")).encode()
                answers = {answer for _, _, answer in peel(blob)}
                self.assertEqual(answers, {"amber-fox-tide-07"})

    def test_fragments_keep_their_edge_spaces(self):
        self.assertEqual(decode_fragment(" rewsn", CURRICULUM[12]), "nswer ")
        self.assertEqual(decode_fragment("TmljZSA=", CURRICULUM[1]), "Nice ")
        self.assertEqual(decode_fragment("nuobt-", CURRICULUM[18]), "no-but")

    def test_split_message_joins_all_nineteen_days(self):
        text = split_blob("tidy-piano-butter-18").decode()
        self.assertEqual(split_message(text, CURRICULUM), MESSAGE.format("tidy-piano-butter-18"))

    def test_split_message_joins_all_twenty_seven_days(self):
        # A fresh Homebase has no hints.json: days 20-27 must come from CURRICULUM itself.
        text = split_blob("cozy-basket-butter-13", days=27).decode()
        self.assertEqual(split_message(text, CURRICULUM), MESSAGE.format("cozy-basket-butter-13"))

    def test_split_message_joins_all_twenty_eight_days(self):
        text = split_blob("proud-compass-ember-84", days=28).decode()
        self.assertEqual(split_message(text, CURRICULUM), MESSAGE.format("proud-compass-ember-84"))

    def test_split_message_joins_all_twenty_nine_days(self):
        # Every Day 30 Mastery blob carries a Day 29 line; a fresh Homebase reads it from CURRICULUM.
        text = split_blob("jovial-comet-nugget-31", days=29).decode()
        self.assertEqual(split_message(text, CURRICULUM), MESSAGE.format("jovial-comet-nugget-31"))

    def test_unknown_line_tries_a_course_text_cipher_before_a_strict_layer(self):
        rot47 = ENCODE[15]
        head, tail = MESSAGE.format("pale-moon")[:40], MESSAGE.format("pale-moon-reef-31")[40:]
        text = "01\t" + base64.b64encode(head.encode()).decode() + "\n40\t" + rot47(tail.encode().hex())
        self.assertEqual(split_message(text, CURRICULUM), MESSAGE.format("pale-moon-reef-31"))

    def test_unknown_later_day_is_guessed_only_when_unambiguous(self):
        text = "01\t" + base64.b64encode(b"Nice work, answer: ").decode() + "\n40\t" + "pale-moon-reef-31".encode().hex()
        self.assertEqual(split_message(text, CURRICULUM), "Nice work, answer: pale-moon-reef-31")
        self.assertIsNone(split_message("01\tTmljZQ==\n41\tjbex", CURRICULUM))  # ROT-like text: not guessed

    def test_guessed_line_with_two_readings_is_settled_by_the_sentence(self):
        # Day 27 Mastery: "U+0065 U+0074 U+002D U+0062" is "et-b" but also unicode/base64 noise.
        payload = "U+0065 U+0074 U+002D U+0062"
        self.assertGreater(len(_guesses(payload)), 1)
        head, tail = MESSAGE.format("cozy-bask"), "utter-13"
        chains = {1: ("base64",), 3: ("base64",)}
        line = lambda n, text: f"{n:02d}\t" + base64.b64encode(text.encode()).decode()
        text = "\n".join((line(1, head), f"02\t{payload}", line(3, tail)))
        self.assertEqual(split_message(text, chains), MESSAGE.format("cozy-basket-butter-13"))
        broken = "\n".join((line(1, "Hello "), f"02\t{payload}", line(3, tail)))
        self.assertIsNone(split_message(broken, chains))  # No reading makes the sentence.

    def test_format_check(self):
        self.assertTrue(fits_format("tidy-piano-butter-18", SLUG_FORMAT))
        self.assertFalse(fits_format("Tidy-piano-18", SLUG_FORMAT))
        self.assertTrue(fits_format("anything", {"kind": "exact_text"}))


class SolverTests(unittest.TestCase):
    def test_mastery_bundle_answers_each_question_from_its_own_member(self):
        slugs = ["amber-fox-tide-07", "calm-river-stone-42", "dusk-owl-fern-99"]
        members = [Member(f"blob-{n:02d}.txt", split_blob(slug, days=n * 6)) for n, slug in enumerate(slugs, 1)]
        questions = [question(n, f"blob-{n:02d}.txt") for n in (1, 2, 3)]
        answers = WarmupBlobSolver().solve(context(b"zip", questions, members))
        self.assertEqual({(a.answer_id, a.answer) for a in answers},
                         {("q1", slugs[0]), ("q2", slugs[1]), ("q3", slugs[2])})

    def test_time_trial_single_blob_and_other_lanes(self):
        blob = ENCODE[17](MESSAGE.format("pale-moon-reef-31")).encode()
        answers = WarmupBlobSolver().solve(context(blob, [question(1, "blob.txt")], challenge_id="warmups-day-17/time_trial"))
        self.assertEqual([a.answer for a in answers], ["pale-moon-reef-31"])
        other = SolveContext("script-analysis-day-01", {"lane": "script-analysis"}, {"answer_ids": ["q1"]},
                             blob, Path("x"), ("q1",))
        self.assertEqual(WarmupBlobSolver().solve(other), [])

    def test_text_cipher_single_blob_uses_its_days_chain(self):
        # Day 28 Time Trial: peel never guesses reversal, so reversed hex needs CURRICULUM[28].
        blob = LATER_ENCODE[28](MESSAGE.format("speedy-button-nugget-52")).encode()
        for challenge_id in ("warmups-day-28", "warmups-day-28/time_trial"):
            with self.subTest(challenge_id=challenge_id):
                answers = WarmupBlobSolver().solve(context(blob, [question(1, "blob.txt")], challenge_id=challenge_id))
                self.assertEqual([a.answer for a in answers], ["speedy-button-nugget-52"])
        self.assertEqual(WarmupBlobSolver().solve(context(blob, [question(1, "blob.txt")], challenge_id="warmups-day-03")), [])

    def test_unknown_day_single_blob_tries_a_text_cipher_first(self):
        # A day after 29 in Day 29's shape (an earlier text cipher over an earlier encoding):
        # decoded, and its chain kept so the day's Mastery line is no longer guessed.
        atbash = ENCODE[13]
        blob = atbash(base64.b32encode(MESSAGE.format("brisk-lantern-moss-64").encode()).decode()).encode()
        for challenge_id in ("warmups-day-30", "warmups-day-30/time_trial"):
            with self.subTest(challenge_id=challenge_id):
                answers = WarmupBlobSolver().solve(context(blob, [question(1, "blob.txt")], challenge_id=challenge_id))
                self.assertEqual([(a.answer, a.chain) for a in answers], [("brisk-lantern-moss-64", ("atbash", "base32"))])
        day29 = LATER_ENCODE[29](MESSAGE.format("nimble-comet-dune-29")).encode()
        answers = WarmupBlobSolver().solve(context(day29, [question(1, "blob.txt")], challenge_id="warmups-day-29"))
        self.assertEqual([(a.answer, a.chain) for a in answers], [("nimble-comet-dune-29", ("rot13", "base64"))])

    def test_learned_day_comes_from_a_proven_hint(self):
        hints = {"warmups-day-40": {"solvers": ["layered-decode"], "chain": ["hex", "reverse"]}}
        fragment = "Nice work, answer: pale-moon-reef-31"[::-1].encode().hex()
        with patch("huntress_ctf.hints.load_hints", return_value=hints):
            from huntress_ctf.solvers.warmups import curriculum
            chains = curriculum()
        self.assertEqual(chains[40], ("hex", "reverse"))
        self.assertEqual(split_message(f"40\t{fragment}", chains), "Nice work, answer: pale-moon-reef-31")


class DeliveryTests(unittest.TestCase):
    def test_listed_capabilities_in_order(self):
        listed = deliveries({"artifacts": [
            {"filename": "blob.txt", "sha256": "AA" * 32, "download": "/?op=download&capability=one"},
            {"filename": "blob.txt", "download": "/?op=download&capability=two"},
            {"filename": "notes.txt"},
        ]})
        self.assertEqual(
            [(d["index"], d["capability"], d["sha256"]) for d in listed],
            [(0, "one", "aa" * 32), (1, "two", None), (2, None, None)],  # The proxy lists no links.
        )

    def test_homebase_style_links_carry_the_capability_in_the_path(self):
        capability = "a3c4e5696ac84275ba9fd3018cf9c3de"
        listed = deliveries({"artifacts": [
            {"filename": "blob.txt", "download": f"/api/huntress/game-master/download/{capability}"},
        ]})
        self.assertEqual([d["capability"] for d in listed], [capability])

    def test_race_downloads_every_delivery_and_omits_run_for_time_on_older_routes(self):
        slugs = ["amber-fox-tide-07", "calm-river-stone-42", "dusk-owl-fern-99"]
        blobs = {f"cap{n}": split_blob(slug, days=n + 1) for n, slug in enumerate(slugs, 1)}

        class Client:
            token = None
            base_url = "https://gm.example"

            def __init__(self):
                self.calls = []
                self.assignment = {
                    "answer_ids": ["q1", "q2", "q3"], "mode": "mastery", "attempt_id": "a",
                    "deadline": "2026-10-20T00:00:00Z",
                    "questions": [question(n, f"delivery {n}: blob.txt") for n in (1, 2, 3)],
                    "artifacts": [{"filename": "blob.txt", "sha256": hashlib.sha256(blobs[f"cap{n}"]).hexdigest(),
                                   "download": f"/?op=download&capability=cap{n}"} for n in (1, 2, 3)],
                }

            def list_challenges(self, day=None, lane=None):
                return {"challenges": [{"id": "warmups-day-03/mastery", "lane": "warmups", "mode": "mastery",
                                        "run_for_time_supported": False}]}

            def status(self, challenge_id):
                self.calls.append("status")
                return {**deepcopy(self.assignment), "result": "CORRECT"}

            def retry(self, challenge_id, timed=False):
                self.calls.append(("retry", timed))
                return deepcopy(self.assignment)

            def artifact(self, challenge_id, delivery=None):
                self.calls.append(("artifact", delivery))
                if delivery == 2:  # One delivery only through its listed link.
                    raise GameMasterError("Game Master returned HTTP 400.")
                return blobs[f"cap{delivery + 1}"]

            def download(self, capability):
                self.calls.append(("download", capability))
                return blobs[capability]

            def submit_many(self, challenge_id, answers):
                self.calls.append(("submit_many", dict(answers)))
                return {"result": "CORRECT"}

        client = Client()
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(StringIO()):
            root = Path(directory)
            code = run_fast(client, "warmups-day-03/mastery", timed=True, artifact_dir=root,
                            work_dir=root / "work", hints_path=root / "hints.json", ntp=lambda: None)
        self.assertEqual(code, COMPLETE)
        self.assertIn(("retry", False), client.calls)  # Timed by default; the flag would be rejected.
        self.assertEqual(sorted(c[1] for c in client.calls if c[0] == "artifact"), [0, 1, 2])
        self.assertEqual([c[1] for c in client.calls if c[0] == "download"], ["cap3"])
        self.assertIn(("submit_many", {"q1": slugs[0], "q2": slugs[1], "q3": slugs[2]}), client.calls)


if __name__ == "__main__":
    unittest.main()
