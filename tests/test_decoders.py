import base64
from pathlib import Path
import time
import unittest

from huntress_ctf.decoders import (
    MORSE, binary, decimal, extract_answer, hexadecimal, morse, peel, rot13,
)
from huntress_ctf.solvers import CluedTextDecoderSolver, LayeredDecodeSolver, SolveContext

TO_MORSE = {letter: code for code, letter in MORSE.items()}
PHRASE = "Great job! To solve, submit this exact answer to the Game Master: brave-otter-lamp-42"


def to_morse(text, separator=" "):
    return separator.join(TO_MORSE[char] for char in text.upper()).encode()


def context(artifact, ids=("a",), instructions="Solve the warmup."):
    return SolveContext("c", {}, {"instructions": instructions}, artifact, Path("sample"), ids)


class DecoderTests(unittest.TestCase):
    def test_morse_letters_digits_and_words(self):
        self.assertEqual(morse(b".... .. / - .... . .-. ."), b"HI THERE")
        self.assertEqual(morse(b"....-  .  -....   ----."), b"4 E 6 9")
        self.assertEqual(morse("··· −−−".encode()), b"SO")
        for data in (b"......-", b"hello", b"", b"/ /", b"0101"):
            with self.subTest(data=data):
                self.assertIsNone(morse(data))

    def test_strict_text_layers(self):
        self.assertEqual(hexadecimal(b"68 65 6c 6c 6f"), b"hello")
        self.assertEqual(hexadecimal(b"0x68,0x69"), b"hi")
        self.assertIsNone(hexadecimal(b"686"))
        self.assertEqual(binary(b"1101000 1101001"), b"hi")
        self.assertEqual(binary(b"0110100001101001"), b"hi")
        self.assertIsNone(binary(b"011"))
        self.assertEqual(decimal(b"104, 105"), b"hi")
        self.assertIsNone(decimal(b"104 999"))
        self.assertEqual(rot13(rot13("Answer: x")), "Answer: x")

    def test_extract_answer_requires_one_explicit_statement(self):
        for text, expected in (
            (PHRASE, "brave-otter-lamp-42"),
            ("The flag is flag{abc123}.", "flag{abc123}"),
            ("The answer is: 'quiet-river'.", "quiet-river"),
            ("Answer: one. Answer: two.", None),
            ('$password = "hunter2"', None),
            ("Nothing to see here.", None),
        ):
            with self.subTest(text=text):
                self.assertEqual(extract_answer(text), expected)

    def test_peel_morse_hex_text(self):
        artifact = to_morse(PHRASE.encode().hex().upper())
        found = peel(artifact)
        self.assertEqual({answer for _, _, answer in found}, {"brave-otter-lamp-42"})
        self.assertEqual(found[0][0], ("morse", "hex"))

    def test_peel_other_stacks(self):
        for artifact, chain in (
            (base64.b64encode(PHRASE.encode().hex().encode()), ("base64", "hex")),
            (" ".join(f"{byte:08b}" for byte in PHRASE.encode()).encode(), ("binary",)),
            (base64.b32encode(base64.b64encode(PHRASE.encode())), ("base32", "base64")),
            (base64.b64encode(rot13(PHRASE).encode()), ("base64", "rot13")),
        ):
            with self.subTest(chain=chain):
                found = peel(artifact)
                self.assertEqual({answer for _, _, answer in found}, {"brave-otter-lamp-42"})
                self.assertEqual(found[0][0], chain)

    def test_undecoded_text_is_never_an_answer(self):
        self.assertEqual(peel(PHRASE.encode()), [])
        self.assertEqual(peel(base64.b64encode(b"no stated result")), [])

    def test_peel_is_fast_on_a_realistic_artifact(self):
        artifact = to_morse((PHRASE * 3).encode().hex().upper())
        began = time.perf_counter()
        peel(artifact)
        self.assertLess(time.perf_counter() - began, 0.25)


class LayeredSolverTests(unittest.TestCase):
    def test_layered_solver_submits_only_the_stated_answer(self):
        artifact = to_morse(PHRASE.encode().hex().upper())
        answers = LayeredDecodeSolver().solve(context(artifact))
        self.assertEqual([(a.answer_id, a.answer) for a in answers], [("a", "brave-otter-lamp-42")])
        self.assertIn("morse -> hex", answers[0].evidence)

    def test_layered_solver_needs_one_answer_id_and_one_answer(self):
        artifact = to_morse(PHRASE.encode().hex().upper())
        self.assertEqual(LayeredDecodeSolver().solve(context(artifact, ("a", "b"))), [])
        ambiguous = base64.b64encode(b"answer: one. answer: two.")
        self.assertEqual(LayeredDecodeSolver().solve(context(ambiguous)), [])

    def test_clued_decoder_agrees_with_layered_solver(self):
        artifact = PHRASE.encode().hex().encode()
        clued = CluedTextDecoderSolver().solve(context(artifact, instructions="Decode the hex text."))
        layered = LayeredDecodeSolver().solve(context(artifact, instructions="Decode the hex text."))
        self.assertEqual([a.answer for a in clued], ["brave-otter-lamp-42"])
        self.assertEqual([a.answer for a in layered], ["brave-otter-lamp-42"])

    def test_clued_decoder_defers_when_more_layers_remain(self):
        inner = base64.b64encode(PHRASE.encode())
        artifact = inner.hex().encode()
        clued = CluedTextDecoderSolver().solve(context(artifact, instructions="Decode the hex text."))
        self.assertEqual(clued, [])
        layered = LayeredDecodeSolver().solve(context(artifact))
        self.assertEqual([a.answer for a in layered], ["brave-otter-lamp-42"])


if __name__ == "__main__":
    unittest.main()
