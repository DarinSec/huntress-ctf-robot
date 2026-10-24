import base64
from pathlib import Path
import time
import unittest

from huntress_ctf.decoders import (
    MORSE, binary, decimal, extract_answer, hexadecimal, morse, peel, rot13, runlength,
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

    def test_runlength_count_char_pairs(self):
        # Day 24 Warmups: "1:N,1:i,1:c,1:e" -> "Nice". A comma can be a character too.
        self.assertEqual(runlength(b"1:N,1:i,1:c,1:e"), b"Nice")
        self.assertEqual(runlength(b"3:a,2:b"), b"aaabb")
        self.assertEqual(runlength(b"2:x,1:,,1:y"), b"xx,y")  # Comma as a character.
        # Rejects anything that is not wholly count:char pairs.
        self.assertIsNone(runlength(b"hello, world"))
        self.assertIsNone(runlength(b"12:34 is the time"))
        self.assertIsNone(runlength(b"1:a;1:b"))  # Wrong separator.
        self.assertIsNone(runlength(b"0:a"))      # A zero count is not a run.
        # End to end: the decoded line states the slug, and peel finds it via runlength.
        blob = ",".join(f"1:{char}" for char in
                         "To solve, submit this exact answer to the Game Master: jaunty-compass-mosaic-76").encode()
        chains = {chain for chain, _, answer in peel(blob) if answer == "jaunty-compass-mosaic-76"}
        self.assertIn(("runlength",), chains)

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


BRAILLE_CELLS = {
    "a": 0x01, "b": 0x03, "c": 0x09, "d": 0x19, "e": 0x11, "f": 0x0B, "g": 0x1B, "h": 0x13, "i": 0x0A,
    "j": 0x1A, "k": 0x05, "l": 0x07, "m": 0x0D, "n": 0x1D, "o": 0x15, "p": 0x0F, "q": 0x1F, "r": 0x17,
    "s": 0x0E, "t": 0x1E, "u": 0x25, "v": 0x27, "w": 0x3A, "x": 0x2D, "y": 0x3D, "z": 0x35,
    ":": 0x12, "-": 0x24, " ": 0x00, ".": 0x32, "!": 0x16, ",": 0x02,
}
NATO_WORDS = {
    "A": "Alfa", "B": "Bravo", "C": "Charlie", "D": "Delta", "E": "Echo", "F": "Foxtrot",
    **{str(n): word for n, word in enumerate(
        ("Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine"))},
}


def to_braille(text):
    cells = []
    for char in text.lower():
        if char.isdigit():
            cells += [0x3C, BRAILLE_CELLS["jabcdefghi"[int(char)]]]
        else:
            cells.append(BRAILLE_CELLS[char])
    return "".join(chr(0x2800 + cell) for cell in cells).encode()


class UnusedFormatTests(unittest.TestCase):
    """Formats no warmup used up to day 20, ready for a later day."""

    def answers(self, data):
        return {(chain, answer) for chain, _, answer in peel(data)}

    def test_each_format_reaches_the_answer(self):
        import quopri
        import zlib
        phrase = PHRASE.encode()
        hexed = phrase.hex()
        cases = {
            ("ascii85",): base64.a85encode(phrase, adobe=True),
            ("base85",): base64.b85encode(phrase),
            ("qp",): quopri.encodestring(phrase, quotetabs=True).replace(b" ", b"=20"),
            ("uu",): b"begin 644 note.txt\n" + b"".join(
                __import__("binascii").b2a_uu(phrase[i:i + 45]) for i in range(0, len(phrase), 45)) + b"`\nend\n",
            ("base64", "zlib"): base64.b64encode(zlib.compress(phrase)),
            ("braille",): to_braille("submit this exact answer: brave-otter-lamp-42"),
            ("nato", "hex"): " ".join(NATO_WORDS[c] for c in hexed.upper()).encode(),
            ("unicode",): " ".join(f"U+{ord(c):04X}" for c in PHRASE).encode(),
            ("octal",): "".join(f"\\{b:03o}" for b in phrase).encode(),
        }
        for chain, data in cases.items():
            with self.subTest(chain=chain):
                self.assertIn((chain, "brave-otter-lamp-42"), self.answers(data))

    def test_quiet_on_plain_text_and_known_formats(self):
        from huntress_ctf.decoders import (
            ascii85, base85, braille, codepoints, inflated, nato, quoted_printable, uuencoded,
        )
        samples = [
            b"Great job to solve submit this", base64.b64encode(b"hello world!"), b"SGVsbG8=",
            b"68 65 6c 6c 6f", b"one two three four", b"%4e%69%63", b"&#78;&#105;",
            b"just some words without any encoding at all", b"x\x9c not really zlib",
        ]
        for sample in samples:
            for decode in (ascii85, base85, quoted_printable, uuencoded, inflated, braille, codepoints):
                with self.subTest(sample=sample, decode=decode.__name__):
                    self.assertIsNone(decode(sample))
        self.assertIsNone(nato(b"Alpha and omega"))  # Not every word is a code word.


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
