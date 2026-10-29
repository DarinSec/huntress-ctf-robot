"""Mobile puzzle codecs no day has used yet, and the bounded search for an unknown codec name."""

import base64
from io import BytesIO
import json
import unittest
import zipfile

from huntress_ctf.solvers.mobile_puzzle import _atbash, _rot47, _vigenere, answer_code

CODE = "ANS-0123456789ABCDEF"


def apk(puzzle):
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00")
        archive.writestr("assets/huntress_puzzle.json", json.dumps(puzzle))
    return buffer.getvalue()


class MobileCodecTests(unittest.TestCase):
    def test_named_codecs(self):
        key = b"k3y"
        xored = bytes(byte ^ key[i % 3] for i, byte in enumerate(CODE.encode()))
        for puzzle in ({"codec": "rot47", "data": _rot47(CODE)}, {"codec": "atbash", "data": _atbash(CODE)},
                       {"codec": "vigenere", "key": "HUNT", "data": _vigenere(CODE, "HUNT", 1)},
                       {"codec": "xor", "key": "k3y", "data": base64.b64encode(xored).decode()}):
            self.assertEqual(answer_code(apk(puzzle)), CODE, puzzle["codec"])

    def test_unknown_codecs_are_searched_two_steps_deep(self):
        for data in (base64.b64encode(CODE[::-1].encode()).decode(),          # reverse, then Base64
                     base64.b64encode(_rot47(CODE).encode()).decode(),         # ROT47, then Base64
                     bytes(byte ^ 0x5A for byte in CODE.encode()).hex()):      # one XOR byte, then hex
            self.assertEqual(answer_code(apk({"codec": "never-seen", "data": data})), CODE, data)

    def test_packet_frames(self):
        def frame(payload, magic=b"HA"):
            body = magic + bytes([len(payload)]) + payload
            check = 0
            for byte in body:
                check ^= byte
            return body + bytes([check])

        whole = frame(CODE.encode())
        self.assertEqual(answer_code(apk({"codec": "packet", "data": whole.hex()})), CODE)
        split = frame(CODE[:10].encode()) + frame(CODE[10:].encode())  # Fragments, in order.
        self.assertEqual(answer_code(apk({"codec": "packet", "data": split.hex()})), CODE)
        decoy = whole[:-1] + bytes([whole[-1] ^ 1]) + frame(b"ANS-FFFFFFFFFFFFFFFF")
        self.assertIsNone(answer_code(apk({"codec": "packet", "data": decoy.hex()})))  # Two codes: ambiguous.

    def test_nothing_is_invented(self):
        self.assertIsNone(answer_code(apk({"codec": "never-seen", "data": "SGVsbG8gd29ybGQ="})))
        self.assertIsNone(answer_code(apk({"codec": "analysis"})))  # No DEX to compute it from.


if __name__ == "__main__":
    unittest.main()
