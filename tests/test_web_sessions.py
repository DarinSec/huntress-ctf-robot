"""Signed-cookie primitives: decode (read), verify/sign (forge), crack, and proof scan.

Pure standard library, so no Flask/itsdangerous is needed to run these -- the module and
its tests match Flask's session defaults by construction.
"""

from __future__ import annotations

import re
import unittest

from huntress_ctf.solvers.web import sessions

PROOF = "proof_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
PROOF_RE = re.compile(r"proof_[0-9a-fA-F]{32}")


class SignRoundTripTests(unittest.TestCase):
    def test_sign_then_decode_recovers_the_payload(self):
        cookie = sessions.sign({"username": "admin"}, "s3cr3t")
        self.assertEqual(sessions.decode_payload(cookie), {"username": "admin"})

    def test_sign_then_verify_with_the_same_key(self):
        cookie = sessions.sign({"username": "admin"}, "s3cr3t")
        self.assertTrue(sessions.verify(cookie, "s3cr3t"))
        self.assertFalse(sessions.verify(cookie, "wrong-key"))

    def test_verify_rejects_a_tampered_payload(self):
        cookie = sessions.sign({"username": "guest"}, "s3cr3t")
        forged_value = sessions.sign({"username": "admin"}, "other").split(".", 1)[0]
        tampered = forged_value + "." + cookie.split(".", 1)[1]
        self.assertFalse(sessions.verify(tampered, "s3cr3t"))

    def test_decode_handles_garbage(self):
        for junk in ("", "not-a-cookie", "...", "!!!.??.$$"):
            self.assertIsNone(sessions.decode_payload(junk))


class CrackTests(unittest.TestCase):
    def test_crack_finds_the_key_in_a_wordlist(self):
        cookie = sessions.sign({"username": "guest"}, "letmein")
        self.assertEqual(sessions.crack_secret(cookie, ["a", "b", "letmein", "c"]), "letmein")

    def test_crack_returns_none_when_absent(self):
        cookie = sessions.sign({"username": "guest"}, "a-strong-random-key")
        self.assertIsNone(sessions.crack_secret(cookie, ["x", "y", "z"]))

    def test_forge_admin_after_cracking(self):
        # The full escalation: recover the key, mint an admin cookie the app would accept.
        captured = sessions.sign({"username": "guest"}, "weakkey")
        key = sessions.crack_secret(captured, ["weakkey"])
        admin = sessions.sign({"username": "admin"}, key)
        self.assertTrue(sessions.verify(admin, "weakkey"))
        self.assertEqual(sessions.decode_payload(admin), {"username": "admin"})


class ProofScanTests(unittest.TestCase):
    def test_proof_in_a_signed_cookie_payload_is_found(self):
        cookie = sessions.sign({"flag": PROOF, "u": "x"}, "k")
        self.assertIn(PROOF, sessions.proofs_in_cookies([cookie], PROOF_RE))

    def test_proof_in_a_raw_cookie_value_is_found(self):
        self.assertIn(PROOF, sessions.proofs_in_cookies([PROOF, "unrelated=1"], PROOF_RE))

    def test_no_proof_yields_nothing(self):
        cookie = sessions.sign({"username": "guest"}, "k")
        self.assertEqual(sessions.proofs_in_cookies([cookie, "theme=dark"], PROOF_RE), [])


if __name__ == "__main__":
    unittest.main()
