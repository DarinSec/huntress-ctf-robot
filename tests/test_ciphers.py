"""ciphers.py against the published vectors (FIPS-197 Appendix C, RFC 6229), and its modes
against `cryptography` when that library happens to be installed (it is no dependency)."""

import os
import unittest

from huntress_ctf import ciphers

PLAIN = bytes.fromhex("00112233445566778899aabbccddeeff")
FIPS = (  # FIPS-197 Appendix C.1-C.3: key, ciphertext of PLAIN.
    ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"),
)


class CipherVectorTest(unittest.TestCase):
    def test_aes_fips197(self):
        for key, ct in FIPS:
            keys = ciphers.expand_key(bytes.fromhex(key))
            self.assertEqual(ciphers.encrypt_block(keys, PLAIN).hex(), ct)
            self.assertEqual(ciphers.decrypt_block(keys, bytes.fromhex(ct)), PLAIN)

    def test_rc4_rfc6229(self):
        # RFC 6229, 40-bit key 0x0102030405: keystream bytes 0-15 and 240-255.
        stream = ciphers.rc4(bytes.fromhex("0102030405"), bytes(256))
        self.assertEqual(stream[:16].hex(), "b2396305f03dc027ccc3524a0a1118a8")
        self.assertEqual(stream[240:256].hex(), "28cb1132c96ce286421dcaadb8b69eae")

    def test_padding_and_bad_input(self):
        self.assertEqual(ciphers.unpad(b"abc" + bytes([13]) * 13), b"abc")
        for size in (0, 1, 15, 16, 17):
            self.assertEqual(ciphers.unpad(ciphers.pad(bytes(size))), bytes(size))
        for bad in (b"", b"abc" + bytes([2]) * 12 + b"\x05", bytes(16)):
            with self.assertRaises(ValueError):
                ciphers.unpad(bad)
        with self.assertRaises(ValueError):
            ciphers.expand_key(b"short")
        with self.assertRaises(ValueError):
            ciphers.cbc_decrypt(bytes(16), bytes(16), b"not blocks")


class CipherModeTest(unittest.TestCase):
    def setUp(self):
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            self.skipTest("cryptography not installed")
        self.lib = Cipher, algorithms, modes, AESGCM

    def test_modes_match_cryptography(self):
        Cipher, algorithms, modes, AESGCM = self.lib
        for n in range(12):
            key, iv = os.urandom(16 + 8 * (n % 3)), os.urandom(16)
            blocks, text = os.urandom(16 * (n + 1)), os.urandom(5 + 7 * n)
            for mode, plain, ours in ((modes.ECB(), blocks, lambda c: ciphers.ecb_decrypt(key, c)),
                                      (modes.CBC(iv), blocks, lambda c: ciphers.cbc_decrypt(key, iv, c)),
                                      (modes.CTR(iv), text, lambda c: ciphers.ctr(key, iv, c))):
                encryptor = Cipher(algorithms.AES(key), mode).encryptor()
                self.assertEqual(ours(encryptor.update(plain) + encryptor.finalize()), plain)
            for mode, ours in ((modes.ECB(), lambda p: ciphers.ecb_encrypt(key, p)),
                               (modes.CBC(iv), lambda p: ciphers.cbc_encrypt(key, iv, p))):
                encryptor = Cipher(algorithms.AES(key), mode).encryptor()
                self.assertEqual(ours(blocks), encryptor.update(blocks) + encryptor.finalize())
            nonce = os.urandom(12)
            self.assertEqual(ciphers.gcm_decrypt(key, nonce, AESGCM(key).encrypt(nonce, text, None)), text)

    def test_ctr_counter_wraps_all_128_bits(self):
        Cipher, algorithms, modes, _ = self.lib
        key, counter, text = bytes(16), b"\xff" * 16, os.urandom(40)
        encryptor = Cipher(algorithms.AES(key), modes.CTR(counter)).encryptor()
        self.assertEqual(ciphers.ctr(key, counter, encryptor.update(text) + encryptor.finalize()), text)


if __name__ == "__main__":
    unittest.main()
