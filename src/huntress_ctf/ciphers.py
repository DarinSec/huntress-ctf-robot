"""AES and RC4 in pure Python (the package has no dependencies), decryption side only.

Real loaders replace a script's XOR with RC4 or AES, and an Android app's javax.crypto Cipher
decrypts its own constants. Both lanes need the same two ciphers, so they live here. Only
what a sample that carries its own key needs: the AES key schedule, the forward and inverse
block cipher (ECB, CBC, CTR, GCM without the tag check), PKCS#7 unpadding, and RC4.
Checked against FIPS-197 Appendix C and RFC 6229 in tests/test_ciphers.py.
"""

from __future__ import annotations

from functools import lru_cache


def _mul(a: int, b: int) -> int:
    """Multiplication in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
        b >>= 1
    return result


def _sbox() -> list[int]:
    """The S-box from its definition: multiplicative inverse, then the affine map (FIPS-197 5.1.1).
    Inverses come from log/antilog tables over the generator 3, so import stays ~1 ms."""
    power, log, x = [0] * 255, [0] * 256, 1
    for i in range(255):
        power[i], log[x] = x, i
        x = _mul(x, 3)
    box = []
    for value in range(256):
        inverse = power[(255 - log[value]) % 255] if value else 0
        bits = inverse
        for shift in (1, 2, 3, 4):
            bits ^= ((inverse << shift) | (inverse >> (8 - shift))) & 0xFF
        box.append(bits ^ 0x63)
    return box


SBOX = _sbox()
INV_SBOX = [0] * 256
for _index, _value in enumerate(SBOX):
    INV_SBOX[_value] = _index
_MUL = {factor: [_mul(value, factor) for value in range(256)] for factor in (2, 3, 9, 11, 13, 14)}
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


@lru_cache(maxsize=64)  # A script search probes the same few keys against many candidates.
def expand_key(key: bytes) -> list[list[int]]:
    """Round keys (16 bytes each) for a 16-, 24- or 32-byte AES key."""
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    nk = len(key) // 4
    rounds = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (rounds + 1)):
        word = list(words[i - 1])
        if i % nk == 0:
            word = [SBOX[b] for b in word[1:] + word[:1]]
            word[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            word = [SBOX[b] for b in word]
        words.append([a ^ b for a, b in zip(words[i - nk], word)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(rounds + 1)]


def _shift(state: list[int], direction: int) -> list[int]:
    # state[4c + r] is row r of column c; row r moves r columns left (direction 1) or right (-1).
    return [state[4 * ((c + direction * r) % 4) + r] for c in range(4) for r in range(4)]


def encrypt_block(round_keys: list[list[int]], block: bytes) -> bytes:
    m2, m3 = _MUL[2], _MUL[3]
    state = [b ^ k for b, k in zip(block, round_keys[0])]
    for number in range(1, len(round_keys)):
        state = _shift([SBOX[b] for b in state], 1)
        if number != len(round_keys) - 1:
            mixed = []
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = state[c:c + 4]
                mixed += [m2[a0] ^ m3[a1] ^ a2 ^ a3, a0 ^ m2[a1] ^ m3[a2] ^ a3,
                          a0 ^ a1 ^ m2[a2] ^ m3[a3], m3[a0] ^ a1 ^ a2 ^ m2[a3]]
            state = mixed
        state = [b ^ k for b, k in zip(state, round_keys[number])]
    return bytes(state)


def decrypt_block(round_keys: list[list[int]], block: bytes) -> bytes:
    m9, m11, m13, m14 = _MUL[9], _MUL[11], _MUL[13], _MUL[14]
    state = [b ^ k for b, k in zip(block, round_keys[-1])]
    for number in range(len(round_keys) - 2, -1, -1):
        state = [INV_SBOX[b] for b in _shift(state, -1)]
        state = [b ^ k for b, k in zip(state, round_keys[number])]
        if number:
            mixed = []
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = state[c:c + 4]
                mixed += [m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3], m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3],
                          m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3], m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]]
            state = mixed
    return bytes(state)


def unpad(data: bytes) -> bytes:
    """Strict PKCS#7 (PKCS5Padding in Java): a wrong key almost never leaves valid padding."""
    if not data or len(data) % 16 or not 1 <= data[-1] <= 16 or data[-data[-1]:] != bytes([data[-1]]) * data[-1]:
        raise ValueError("bad padding")
    return data[:-data[-1]]


def ecb_decrypt(key: bytes, data: bytes) -> bytes:
    if len(data) % 16:
        raise ValueError("ECB data is not whole blocks")
    keys = expand_key(bytes(key))
    return b"".join(decrypt_block(keys, data[i:i + 16]) for i in range(0, len(data), 16))


def cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(iv) != 16 or len(data) % 16:
        raise ValueError("CBC needs a 16-byte IV and whole blocks")
    keys, out, prior = expand_key(bytes(key)), bytearray(), iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(decrypt_block(keys, block), prior))
        prior = block
    return bytes(out)


def ctr(key: bytes, counter: bytes, data: bytes, width: int = 128) -> bytes:
    """CTR keystream XOR (encrypts and decrypts). Java's AES/CTR counts over all 128 bits;
    GCM counts over the last 32 (width=32)."""
    if len(counter) != 16:
        raise ValueError("CTR needs a 16-byte counter block")
    keys, out, value = expand_key(bytes(key)), bytearray(), int.from_bytes(counter, "big")
    mask = (1 << width) - 1
    for i in range(0, len(data), 16):
        stream = encrypt_block(keys, value.to_bytes(16, "big"))
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], stream))
        value = (value & ~mask) | ((value + 1) & mask)
    return bytes(out)


def gcm_decrypt(key: bytes, nonce: bytes, data: bytes, tag_bytes: int = 16) -> bytes:
    """AES/GCM/NoPadding as Java returns it (ciphertext then tag) for a 12-byte nonce. The tag is
    stripped, not checked: an answer built from a wrong key fails its own format check."""
    if len(nonce) != 12 or len(data) < tag_bytes:
        raise ValueError("GCM needs a 12-byte nonce and the tag")
    return ctr(key, nonce + b"\0\0\0\2", data[:len(data) - tag_bytes], width=32)


@lru_cache(maxsize=64)
def _rc4_schedule(key: bytes) -> tuple[int, ...]:
    if not 1 <= len(key) <= 256:
        raise ValueError("RC4 key must be 1-256 bytes")
    box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + box[i] + key[i % len(key)]) & 0xFF
        box[i], box[j] = box[j], box[i]
    return tuple(box)


def rc4(key: bytes, data: bytes) -> bytes:
    box = list(_rc4_schedule(bytes(key)))
    out, i, j = bytearray(len(data)), 0, 0
    for n, byte in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + box[i]) & 0xFF
        box[i], box[j] = box[j], box[i]
        out[n] = byte ^ box[(box[i] + box[j]) & 0xFF]
    return bytes(out)
