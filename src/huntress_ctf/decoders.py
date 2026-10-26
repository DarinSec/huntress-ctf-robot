"""Strict, pure decoders for layered text encodings and answer-phrase extraction.

Every decoder returns None unless its whole input matches the format, so a
breadth-first search over them stays small and never guesses at partial data.
"""

from __future__ import annotations

import base64
import binascii
from collections import deque
from functools import lru_cache
import html
import json
import quopri
import re
from urllib.parse import unquote_to_bytes
import zlib

from .containers import ZIP_ERRORS, decompress

MAX_LAYER_DEPTH = 5
MAX_NODES = 64

MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
    ".-.-.-": ".", "--..--": ",", "..--..": "?", ".----.": "'", "-.-.--": "!",
    "-..-.": "/", "-.--.": "(", "-.--.-": ")", ".-...": "&", "---...": ":",
    "-.-.-.": ";", "-...-": "=", ".-.-.": "+", "-....-": "-", "..--.-": "_",
    ".-..-.": '"', "...-..-": "$", ".--.-.": "@",
}
_MORSE_CHARS = str.maketrans({"·": ".", "•": ".", "∙": ".", "−": "-", "–": "-", "—": "-"})
_MORSE_TEXT = re.compile(r"[.\-/| \t\r\n]+")
_MORSE_WORDS = re.compile(r"\s*[/|]\s*|\s{2,}")
_HEX_TEXT = re.compile(r"(?:0x|\\x)?[0-9a-fA-F]{2}(?:[\s,:]*(?:0x|\\x)?[0-9a-fA-F]{2})*")
_HEX_PREFIX = re.compile(r"0x|\\x|[\s,:]")
_BINARY_TEXT = re.compile(r"[01]+(?:\s+[01]+)*")
_DECIMAL_TEXT = re.compile(r"\d{1,3}(?:[\s,]+\d{1,3})+")
_BASE64_TEXT = re.compile(r"[A-Za-z0-9+/\-_]+={0,2}")
_BASE32_TEXT = re.compile(r"[A-Z2-7]+={0,6}")
_WHITESPACE = b" \t\r\n\x0b\x0c"
_LAYOUT = str.maketrans("", "", "\t\r\n")


def raw_text(data: bytes) -> str | None:
    """Printable text with its own edge spaces kept (message fragments need them).

    UTF-8, or UTF-16 (Warmups Day 19-20) or UTF-32 when the bytes start with a byte-order mark.
    """
    if data[:4] in (b"\xff\xfe\0\0", b"\0\0\xfe\xff"):
        encoding = "utf-32"
    else:
        encoding = "utf-16" if data[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8"
    try:
        text = data.decode(encoding)
    except UnicodeDecodeError:
        return None
    if not text or not text.translate(_LAYOUT).isprintable():
        return None
    return text


def as_text(data: bytes) -> str | None:
    """Printable text, stripped, or None for binary data."""
    return _as_text(data if type(data) is bytes else bytes(data))


def clear_cache() -> None:
    """Forget cached texts, so a timing run sees each artifact as the clock would: new."""
    _as_text.cache_clear()


# Every layer asks for the same node's text, so a few entries make each node one decode.
@lru_cache(maxsize=8)
def _as_text(data: bytes) -> str | None:
    text = raw_text(data)
    return (text.strip() or None) if text is not None else None


def morse(data: bytes) -> bytes | None:
    text = as_text(data)
    if text is None:
        return None
    text = text.translate(_MORSE_CHARS)
    if not _MORSE_TEXT.fullmatch(text) or not re.search(r"[.\-]", text):
        return None
    words = []
    for word in _MORSE_WORDS.split(text.strip()):
        letters = word.split()
        if not letters:
            continue
        try:
            words.append("".join(MORSE[letter] for letter in letters))
        except KeyError:
            return None
    return " ".join(words).encode("ascii") if words else None


def hexadecimal(data: bytes) -> bytes | None:
    text = as_text(data)
    if text is None or not _HEX_TEXT.fullmatch(text):
        return None
    digits = _HEX_PREFIX.sub("", text)
    if len(digits) % 2:
        return None
    return bytes.fromhex(digits)


def binary(data: bytes) -> bytes | None:
    text = as_text(data)
    if text is None or not _BINARY_TEXT.fullmatch(text):
        return None
    groups = text.split()
    width = len(groups[0])
    if len(groups) > 1 and width in (7, 8) and all(len(group) == width for group in groups):
        return bytes(int(group, 2) for group in groups)
    bits = "".join(groups)
    if len(bits) % 8:
        return None
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def decimal(data: bytes) -> bytes | None:
    text = as_text(data)
    if text is None or not _DECIMAL_TEXT.fullmatch(text):
        return None
    values = [int(item) for item in re.split(r"[\s,]+", text)]
    if any(value > 255 for value in values):
        return None
    return bytes(values)


def base64_text(data: bytes) -> bytes | None:
    """Standard or URL-safe Base64, padded or not (Warmups Day 11 drops the padding)."""
    compact = data.translate(None, _WHITESPACE)
    if len(compact) < 4 or len(compact) % 4 == 1:
        return None
    padded = compact if compact.endswith(b"=") else compact + b"=" * (-len(compact) % 4)
    if len(padded) % 4:
        return None
    try:
        if not _BASE64_TEXT.fullmatch(padded.decode("ascii")):
            return None
        if b"-" in padded or b"_" in padded:
            decoded = base64.urlsafe_b64decode(padded)
            canonical = base64.urlsafe_b64encode(decoded)
        else:
            decoded = base64.b64decode(padded, validate=True)
            canonical = base64.b64encode(decoded)
    except (binascii.Error, ValueError):
        return None
    return decoded if canonical == padded else None


def base32_text(data: bytes) -> bytes | None:
    compact = data.translate(None, _WHITESPACE)
    if len(compact) < 8 or len(compact) % 8:
        return None
    try:
        if not _BASE32_TEXT.fullmatch(compact.decode("ascii")):
            return None
        decoded = base64.b32decode(compact)
    except (binascii.Error, ValueError):
        return None
    return decoded if base64.b32encode(decoded) == compact else None


_OCTAL_TEXT = re.compile(r"[0-3][0-7]{2}(?:\s+[0-3][0-7]{2})+")
_OCTAL_ESCAPES = re.compile(r"(?:\\[0-3][0-7]{2}){2,}")
_URL_TEXT = re.compile(r"(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9\-._~!$&'()*+,;=:@/?# ])+")
_ENTITY = re.compile(r"&(?:#\d{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")
_BACON_TEXT = re.compile(r"[abAB]{5}(?:\s+[abAB]{5})*")
_BACON_BITS = str.maketrans("abAB", "0101")


def octal(data: bytes) -> bytes | None:
    """Three-digit octal byte codes: "116 151 143" (Warmups Day 6), or escapes "\\116\\151"."""
    text = as_text(data)
    if text is None:
        return None
    if _OCTAL_ESCAPES.fullmatch(text):
        return bytes(int(code, 8) for code in text.split("\\")[1:])
    if not _OCTAL_TEXT.fullmatch(text):
        return None
    return bytes(int(code, 8) for code in text.split())


def url_encoded(data: bytes) -> bytes | None:
    """Percent-encoding: "%4e%69%63" (Warmups Day 7)."""
    text = as_text(data)
    if text is None or "%" not in text or not _URL_TEXT.fullmatch(text):
        return None
    decoded = unquote_to_bytes(text)
    return decoded if decoded != text.encode() else None


def html_entities(data: bytes) -> bytes | None:
    """HTML character references: "&#78;&#105;" (Warmups Day 8)."""
    text = as_text(data)
    if text is None or not _ENTITY.search(text):
        return None
    decoded = html.unescape(text)
    return decoded.encode("utf-8") if decoded != text else None


def json_escapes(data: bytes) -> bytes | None:
    """A JSON string of escapes: "\\u004e\\u0069" (Warmups Day 9), quoted or not."""
    text = as_text(data)
    if text is None or "\\u" not in text:
        return None
    body = text[1:-1] if len(text) >= 2 and text[0] == text[-1] == '"' else text
    try:
        value = json.loads(f'"{body}"')
    except ValueError:
        return None
    return value.encode("utf-8") if isinstance(value, str) and value != body else None


def bacon(data: bytes) -> bytes | None:
    """Five-letter a/b groups (Warmups Day 17). Values under 16 are hex nibbles, so the
    output is hex text for the next layer; otherwise they are the letters A-Z."""
    text = as_text(data)
    if text is None or not _BACON_TEXT.fullmatch(text):
        return None
    values = [int(group.translate(_BACON_BITS), 2) for group in text.split()]
    if all(value < 16 for value in values):
        return "".join("0123456789abcdef"[value] for value in values).encode("ascii")
    if all(value < 26 for value in values):
        return "".join(chr(65 + value) for value in values).encode("ascii")
    return None


# Formats no warmup has used yet (days 1-20), each strict enough to stay quiet on other
# text, so a new day that uses one is solved at the release instead of by hand.
_BASE85_TEXT = re.compile(r"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]+")
_QP_ESCAPE = re.compile(r"=[0-9A-Fa-f]{2}")
_QP_LONE_EQUALS = re.compile(r"=(?![0-9A-Fa-f]{2}|\r?\n|$)")
_UU_BEGIN = re.compile(r"begin [0-7]{3,4} \S.*")
_CODEPOINT_TEXT = re.compile(r"U\+[0-9A-Fa-f]{4,6}(?:[\s,]*U\+[0-9A-Fa-f]{4,6})*")
MAX_INFLATED = 4 * 1024 * 1024
_BRAILLE = {  # Grade 1 cells by dot bits (dot 1 = 0x01 ... dot 6 = 0x20).
    0x01: "a", 0x03: "b", 0x09: "c", 0x19: "d", 0x11: "e", 0x0B: "f", 0x1B: "g", 0x13: "h",
    0x0A: "i", 0x1A: "j", 0x05: "k", 0x07: "l", 0x0D: "m", 0x1D: "n", 0x15: "o", 0x0F: "p",
    0x1F: "q", 0x17: "r", 0x0E: "s", 0x1E: "t", 0x25: "u", 0x27: "v", 0x3A: "w", 0x2D: "x",
    0x3D: "y", 0x35: "z", 0x02: ",", 0x06: ";", 0x12: ":", 0x32: ".", 0x16: "!", 0x26: "?",
    0x04: "'", 0x24: "-", 0x00: " ",
}
_BRAILLE_NUMBER, _BRAILLE_CAPITAL = 0x3C, 0x20
_BRAILLE_DIGITS = dict(zip("abcdefghij", "1234567890"))
_NATO = {
    "alfa": "A", "alpha": "A", "bravo": "B", "charlie": "C", "delta": "D", "echo": "E",
    "foxtrot": "F", "golf": "G", "hotel": "H", "india": "I", "juliett": "J", "juliet": "J",
    "kilo": "K", "lima": "L", "mike": "M", "november": "N", "oscar": "O", "papa": "P",
    "quebec": "Q", "romeo": "R", "sierra": "S", "tango": "T", "uniform": "U", "victor": "V",
    "whiskey": "W", "whisky": "W", "x-ray": "X", "xray": "X", "yankee": "Y", "zulu": "Z",
    "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6",
    "seven": "7", "eight": "8", "nine": "9", "niner": "9",
}


def ascii85(data: bytes) -> bytes | None:
    """Adobe Ascii85 between <~ and ~>; without them too much ordinary text would fit."""
    text = as_text(data)
    if text is None or not (text.startswith("<~") and text.endswith("~>")):
        return None
    try:
        return base64.a85decode(text, adobe=True)
    except ValueError:
        return None


def base85(data: bytes) -> bytes | None:
    """RFC 1924 Base85 (git, Python b85), only when it decodes to text and re-encodes exactly."""
    compact = data.translate(None, _WHITESPACE)
    if len(compact) < 10 or len(compact) % 5 == 1:
        return None
    try:
        if not _BASE85_TEXT.fullmatch(compact.decode("ascii")):
            return None
        decoded = base64.b85decode(compact)
    except ValueError:
        return None
    if base64.b85encode(decoded) != compact or raw_text(decoded) is None:
        return None
    return decoded


def quoted_printable(data: bytes) -> bytes | None:
    """MIME quoted-printable: "=4E=69c=65"; every "=" must start an escape or a soft break."""
    text = as_text(data)
    if text is None or not _QP_ESCAPE.search(text) or _QP_LONE_EQUALS.search(text):
        return None
    decoded = quopri.decodestring(text.encode("ascii", "ignore"))
    return decoded if decoded != text.encode() else None


def uuencoded(data: bytes) -> bytes | None:
    """Classic uuencode between "begin <mode> <name>" and "end"."""
    text = raw_text(data)
    lines = text.strip().splitlines() if text else []
    if len(lines) < 3 or not _UU_BEGIN.fullmatch(lines[0]) or lines[-1].strip() != "end":
        return None
    out = bytearray()
    try:
        for line in lines[1:-1]:
            if line.strip() not in ("", "`"):
                out += binascii.a2b_uu(line)
    except binascii.Error:
        return None
    return bytes(out) or None


def inflated(data: bytes) -> bytes | None:
    """A zlib or gzip stream, by its header: e.g. Base64 of a compressed message."""
    if data[:2] == b"\x1f\x8b":
        wbits = 16 + zlib.MAX_WBITS
    elif len(data) > 2 and data[0] == 0x78 and int.from_bytes(data[:2], "big") % 31 == 0:
        wbits = zlib.MAX_WBITS
    else:
        return None
    inflater = zlib.decompressobj(wbits)
    try:
        out = inflater.decompress(data, MAX_INFLATED)
    except zlib.error:
        return None
    return out if out and inflater.eof and not inflater.unconsumed_tail else None


def braille(data: bytes) -> bytes | None:
    """Unicode Braille, grade 1: letters, the number sign before digits, the capital sign."""
    text = as_text(data)
    if text is None or not all(0x2800 <= ord(char) <= 0x283F or char.isspace() for char in text):
        return None
    out: list[str] = []
    number = capital = False
    for char in text:
        cell = ord(char) - 0x2800 if not char.isspace() else 0
        if cell == _BRAILLE_NUMBER:
            number = True
            continue
        if cell == _BRAILLE_CAPITAL:
            capital = True
            continue
        letter = _BRAILLE.get(cell)
        if letter is None:
            return None
        if number and letter in _BRAILLE_DIGITS:
            letter = _BRAILLE_DIGITS[letter]
        else:
            number = False
        out.append(letter.upper() if capital else letter)
        capital = False
    decoded = "".join(out)
    return decoded.encode("utf-8") if any(c.isalnum() for c in decoded) else None


def nato(data: bytes) -> bytes | None:
    """NATO spelling ("Hotel Echo Xray"); "/" or "|" separates words."""
    text = as_text(data)
    if text is None:
        return None
    words = [word.split() for word in re.split(r"\s*[/|]\s*", text.lower())]
    tokens = [token for word in words for token in word]
    if len(tokens) < 3 or any(token not in _NATO for token in tokens):
        return None
    return " ".join("".join(_NATO[token] for token in word) for word in words).encode("ascii")


_RL_TOKEN = re.compile(r"(\d{1,4}):(.)", re.S)


def runlength(data: bytes) -> bytes | None:
    """Run-length `count:char` pairs joined by commas (Day 24 Warmups):
    "1:N,1:i,1:c,1:e" -> "Nice". A comma can itself be a character ("1:,"), so the tokens
    are scanned left to right rather than split, and the whole text must be these pairs,
    so this never fires on ordinary text."""
    text = as_text(data)
    if text is None or ":" not in text:
        return None
    pieces: list[str] = []
    position = 0
    while position < len(text):
        match = _RL_TOKEN.match(text, position)
        if not match:
            return None
        count = int(match.group(1))
        if count < 1:
            return None
        pieces.append(match.group(2) * count)
        position = match.end()
        if position < len(text):  # A single comma separates tokens.
            if text[position] != ",":
                return None
            position += 1
    if not pieces:
        return None
    try:
        return "".join(pieces).encode("utf-8")
    except UnicodeEncodeError:
        return None


def codepoints(data: bytes) -> bytes | None:
    """Unicode code points: "U+004E U+0069"."""
    text = as_text(data)
    if text is None or not _CODEPOINT_TEXT.fullmatch(text):
        return None
    try:
        return "".join(chr(int(code, 16)) for code in re.findall(r"U\+([0-9A-Fa-f]{4,6})", text)).encode("utf-8")
    except (ValueError, UnicodeEncodeError):
        return None


_ROT13 = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)
_ROT47 = {code: 33 + (code - 33 + 47) % 94 for code in range(33, 127)}
_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_LOWER = _UPPER.lower()
_ATBASH = str.maketrans(_UPPER + _LOWER, _UPPER[::-1] + _LOWER[::-1])


def _caesar_table(shift: int) -> dict[int, int]:
    """Undo a forward shift: ciphertext letter minus `shift`."""
    back = (26 - shift) % 26
    return str.maketrans(_UPPER + _LOWER, _UPPER[back:] + _UPPER[:back] + _LOWER[back:] + _LOWER[:back])


_CAESAR = {shift: _caesar_table(shift) for shift in range(1, 26) if shift != 13}


def rot13(text: str) -> str:
    return text.translate(_ROT13)


def rot47(text: str) -> str:
    return text.translate(_ROT47)


def reverse(text: str) -> str:
    return text[::-1]


def atbash(text: str) -> str:
    return text.translate(_ATBASH)


def rail_fence(text: str, rails: int) -> str:
    """Undo a rail-fence (zigzag) transposition with `rails` rails."""
    if not 2 <= rails < len(text):
        return text
    period, size = 2 * (rails - 1), len(text)
    # Rail r holds positions r, P-r, P+r, 2P-r, ... (P = period): built per rail, no per-character sort.
    order = list(range(0, size, period))
    for rail in range(1, rails - 1):
        order += sorted((*range(rail, size, period), *range(period - rail, size, period)))
    order += range(rails - 1, size, period)
    plain = [""] * size
    for char, position in zip(text, order):
        plain[position] = char
    return "".join(plain)


# --- Formats no warmup day has used yet (anticipated). Each is strict on its whole input and
# must decode to printable text, so on an earlier day's blob it rejects at once or adds nothing.

_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_BASE91 = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
           "!#$%&()*+,./:;<=>?@[]^_`{|}~\"")
_BASE45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_INDEX58, _INDEX62, _INDEX91, _INDEX45 = ({c: i for i, c in enumerate(a)} for a in (_BASE58, _BASE62, _BASE91, _BASE45))
_BASE58_TEXT = re.compile(r"[1-9A-HJ-NP-Za-km-z]{6,4096}")
_BASE62_TEXT = re.compile(r"(?=[^\d]*\d)(?=[^A-Z]*[A-Z])(?=[^a-z]*[a-z])[0-9A-Za-z]{8,4096}")
_BASE91_TEXT = re.compile(r"[A-Za-z0-9!#$%&()*+,./:;<=>?@\[\]^_`{|}~\"]{8,}")
_BASE45_TEXT = re.compile(r"[0-9A-Z $%*+\-./:]{3,}")
MAX_BF_STEPS = 2_000_000


def _big_base(text: str, index: dict[str, int], radix: int, zero: str) -> bytes:
    value = 0
    for char in text:
        value = value * radix + index[char]
    body = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
    return b"\0" * (len(text) - len(text.lstrip(zero))) + body


def _texty(decoded: bytes) -> bytes | None:
    return decoded if decoded and raw_text(decoded) is not None else None


def base58(data: bytes) -> bytes | None:
    """Bitcoin Base58 (no 0, O, I, l): a big number, leading "1"s are zero bytes."""
    text = as_text(data)
    if text is None or not _BASE58_TEXT.fullmatch(text):
        return None
    return _texty(_big_base(text, _INDEX58, 58, "1"))


def base62(data: bytes) -> bytes | None:
    """Base62 (0-9A-Za-z), as a big number; needs digits and both cases, unlike a plain word."""
    text = as_text(data)
    if text is None or not _BASE62_TEXT.fullmatch(text):
        return None
    return _texty(_big_base(text, _INDEX62, 62, "0"))


def base91(data: bytes) -> bytes | None:
    """basE91 (Joachim Henke's reference decoder)."""
    text = as_text(data)
    if text is None or not _BASE91_TEXT.fullmatch(text):
        return None
    out, value, bits, count = bytearray(), -1, 0, 0
    for char in text:
        digit = _INDEX91[char]
        if value < 0:
            value = digit
            continue
        value += digit * 91
        bits |= value << count
        count += 13 if (value & 8191) > 88 else 14
        while True:
            out.append(bits & 255)
            bits >>= 8
            count -= 8
            if count <= 7:
                break
        value = -1
    if value >= 0:
        out.append((bits | value << count) & 255)
    return _texty(bytes(out))


def base45(data: bytes) -> bytes | None:
    """RFC 9285 Base45 (QR-code friendly): three characters per two bytes."""
    text = as_text(data)
    if text is None or len(text) % 3 == 1 or not _BASE45_TEXT.fullmatch(text):
        return None
    out = bytearray()
    for i in range(0, len(text), 3):
        chunk = [_INDEX45[c] for c in text[i:i + 3]]
        value = sum(d * 45 ** n for n, d in enumerate(chunk))
        if len(chunk) == 3:
            if value > 0xFFFF:
                return None
            out += value.to_bytes(2, "big")
        elif value > 0xFF:
            return None
        else:
            out.append(value)
    return _texty(bytes(out))


def base100(data: bytes) -> bytes | None:
    """base100 (emoji): every byte b is the code point U+1F3F7 + b."""
    text = as_text(data)
    if text is None:
        return None
    compact = "".join(text.split())
    if len(compact) < 2 or not all(0x1F3F7 <= ord(c) <= 0x1F4F6 for c in compact):
        return None
    return _texty(bytes(ord(c) - 0x1F3F7 for c in compact))


# Forecast for days 26-31 (tests/test_forecast.py): the next steps of series the course is in.
# Compression (Day 21 gzip, Day 22 zlib), number bases (64, 32, 85), character encodings
# (Day 19-20 UTF-16, Day 25 code points) and Day 24's "the comma knows where to stop".
_BASE36_TEXT = re.compile(r"(?=\D*\d)(?:(?=[^a-z]*[a-z])[0-9a-z]{8,4096}|(?=[^A-Z]*[A-Z])[0-9A-Z]{8,4096})")
_BIGINT_TEXT = re.compile(r"[1-9]\d{19,4095}")  # int() refuses past 4300 digits.
_BASE32HEX_TEXT = re.compile(r"(?=[^A-V]*[A-V])[0-9A-V]{8,}={0,6}")
_UTF7_RUN = re.compile(r"\+[A-Za-z0-9+/]+-?")
_DUMP_OFFSET = re.compile(r"([0-9a-fA-F]{6,16}):?(?:\s+|$)")
_DUMP_GROUP = re.compile(r"(?:[0-9a-fA-F]{2}){1,4}")
_MIME_WORD = re.compile(r"=\?([\w.:-]+)\?([BbQq])\?([^?\s]*)\?=")
_NETSTRING_LENGTH = re.compile(rb"(0|[1-9]\d{0,5}):")


def unpacked(data: bytes) -> bytes | None:
    """bzip2, xz or LZMA-alone by their headers, or a raw deflate stream (no header, so only
    from binary input and only to text): the compressors after gzip and zlib."""
    if data[:3] == b"BZh" and data[4:10] == b"1AY&SY":
        kind = "bz2"
    elif data[:6] == b"\xfd7zXZ\0" or (data[:1] == b"\x5d" and int.from_bytes(data[1:5], "little").bit_count() == 1):
        kind = "xz"  # The xz decompressor reads LZMA-alone too.
    elif raw_text(data) is None:
        kind = "raw"
    else:
        return None
    try:
        out = decompress(data, kind, MAX_INFLATED)
    except ZIP_ERRORS:
        return None
    return _texty(out) if kind == "raw" else out or None


def base36(data: bytes) -> bytes | None:
    """Base36 (0-9 and one case of a-z) as a big number; needs digits and letters, unlike a word."""
    text = as_text(data)
    if text is None or not _BASE36_TEXT.fullmatch(text):
        return None
    value = int(text, 36)
    return _texty(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def bigint(data: bytes) -> bytes | None:
    """The message's bytes as one big decimal number (int.from_bytes of the text)."""
    text = as_text(data)
    if text is None or not _BIGINT_TEXT.fullmatch(text):
        return None
    value = int(text)
    return _texty(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def base32hex(data: bytes) -> bytes | None:
    """RFC 4648 base32hex (0-9A-V), the extended-hex alphabet of Base32."""
    text = as_text(data)
    if text is None or not _BASE32HEX_TEXT.fullmatch(text):
        return None
    try:
        return _texty(base64.b32hexdecode(text.rstrip("=") + "=" * (-len(text.rstrip("=")) % 8)))
    except (binascii.Error, ValueError):
        return None


def ebcdic(data: bytes) -> bytes | None:
    """EBCDIC (code page 037): bytes UTF-8 cannot read, mostly letters and spaces as cp037."""
    if len(data) < 4 or raw_text(data) is not None:
        return None
    text = data.decode("cp037")
    if not text.translate(_LAYOUT).isprintable() or sum(c.isalnum() or c == " " for c in text) < 0.7 * len(text):
        return None
    return text.encode("utf-8")


def utf7(data: bytes) -> bytes | None:
    """UTF-7 ("warmup+ACE- To"); a stray "+" in Base64 decodes to CJK noise, which is refused."""
    text = as_text(data)
    if text is None or not _UTF7_RUN.search(text):
        return None
    try:
        decoded = text.encode("ascii").decode("utf-7")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return None
    if decoded == text or not decoded.translate(_LAYOUT).isprintable() or any(ord(c) >= 0x800 for c in decoded):
        return None
    return decoded.encode("utf-8")


def hexdump(data: bytes) -> bytes | None:
    """`xxd` ("00000000: 4e69 6365  Nice") or `hexdump -C` ("00000000  4e 69  |Ni|") back to bytes."""
    text = as_text(data)
    if text is None:
        return None
    out = bytearray()
    for number, line in enumerate(text.splitlines()):
        match = _DUMP_OFFSET.match(line)
        if not match or (number == 0 and int(match[1], 16) != 0):
            return None
        body = line[match.end():]
        # hexdump -C has a double space mid-row, so its |ASCII| column is cut first; xxd's follows two spaces.
        body = body.split("|", 1)[0] if "|" in body else body.split("  ", 1)[0]
        for group in body.split():
            if not _DUMP_GROUP.fullmatch(group):
                return None
            out += bytes.fromhex(group)
    return bytes(out) or None


def mime_words(data: bytes) -> bytes | None:
    """RFC 2047 encoded words ("=?utf-8?B?TmljZQ==?=", "=?utf-8?Q?Nice_work?="), as in mail headers."""
    text = as_text(data)
    if text is None or not text.startswith("=?") or _MIME_WORD.sub("", text).strip():
        return None
    out = []
    for charset, kind, payload in _MIME_WORD.findall(text):
        try:
            raw = (base64.b64decode(payload + "=" * (-len(payload) % 4), validate=True) if kind in "Bb"
                   else quopri.decodestring(payload.encode("ascii"), header=True))
            out.append(raw.decode(charset))
        except (binascii.Error, LookupError, UnicodeError, ValueError):
            return None
    return "".join(out).encode("utf-8") or None


def netstrings(data: bytes) -> bytes | None:
    """Netstrings `<length>:<bytes>,` back to back ("4:Nice,5: work,"); Day 24's one-character
    tokens without the last comma stay the runlength layer's."""
    blob = data.strip(_WHITESPACE)
    out, at = bytearray(), 0
    while at < len(blob):
        match = _NETSTRING_LENGTH.match(blob, at)
        if not match:
            return None
        end = match.end() + int(match[1])
        if blob[end:end + 1] != b",":
            return None
        out += blob[match.end():end]
        at = end + 1
        while blob[at:at + 1] in (b"\n", b"\r"):
            at += 1
    return _texty(bytes(out))


_OOK = {("Ook.", "Ook?"): ">", ("Ook?", "Ook."): "<", ("Ook.", "Ook."): "+", ("Ook!", "Ook!"): "-",
        ("Ook!", "Ook."): ".", ("Ook.", "Ook!"): ",", ("Ook!", "Ook?"): "[", ("Ook?", "Ook!"): "]"}


def brainfuck(data: bytes) -> bytes | None:
    """What a Brainfuck (or Ook!) program prints, run with a step cap and no input."""
    text = as_text(data)
    if text is None:
        return None
    if text.startswith("Ook"):
        words = text.split()
        if len(words) % 2 or not all(pair in _OOK for pair in zip(words[::2], words[1::2])):
            return None
        text = "".join(_OOK[pair] for pair in zip(words[::2], words[1::2]))
    program = "".join(text.split())
    if "." not in program or program.strip("+-<>[].") or "," in program:
        return None
    jumps, stack = {}, []
    for at, op in enumerate(program):
        if op == "[":
            stack.append(at)
        elif op == "]":
            if not stack:
                return None
            start = stack.pop()
            jumps[start], jumps[at] = at, start
    if stack:
        return None
    tape, cell, pc, out = bytearray(30000), 0, 0, bytearray()
    for _ in range(MAX_BF_STEPS):
        if pc >= len(program):
            return _texty(bytes(out))
        op = program[pc]
        if op == "+":
            tape[cell] = (tape[cell] + 1) & 255
        elif op == "-":
            tape[cell] = (tape[cell] - 1) & 255
        elif op == ">":
            cell += 1
            if cell >= len(tape):
                return None
        elif op == "<":
            cell -= 1
            if cell < 0:
                return None
        elif op == ".":
            out.append(tape[cell])
        elif op == "[" and not tape[cell]:
            pc = jumps[pc]
        elif op == "]" and tape[cell]:
            pc = jumps[pc]
        pc += 1
    return None


# --- Keyed letter ciphers, broken with the warmup sentence as a crib ----------------------------
# Every warmup states "Nice work decoding this warmup! To solve, submit this exact answer to the
# Game Master: <slug>". These ciphers keep word boundaries, so the ciphertext's word-length
# pattern places the crib; the key then follows from the aligned letters, no key search.

CRIB = "nice work decoding this warmup to solve submit this exact answer to the game master".split()
_CRIB_PATTERNS = ("".join(chr(len(w)) for w in CRIB), "".join(chr(len(w)) for w in CRIB[7:]))
_WORD = re.compile(r"[A-Za-z]+")


@lru_cache(maxsize=8)
def _aligned(text: str) -> tuple[list[int], dict[int, int]] | None:
    """(cipher letters 0-25 in order, {letter index: crib plain letter}) or None."""
    if text.count(" ") < 7 or len(text) > MAX_WEAK_TEXT:
        return None
    words = [(m.start(), m.group()) for m in _WORD.finditer(text)]
    shape = "".join(chr(min(len(w), 0x10FFFF)) for _, w in words)
    for pattern, crib in zip(_CRIB_PATTERNS, (CRIB, CRIB[7:])):
        at = shape.find(pattern)
        if at >= 0:
            break
    else:
        return None
    letters = [ord(c.lower()) - 97 for _, w in words for c in w]
    first = sum(len(w) for _, w in words[:at])
    plain = [ord(c) - 97 for c in "".join(crib)]
    return letters, {first + i: p for i, p in enumerate(plain)}


def _render(text: str, plain: list[int | None]) -> str:
    """The text with its letters replaced by `plain` (case kept); "" if a letter is unknown."""
    if any(p is None for p in plain):
        return ""
    stream = iter(plain)
    out = _WORD.sub(lambda m: "".join(chr(next(stream) + (65 if c.isupper() else 97)) for c in m.group()), text)
    return "" if out == text else out


def _periodic(stream: dict[int, int]) -> list[int] | None:
    for period in range(1, 21):
        key: dict[int, int] = {}
        if all(key.setdefault(i % period, k) == k for i, k in stream.items()) and len(key) == period:
            return [key[i] for i in range(period)]
    return None


def vigenere(text: str) -> str:
    found = _aligned(text)
    if not found:
        return ""
    letters, crib = found
    key = _periodic({i: (letters[i] - p) % 26 for i, p in crib.items()})
    if not key:
        return ""
    return _render(text, [(c - key[i % len(key)]) % 26 for i, c in enumerate(letters)])


def beaufort(text: str) -> str:
    found = _aligned(text)
    if not found:
        return ""
    letters, crib = found
    key = _periodic({i: (letters[i] + p) % 26 for i, p in crib.items()})
    if not key or len(key) == 1 and key[0] == 25:  # Beaufort with key "z" is Atbash: WEAK_STEPS has it.
        return ""
    return _render(text, [(key[i % len(key)] - c) % 26 for i, c in enumerate(letters)])


def autokey(text: str) -> str:
    """Plaintext autokey: c[i] = p[i] + (key[i] if i < len(key) else p[i - len(key)])."""
    found = _aligned(text)
    if not found:
        return ""
    letters, crib = found
    for period in range(1, 17):
        checks = [i for i in crib if i - period in crib]
        if len(checks) < 12 or any((letters[i] - crib[i]) % 26 != crib[i - period] for i in checks):
            continue
        plain: list[int | None] = [None] * len(letters)
        for i, p in crib.items():
            plain[i] = p
        for i in range(len(letters) - 1, period - 1, -1):  # backwards: p[i - P] = c[i] - p[i]
            if plain[i] is not None and plain[i - period] is None:
                plain[i - period] = (letters[i] - plain[i]) % 26
        for i in range(period, len(letters)):              # forwards: p[i] = c[i] - p[i - P]
            if plain[i] is None and plain[i - period] is not None:
                plain[i] = (letters[i] - plain[i - period]) % 26
        return _render(text, plain)
    return ""


def affine(text: str) -> str:
    """c = a*p + b (mod 26); Caesar (a = 1) and Atbash (a = b = 25) have steps of their own."""
    found = _aligned(text)
    if not found:
        return ""
    letters, crib = found
    pairs = {(letters[i], p) for i, p in crib.items()}
    for a in (3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
        c0, p0 = next(iter(pairs))
        b = (c0 - a * p0) % 26
        if (a, b) != (25, 25) and all((a * p + b) % 26 == c for c, p in pairs):
            inverse = pow(a, -1, 26)
            return _render(text, [(inverse * (c - b)) % 26 for c in letters])
    return ""


def substitution(text: str) -> str:
    """A keyed alphabet: the crib maps 21 letters; only a text using no other letter decodes."""
    found = _aligned(text)
    if not found:
        return ""
    letters, crib = found
    table: dict[int, int] = {}
    for i, p in crib.items():
        if table.setdefault(letters[i], p) != p:
            return ""
    if len(set(table.values())) != len(table):
        return ""
    return _render(text, [table.get(c) for c in letters])


def scytale(text: str, columns: int) -> str:
    """Undo a columnar transposition with the columns in order (scytale): read back row-wise."""
    if not 2 <= columns < len(text):
        return ""
    sizes = [len(range(c, len(text), columns)) for c in range(columns)]
    plain, at = [""] * len(text), 0
    for c, size in enumerate(sizes):
        plain[c::columns] = text[at:at + size]
        at += size
    return "".join(plain)


# Ordered so the cheapest, most specific formats are tried first.
LAYERS = (
    ("morse", morse), ("bacon", bacon), ("binary", binary), ("octal", octal),
    ("hex", hexadecimal), ("decimal", decimal), ("base32", base32_text),
    ("base64", base64_text), ("url", url_encoded), ("html", html_entities),
    ("json", json_escapes),
    # Not used by days 1-20; after the known ones, so they never crowd a known chain out.
    ("ascii85", ascii85), ("base85", base85), ("qp", quoted_printable), ("uu", uuencoded),
    ("zlib", inflated), ("braille", braille), ("nato", nato), ("unicode", codepoints),
    ("runlength", runlength),  # Day 24: "1:N,1:i,1:c,1:e" -> "Nice".
    # Anticipated (no day yet): strict, text-only results, last so known chains come first.
    ("base58", base58), ("base62", base62), ("base91", base91), ("base45", base45),
    ("base100", base100), ("brainfuck", brainfuck),
    # Forecast for days 26-31 (tests/test_forecast.py), strict like the ones above.
    ("unpacked", unpacked), ("base36", base36), ("bigint", bigint), ("base32hex", base32hex),
    ("ebcdic", ebcdic), ("utf7", utf7), ("hexdump", hexdump), ("mime", mime_words), ("netstring", netstrings),
)
# The anticipated layers above, kept out of guessed two-step chains (warmups._guess_fragment).
ANTICIPATED = frozenset({"base58", "base62", "base91", "base45", "base100", "brainfuck", "unpacked", "base36",
                         "bigint", "base32hex", "ebcdic", "utf7", "hexdump", "mime", "netstring"})
# Letter rotations apply to any text, so they are tried only as a last step.
FINAL_STEPS = (("rot13", rot13), ("rot47", rot47))
# Weaker text ciphers turn any text into other text, so they are tried as a last step
# too, and only on short texts: decoy-free warmup sized, never a large script on the clock.
WEAK_STEPS = (
    ("reverse", reverse), ("atbash", atbash),
    *((f"caesar{shift}", lambda text, table=table: text.translate(table)) for shift, table in _CAESAR.items()),
    *((f"railfence{rails}", lambda text, rails=rails: rail_fence(text, rails)) for rails in range(2, 9)),
    # Anticipated: keyed ciphers broken with the warmup crib ("" when it does not fit), and the
    # plain columnar transposition. Each derives its key from the text, so a proven chain replays.
    ("vigenere", vigenere), ("beaufort", beaufort), ("autokey", autokey), ("affine", affine),
    ("substitution", substitution),
    *((f"scytale{columns}", lambda text, columns=columns: scytale(text, columns)) for columns in range(2, 13)),
)
MAX_WEAK_TEXT = 16 * 1024

# Only "answer"/"flag" statements count. Assignments such as `$password = "x"` in a
# decoded script are evidence to analyze, not a stated answer.
_ANSWER_PHRASE = re.compile(
    r"\b(?:answer|flag)\b[^:\n]{0,80}?(?::|\bis\b:?)\s*[\"'`]?([^\s\"'`]{1,200})", re.I,
)
_FLAG = re.compile(r"\b(?:flag|ctf|huntress)\{[^{}\s]{1,200}\}", re.I)
_TRAILING = ".,;!?)]>"


def extract_answer(text: str) -> str | None:
    """The single answer a decoded text explicitly states, or None if absent or ambiguous."""
    lowered = text.lower()
    # Both patterns need one of these words; most texts in a decode search have none.
    if "answer" not in lowered and "flag" not in lowered and not (
        "{" in text and ("ctf" in lowered or "huntress" in lowered)
    ):
        return None
    found = {match.group() for match in _FLAG.finditer(text)}
    if not found:
        found = {match.group(1).rstrip(_TRAILING) for match in _ANSWER_PHRASE.finditer(text)}
    found.discard("")
    return found.pop() if len(found) == 1 else None


_STEPS = {**dict(LAYERS), **dict(FINAL_STEPS), **dict(WEAK_STEPS)}
_FINAL_NAMES = frozenset(name for name, _ in (*FINAL_STEPS, *WEAK_STEPS))


def _run_chain(data: bytes, chain: tuple[str, ...], keep_edges: bool) -> str | None:
    """Text after the named steps, or None when a step does not apply."""
    if not chain or any(name not in _STEPS for name in chain):
        return None
    to_text = raw_text if keep_edges else as_text
    value: bytes | str = data
    for name in chain:
        step = _STEPS[name]
        if name in _FINAL_NAMES:
            text = value if isinstance(value, str) else to_text(value)
            if text is None:
                return None
            value = step(text)
            if not value:  # A keyed step that does not fit (a crib-less fragment): no piece, not "".
                return None
        else:
            raw = value.encode() if isinstance(value, str) else value
            value = step(raw)
            if value is None:
                return None
    return value if isinstance(value, str) else to_text(value)


def apply_chain(data: bytes, chain: tuple[str, ...]) -> tuple[str, str] | None:
    """Replay a proven chain (e.g. ("morse", "hex")) directly: (text, answer) or None."""
    text = _run_chain(data, chain, keep_edges=False)
    answer = extract_answer(text) if text is not None else None
    return (text, answer) if answer is not None else None


def decode_fragment(payload: str, chain: tuple[str, ...]) -> str | None:
    """One piece of a split message, decoded with its edge spaces intact ("nswer " + "to")."""
    return _run_chain(payload.encode("utf-8"), chain, keep_edges=True)


def peel(data: bytes) -> list[tuple[tuple[str, ...], str, str]]:
    """Breadth-first decode until text states an answer: [(chain, text, answer)].

    The undecoded input never counts on its own: at least one layer must apply.
    """
    found = []
    queue = deque([((), data)])
    seen = {data}
    while queue:
        chain, value = queue.popleft()
        text = as_text(value)
        if text is not None:
            answer = extract_answer(text) if chain else None
            if answer is not None:
                found.append((chain, text, answer))
                continue
            finals = FINAL_STEPS + WEAK_STEPS if len(text) <= MAX_WEAK_TEXT else FINAL_STEPS
            for name, step in finals:
                rotated = step(text)
                answer = extract_answer(rotated)
                if answer is not None:
                    found.append(((*chain, name), rotated, answer))
        if len(chain) >= MAX_LAYER_DEPTH:
            continue
        for name, decode in LAYERS:
            decoded = decode(value)
            if decoded and decoded not in seen and len(seen) < MAX_NODES:
                seen.add(decoded)
                queue.append(((*chain, name), decoded))
    return found
