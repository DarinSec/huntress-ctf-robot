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
import re
from urllib.parse import unquote_to_bytes

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

    UTF-8, or UTF-16 when the bytes start with a byte-order mark (Warmups Day 19).
    """
    try:
        text = data.decode("utf-16" if data[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8")
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
_URL_TEXT = re.compile(r"(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9\-._~!$&'()*+,;=:@/?# ])+")
_ENTITY = re.compile(r"&(?:#\d{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")
_BACON_TEXT = re.compile(r"[abAB]{5}(?:\s+[abAB]{5})*")
_BACON_BITS = str.maketrans("abAB", "0101")


def octal(data: bytes) -> bytes | None:
    """Three-digit octal byte codes: "116 151 143" (Warmups Day 6)."""
    text = as_text(data)
    if text is None or not _OCTAL_TEXT.fullmatch(text):
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
    period = 2 * (rails - 1)
    rail_of = [min(i % period, period - i % period) for i in range(len(text))]
    order = sorted(range(len(text)), key=lambda i: (rail_of[i], i))
    plain = [""] * len(text)
    for char, position in zip(text, order):
        plain[position] = char
    return "".join(plain)


# Ordered so the cheapest, most specific formats are tried first.
LAYERS = (
    ("morse", morse), ("bacon", bacon), ("binary", binary), ("octal", octal),
    ("hex", hexadecimal), ("decimal", decimal), ("base32", base32_text),
    ("base64", base64_text), ("url", url_encoded), ("html", html_entities),
    ("json", json_escapes),
)
# Letter rotations apply to any text, so they are tried only as a last step.
FINAL_STEPS = (("rot13", rot13), ("rot47", rot47))
# Weaker text ciphers turn any text into other text, so they are tried as a last step
# too, and only on short texts: decoy-free warmup sized, never a large script on the clock.
WEAK_STEPS = (
    ("reverse", reverse), ("atbash", atbash),
    *((f"caesar{shift}", lambda text, table=table: text.translate(table)) for shift, table in _CAESAR.items()),
    *((f"railfence{rails}", lambda text, rails=rails: rail_fence(text, rails)) for rails in range(2, 9)),
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
