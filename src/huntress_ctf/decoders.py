"""Strict, pure decoders for layered text encodings and answer-phrase extraction.

Every decoder returns None unless its whole input matches the format, so a
breadth-first search over them stays small and never guesses at partial data.
"""

from __future__ import annotations

import base64
import binascii
from collections import deque
import re

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
_WHITESPACE = re.compile(rb"\s+")


def as_text(data: bytes) -> str | None:
    """Printable UTF-8 text, or None for binary data."""
    try:
        text = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    if not text or any(not char.isprintable() and char not in "\t\r\n" for char in text):
        return None
    return text


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
    compact = _WHITESPACE.sub(b"", data)
    if len(compact) < 4 or len(compact) % 4:
        return None
    try:
        if not _BASE64_TEXT.fullmatch(compact.decode("ascii")):
            return None
        if b"-" in compact or b"_" in compact:
            decoded = base64.urlsafe_b64decode(compact)
            canonical = base64.urlsafe_b64encode(decoded)
        else:
            decoded = base64.b64decode(compact, validate=True)
            canonical = base64.b64encode(decoded)
    except (binascii.Error, ValueError):
        return None
    return decoded if canonical == compact else None


def base32_text(data: bytes) -> bytes | None:
    compact = _WHITESPACE.sub(b"", data)
    if len(compact) < 8 or len(compact) % 8:
        return None
    try:
        if not _BASE32_TEXT.fullmatch(compact.decode("ascii")):
            return None
        decoded = base64.b32decode(compact)
    except (binascii.Error, ValueError):
        return None
    return decoded if base64.b32encode(decoded) == compact else None


def rot13(text: str) -> str:
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    ))


def rot47(text: str) -> str:
    return "".join(
        chr(33 + (ord(char) - 33 + 47) % 94) if "!" <= char <= "~" else char
        for char in text
    )


# Ordered so the cheapest, most specific formats are tried first.
LAYERS = (
    ("morse", morse), ("binary", binary), ("hex", hexadecimal),
    ("decimal", decimal), ("base32", base32_text), ("base64", base64_text),
)
# Letter rotations apply to any text, so they are tried only as a last step.
FINAL_STEPS = (("rot13", rot13), ("rot47", rot47))

# Only "answer"/"flag" statements count. Assignments such as `$password = "x"` in a
# decoded script are evidence to analyze, not a stated answer.
_ANSWER_PHRASE = re.compile(
    r"\b(?:answer|flag)\b[^:\n]{0,80}?(?::|\bis\b:?)\s*[\"'`]?([^\s\"'`]{1,200})", re.I,
)
_FLAG = re.compile(r"\b(?:flag|ctf|huntress)\{[^{}\s]{1,200}\}", re.I)
_TRAILING = ".,;!?)]>"


def extract_answer(text: str) -> str | None:
    """The single answer a decoded text explicitly states, or None if absent or ambiguous."""
    found = {match.group() for match in _FLAG.finditer(text)}
    if not found:
        found = {match.group(1).rstrip(_TRAILING) for match in _ANSWER_PHRASE.finditer(text)}
    found.discard("")
    return found.pop() if len(found) == 1 else None


_STEPS = {**dict(LAYERS), **dict(FINAL_STEPS)}


def apply_chain(data: bytes, chain: tuple[str, ...]) -> tuple[str, str] | None:
    """Replay a proven chain (e.g. ("morse", "hex")) directly: (text, answer) or None."""
    if not chain or any(name not in _STEPS for name in chain):
        return None
    value: bytes | str = data
    for name in chain:
        step = _STEPS[name]
        if name in dict(FINAL_STEPS):
            text = value if isinstance(value, str) else as_text(value)
            if text is None:
                return None
            value = step(text)
        else:
            raw = value.encode() if isinstance(value, str) else value
            value = step(raw)
            if value is None:
                return None
    text = value if isinstance(value, str) else as_text(value)
    answer = extract_answer(text) if text is not None else None
    return (text, answer) if answer is not None else None


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
            for name, step in FINAL_STEPS:
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
