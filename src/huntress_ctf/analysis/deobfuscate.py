"""Undo the common script obfuscators statically, for questions the plain text could not answer.

A new Script day tends to wrap the same hidden record in one more layer of obfuscation. The
rules below write out what a well-known obfuscator hides, without running anything:

- JavaScript `String.fromCharCode(72, 105)`, PowerShell `[char]72+[char]105` and
  `-join [char[]](72,105)`, VBScript `Chr(72) & Chr(105)`, Python `chr(72)+chr(105)` and
  `bytes([72, 105]).decode()`: each becomes the string literal "Hi".
- PowerShell format strings `("{1}{0}" -f 'b','a')` -> 'ab', and backticks inside words
  (I`E`X -> IEX).
- Batch substring expansion: `%v:~2,3%` and `%v%` over the script's own `set v=...` lines.
- Dean Edwards' `eval(function(p,a,c,k,e,d){...})` packer, unpacked.
- `powershell -EncodedCommand <Base64 UTF-16LE>`, and Base64 literals that hold a gzip, zlib
  or (next to DeflateStream) raw-deflate stream, inflated within a bound.

deobfuscate() returns the text with those rewrites (decoded payloads appended after it), or
the text itself when no rule applies, so callers retry only when something changed. Each rule
looks for its own marker first, and the caller runs it only for an unanswered question, so a
day the plain text already answers costs nothing more.
"""

from __future__ import annotations

import base64
import binascii
import re

from ..containers import ZIP_ERRORS, decompress

MAX_TEXT = 4 * 1024 * 1024
MAX_INFLATED = 1024 * 1024
_NUM = r"(?:0x[0-9a-fA-F]+|\d+)"


def _literal(codes) -> str | None:
    try:
        text = "".join(chr(int(code, 0) if code.lower().startswith("0x") else int(code)) for code in codes)
    except (ValueError, OverflowError):
        return None
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _numbers(blob: str) -> list[str]:
    return re.findall(_NUM, blob)


def _char_codes(text: str) -> str:
    rules = (
        re.compile(r"String\.fromCharCode\s*\(\s*((?:" + _NUM + r"\s*,\s*)*" + _NUM + r")\s*\)"),
        re.compile(r"(?:-join\s*\(?\s*|\[string\]::join\(\s*['\"]{2}\s*,\s*)\[char\[\]\]\s*\(\s*((?:" + _NUM
                   + r"\s*,\s*)*" + _NUM + r")\s*\)\)?", re.I),
        re.compile(r"bytes?(?:array)?\(\s*\[\s*((?:" + _NUM + r"\s*,\s*)*" + _NUM + r")\s*,?\s*\]\s*\)\s*\.decode\([^)]*\)"),
    )
    for rule in rules:
        text = rule.sub(lambda m: _literal(_numbers(m.group(1))) or m.group(), text)
    # Runs of single characters joined by + or &: [char]72+[char]105, Chr(72) & Chr(105), chr(72)+chr(105).
    run = re.compile(r"(?:(?:\[char\]\s*\(?\s*" + _NUM + r"\s*\)?|\bchr[wb]?\(\s*" + _NUM + r"\s*\))\s*[+&]?\s*){2,}", re.I)
    return run.sub(lambda m: (_literal(re.findall(r"(?<![\w$])" + _NUM, re.sub(r"(?i)\[char\]|chr[wb]?", " ", m.group())))
                              or m.group()) + " ", text)


_FORMAT = re.compile(r"\(\s*([\"'])((?:[^\"'{}]|\{\d+\})*)\1\s*-f\s*((?:([\"'])[^\"']*\4\s*,\s*)*([\"'])[^\"']*\5)\s*\)", re.I)


def _format_operator(text: str) -> str:
    def render(m):
        values = [a or b for a, b in re.findall(r"\"([^\"]*)\"|'([^']*)'", m.group(3))]
        try:
            return "'" + re.sub(r"\{(\d+)\}", lambda f: values[int(f.group(1))], m.group(2)) + "'"
        except IndexError:
            return m.group()
    return _FORMAT.sub(render, text)


def _batch(text: str) -> str:
    values: dict[str, str] = {}
    for name, value in re.findall(r'(?im)^\s*set\s+"?([\w.$#@-]+)=([^"\r\n]*)"?\s*$', text):
        values[name.lower()] = value

    def expand(m):
        value = values.get(m.group(1).lower())
        if value is None:
            return m.group()
        if m.group(2) is None:
            return value
        start, length = int(m.group(2)), m.group(3)
        start = start if start >= 0 else max(0, len(value) + start)
        if length is None:
            return value[start:]
        length = int(length)
        return value[start:start + length] if length >= 0 else value[start:len(value) + length]
    if not values:
        return text
    return re.sub(r"%([\w.$#@-]+)(?::~(-?\d+)(?:,(-?\d+))?)?%", expand, text)


def _base(number: int, radix: int) -> str:
    """The packer's own encoder: e(c) = (c < a ? '' : e(c / a)) + (c % a > 35 ? chr(c % a + 29) : base36)."""
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    head = "" if number < radix else _base(number // radix, radix)
    rest = number % radix
    return head + (chr(rest + 29) if rest > 35 else digits[rest])


_PACKED = re.compile(r"\}\s*\(\s*'((?:[^'\\]|\\.)*)'\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*'((?:[^'\\]|\\.)*)'\.split\('\|'\)", re.S)


def unpack_packer(text: str) -> str | None:
    if "eval(function(p,a,c,k,e," not in text.replace(" ", ""):
        return None
    m = _PACKED.search(text)
    if not m:
        return None
    payload, radix, count, words = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4).split("|")
    if not 2 <= radix <= 95 or count > 65536:
        return None
    table = {_base(i, radix): (words[i] if i < len(words) and words[i] else _base(i, radix)) for i in range(count)}
    payload = payload.replace("\\'", "'").replace("\\\\", "\\")
    return re.sub(r"\b\w+\b", lambda w: table.get(w.group(), w.group()), payload)


def _decoded_payloads(text: str) -> list[str]:
    found = []
    for m in re.finditer(r"(?i)\s-e(?:c|nc|ncodedcommand)?\s+['\"]?([A-Za-z0-9+/]{16,}={0,2})", text):
        try:
            found.append(base64.b64decode(m.group(1), validate=True).decode("utf-16-le"))
        except (ValueError, binascii.Error, UnicodeDecodeError):
            pass
    raw_deflate = "deflatestream" in text.lower()
    for m in re.finditer(r"['\"]([A-Za-z0-9+/]{24,}={0,2})['\"]", text):
        try:
            blob = base64.b64decode(m.group(1), validate=True)
        except (ValueError, binascii.Error):
            continue
        kind = ("gzip" if blob[:2] == b"\x1f\x8b" else "zlib" if blob[:1] == b"\x78" and int.from_bytes(blob[:2], "big") % 31 == 0
                else "raw" if raw_deflate else None)
        if kind is None:
            continue
        try:
            found.append(decompress(blob, kind, MAX_INFLATED).decode("utf-8"))
        except (*ZIP_ERRORS, UnicodeDecodeError):
            continue
    return found


def deobfuscate(text: str) -> str:
    if not text or len(text) > MAX_TEXT:
        return text
    out = text
    low = text.lower()
    if "fromcharcode" in low or "[char" in low or "chr" in low or ".decode(" in low:
        out = _char_codes(out)
    if "-f" in low and "{0}" in text:
        out = _format_operator(out)
    if "`" in text:
        out = re.sub(r"(?<=\w)`(?=\w)", "", out)
    if "%" in text and re.search(r"(?im)^\s*set\s", text):
        out = _batch(out)
    extra = [x for x in (unpack_packer(text), *_decoded_payloads(text)) if x]
    return out + ("\n" + "\n".join(extra) if extra else "")
