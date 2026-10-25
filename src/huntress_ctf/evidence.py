"""Fast, stdlib-only fact extraction: metadata fields, IOCs, and decoded script blobs.

Used by the triage report (for the AI) and by FactSolver (for answers). Everything here
parses bytes; nothing is executed. Values keep their order and are de-duplicated.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from html import unescape
from io import BytesIO
import re
import struct
import zipfile
import zlib

from .containers import ZIP_ERRORS, Member

MAX_STREAMS = 200
MAX_STREAM_BYTES = 4 * 1024 * 1024
MAX_BLOBS = 50
MAX_TEXT_SCAN = 8 * 1024 * 1024


@dataclass
class Facts:
    metadata: dict[str, list[str]] = field(default_factory=dict)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    blobs: list[tuple[str, str]] = field(default_factory=list)


def _add(target: dict[str, list[str]], key: str, value: str) -> None:
    value = value.replace("\x00", "").strip()
    if value and value not in target.setdefault(key, []):
        target[key].append(value)


# --- Metadata -------------------------------------------------------------------

_TIFF_TAGS = {
    0x010E: "ImageDescription", 0x010F: "Make", 0x0110: "Model", 0x0131: "Software",
    0x0132: "DateTime", 0x013B: "Artist", 0x8298: "Copyright",
    0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized", 0x9286: "UserComment",
    0xA430: "CameraOwnerName", 0xA431: "BodySerialNumber", 0xA434: "LensModel",
    0x9C9B: "XPTitle", 0x9C9C: "XPComment", 0x9C9D: "XPAuthor",
    0x9C9E: "XPKeywords", 0x9C9F: "XPSubject",
}
_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


def _tiff(data: bytes, out: dict[str, list[str]], prefix: str = "EXIF") -> None:
    if len(data) < 8 or data[:2] not in (b"II", b"MM"):
        return
    order = "<" if data[:2] == b"II" else ">"
    if struct.unpack(order + "H", data[2:4])[0] != 42:
        return

    def entries(offset: int):
        if offset + 2 > len(data):
            return
        count = struct.unpack(order + "H", data[offset:offset + 2])[0]
        for index in range(min(count, 512)):
            start = offset + 2 + index * 12
            if start + 12 > len(data):
                return
            tag, kind, number = struct.unpack(order + "HHI", data[start:start + 8])
            size = _TYPE_SIZES.get(kind, 0) * number
            if not size:
                continue
            if size <= 4:
                raw = data[start + 8:start + 8 + size]
            else:
                pointer = struct.unpack(order + "I", data[start + 8:start + 12])[0]
                raw = data[pointer:pointer + size]
                if len(raw) < size:
                    continue
            yield tag, kind, number, raw, data[start + 8:start + 12]

    def rationals(raw: bytes, number: int) -> list[float]:
        values = struct.unpack(order + "I" * (2 * number), raw[:8 * number])
        return [n / d if d else 0.0 for n, d in zip(values[::2], values[1::2])]

    def ifd(offset: int, gps: bool = False) -> None:
        position: dict[str, object] = {}
        for tag, kind, number, raw, inline in entries(offset):
            if not gps and tag in (0x8769, 0x8825):
                child = struct.unpack(order + "I", inline)[0]
                if 0 < child < len(data) and child != offset:
                    ifd(child, gps=tag == 0x8825)
                continue
            if gps:
                if tag in (1, 3) and kind == 2:
                    position[f"ref{tag}"] = raw.rstrip(b"\x00").decode("ascii", "replace")
                elif tag in (2, 4) and kind == 5 and number == 3:
                    degrees, minutes, seconds = rationals(raw, 3)
                    position[f"val{tag}"] = degrees + minutes / 60 + seconds / 3600
                continue
            name = _TIFF_TAGS.get(tag)
            if name is None:
                continue
            if name.startswith("XP"):
                value = raw.decode("utf-16-le", "replace")
            elif name == "UserComment":
                value = raw[8:].decode("utf-16-le" if raw[:8].startswith(b"UNICODE") else "latin-1", "replace")
            elif kind == 2:
                value = raw.rstrip(b"\x00").decode("utf-8", "replace")
            else:
                continue
            _add(out, f"{prefix}:{name}", value)
        if gps and "val2" in position and "val4" in position:
            latitude = position["val2"] * (-1 if position.get("ref1") == "S" else 1)
            longitude = position["val4"] * (-1 if position.get("ref3") == "W" else 1)
            _add(out, "GPS:Latitude", f"{latitude:.6f}")
            _add(out, "GPS:Longitude", f"{longitude:.6f}")
            _add(out, "GPS:Position", f"{latitude:.6f}, {longitude:.6f}")

    try:
        ifd(struct.unpack(order + "I", data[4:8])[0])
    except struct.error:
        return


def _jpeg(data: bytes, out: dict[str, list[str]]) -> None:
    offset = 2
    while offset + 4 <= len(data) and data[offset] == 0xFF:
        marker = data[offset + 1]
        if marker in (0xD9, 0xDA):
            break
        length = struct.unpack(">H", data[offset + 2:offset + 4])[0]
        segment = data[offset + 4:offset + 2 + length]
        if marker == 0xE1 and segment.startswith(b"Exif\x00\x00"):
            _tiff(segment[6:], out)
        elif marker == 0xFE:
            _add(out, "JPEG:Comment", segment.decode("utf-8", "replace"))
        offset += 2 + length


def _png(data: bytes, out: dict[str, list[str]]) -> None:
    offset = 8
    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        kind = data[offset + 4:offset + 8]
        chunk = data[offset + 8:offset + 8 + length]
        offset += 12 + length
        try:
            if kind == b"tEXt" and b"\x00" in chunk:
                key, value = chunk.split(b"\x00", 1)
                _add(out, f"PNG:{key.decode('latin-1')}", value.decode("latin-1"))
            elif kind == b"zTXt" and b"\x00" in chunk:
                key, rest = chunk.split(b"\x00", 1)
                _add(out, f"PNG:{key.decode('latin-1')}",
                     _inflate(rest[1:], zlib.MAX_WBITS).decode("latin-1"))
            elif kind == b"iTXt" and b"\x00" in chunk:
                key, rest = chunk.split(b"\x00", 1)
                compressed, rest = rest[0], rest[2:]
                _language, _translated, text = rest.split(b"\x00", 2)
                if compressed:
                    text = _inflate(text, zlib.MAX_WBITS)
                _add(out, f"PNG:{key.decode('latin-1')}", text.decode("utf-8", "replace"))
            elif kind == b"eXIf":
                _tiff(chunk, out)
            elif kind == b"IEND":
                break
        except (ValueError, zlib.error):
            continue


_PDF_KEYS = rb"Title|Author|Subject|Keywords|Creator|Producer|CreationDate|ModDate|Company|SourceModified"
_PDF_ENTRY = re.compile(rb"/(" + _PDF_KEYS + rb")\s*(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]*>)", re.S)
_PDF_STREAM = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.S)
_PDF_ESCAPES = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f"}


def _pdf_string(token: bytes) -> str:
    if token.startswith(b"<"):
        try:
            raw = binascii.unhexlify(re.sub(rb"\s", b"", token[1:-1]))
        except binascii.Error:
            return ""
    else:
        raw = re.sub(
            rb"\\([0-7]{1,3}|.)",
            lambda m: bytes([int(m.group(1), 8) & 0xFF]) if m.group(1)[:1].isdigit()
            else _PDF_ESCAPES.get(m.group(1), m.group(1)),
            token[1:-1], flags=re.S,
        )
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", "replace")
    return raw.decode("utf-8", "replace") if raw.isascii() else raw.decode("latin-1")


def _pdf(data: bytes, out: dict[str, list[str]]) -> None:
    sources = [data]
    for match in list(_PDF_STREAM.finditer(data))[:MAX_STREAMS]:
        try:
            sources.append(_inflate(match.group(1), zlib.MAX_WBITS))
        except zlib.error:
            continue
    for source in sources:
        for key, token in _PDF_ENTRY.findall(source):
            _add(out, f"PDF:{key.decode()}", _pdf_string(token))
        _xmp(source, out)


_XMP_ELEMENT = re.compile(
    r"<((?:dc|xmp|pdf|photoshop|xmpMM|exif|tiff|xmpRights):[A-Za-z]+)\b[^>]*>(.*?)</\1>", re.S,
)
_XMP_ATTRIBUTE = re.compile(r"\b((?:dc|xmp|pdf|photoshop|xmpMM|exif|tiff):[A-Za-z]+)=\"([^\"]*)\"")


def _xmp(data: bytes, out: dict[str, list[str]]) -> None:
    start = data.find(b"<x:xmpmeta")
    while start != -1:
        end = data.find(b"</x:xmpmeta>", start)
        if end == -1:
            break
        packet = data[start:end].decode("utf-8", "replace")
        for key, value in _XMP_ATTRIBUTE.findall(packet):
            _add(out, f"XMP:{key}", unescape(value))
        for key, inner in _XMP_ELEMENT.findall(packet):
            items = re.findall(r"<rdf:li\b[^>]*>(.*?)</rdf:li>", inner, re.S) or [inner]
            for item in items:
                _add(out, f"XMP:{key}", unescape(re.sub(r"<[^>]+>", "", item)))
        start = data.find(b"<x:xmpmeta", end)


_OFFICE_ELEMENT = re.compile(r"<(?:[A-Za-z]+:)?([A-Za-z]+)\b[^>/]*>([^<]*)</(?:[A-Za-z]+:)?\1>")
_OFFICE_CUSTOM = re.compile(r"<property\b[^>]*\bname=\"([^\"]+)\"[^>]*>\s*<vt:[a-z0-9]+>([^<]*)</vt:", re.S)


def _office_and_zip(data: bytes, out: dict[str, list[str]]) -> None:
    try:
        archive = zipfile.ZipFile(BytesIO(data))
    except ZIP_ERRORS:
        return
    with archive:
        if archive.comment:
            _add(out, "ZIP:comment", archive.comment.decode("utf-8", "replace"))
        for info in archive.infolist()[:50]:
            _add(out, f"ZIP:modified:{info.filename}", "%04d-%02d-%02d %02d:%02d:%02d" % info.date_time)
        for name, prefix in (("docProps/core.xml", "Office"), ("docProps/app.xml", "Office"),
                             ("docProps/custom.xml", "Office:custom")):
            try:
                if archive.getinfo(name).flag_bits & 0x1:
                    continue
                with archive.open(name) as stream:  # Only the part that is used is inflated.
                    xml = stream.read(MAX_STREAM_BYTES).decode("utf-8", "replace")
            except (KeyError, *ZIP_ERRORS):
                continue
            pattern = _OFFICE_CUSTOM if prefix == "Office:custom" else _OFFICE_ELEMENT
            for key, value in pattern.findall(xml):
                _add(out, f"{prefix}:{key}", unescape(value))


def metadata(data: bytes) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    if data.startswith(b"\xff\xd8\xff"):
        _jpeg(data, out)
        _xmp(data, out)
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        _png(data, out)
        _xmp(data, out)
    elif data.startswith(b"%PDF-"):
        _pdf(data, out)
    elif data.startswith(b"PK\x03\x04"):
        _office_and_zip(data, out)
    elif data[:4] in (b"II*\x00", b"MM\x00*"):
        _tiff(data, out, "TIFF")
    return out


# --- IOCs -----------------------------------------------------------------------

_TLDS = (
    "com|net|org|info|biz|io|co|me|xyz|top|site|online|club|ru|cn|de|uk|fr|nl|su|in|br|jp|"
    "kr|us|eu|tk|ml|ga|cf|gq|pw|cc|ws|ly|app|dev|cloud|live|link|click|shop|store|tech|"
    "space|website|onion|gov|edu|mil|int|ca|au|it|es|se|no|fi|dk|pl|ch|at|be|cz|ua|ir|tv"
)
IOC_PATTERNS = {
    "url": re.compile(r"\b(?:https?|hxxps?|ftp)://[^\s\"'<>()\[\]{}`]+", re.I),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "domain": re.compile(
        # Not followed by ".Word" or a call: keeps System.Net.WebClient and [System.IO.File] out.
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + _TLDS + r")\b(?!\.\w)(?![.\w-]*\()", re.I),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"),
    "sha256": re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])"),
    "sha1": re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])"),
    "md5": re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])"),
    "registry": re.compile(
        r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)(?::)?\\[^\s\"'`;|,)]+", re.I),
    "path": re.compile(
        r"(?:\b[A-Za-z]:\\|%[A-Za-z_]+%\\|\\\\[\w.$-]+\\)[^\s\"'`<>|*?;,]+"),
}
_TRAILING = ".,;:!?)]}>'\""


def iocs(text: str, kinds: frozenset[str] | set[str] | None = None) -> dict[str, list[str]]:
    """All IOC kinds, or only `kinds`: each pattern is a full pass over the text."""
    out: dict[str, list[str]] = {}
    text = text[:MAX_TEXT_SCAN]
    for kind, pattern in IOC_PATTERNS.items():
        if kinds is not None and kind not in kinds:
            continue
        for match in pattern.finditer(text):
            value = match.group().rstrip(_TRAILING)
            if kind == "domain" and re.fullmatch(r"[\d.]+", value):
                continue
            _add(out, kind, value)
    return out


# --- Script blobs ---------------------------------------------------------------

_ENCODED_COMMAND = re.compile(r"-e(?:nc(?:odedcommand)?|c)?\s+[\"']?([A-Za-z0-9+/]{16,}={0,2})", re.I)
_FROM_BASE64 = re.compile(r"FromBase64String\(\s*[\"']([A-Za-z0-9+/=\s]{8,})[\"']", re.I)
_LONG_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])")
_CHAR_RUN = re.compile(r"(?:\[char\]\s*\(?\s*\d{1,3}\s*\)?\s*[+,]?\s*){4,}", re.I)


def _printable(text: str) -> bool:
    return bool(text) and sum(ch.isprintable() or ch in "\r\n\t" for ch in text) >= 0.95 * len(text)


def _inflate(raw: bytes, wbits: int) -> bytes:
    # Bounded: a tiny compressed blob must not expand into gigabytes.
    return zlib.decompressobj(wbits).decompress(raw, MAX_STREAM_BYTES)


def _decode_bytes(raw: bytes) -> str | None:
    for opener in (lambda b: b, lambda b: _inflate(b, 16 + zlib.MAX_WBITS),
                   lambda b: _inflate(b, -15), lambda b: _inflate(b, zlib.MAX_WBITS)):
        try:
            data = opener(raw)
        except zlib.error:
            continue
        if not data:
            continue
        for encoding in ("utf-8", "utf-16-le"):
            try:
                text = data.decode(encoding)
            except UnicodeDecodeError:
                continue
            if _printable(text):
                return text
    return None


def decoded_blobs(text: str, depth: int = 3) -> list[tuple[str, str]]:
    """Decode PowerShell -EncodedCommand, FromBase64String, long Base64, and [char] runs."""
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    def visit(source: str, level: int) -> None:
        candidates: list[tuple[str, bytes | str]] = []
        lowered = source.lower()
        for label, pattern in (("encoded-command", _ENCODED_COMMAND), ("from-base64", _FROM_BASE64),
                               ("base64", _LONG_BASE64)):
            if label == "from-base64" and "frombase64string" not in lowered:
                continue  # The pattern needs this literal; skipping saves a full pass.
            for match in pattern.finditer(source):
                token = re.sub(r"\s", "", match.group(1) if pattern.groups else match.group())
                try:
                    candidates.append((label, base64.b64decode(token + "=" * (-len(token) % 4))))
                except (binascii.Error, ValueError):
                    continue
        for match in (_CHAR_RUN.finditer(source) if "[char]" in lowered else ()):
            codes = [int(code) for code in re.findall(r"\d{1,3}", match.group())]
            if all(code < 0x110000 for code in codes):
                candidates.append(("char-codes", "".join(map(chr, codes))))
        for label, value in candidates:
            if len(found) >= MAX_BLOBS:
                return
            decoded = value if isinstance(value, str) else _decode_bytes(value)
            if decoded and decoded not in seen:
                seen.add(decoded)
                found.append((label, decoded))
                if level > 1:
                    visit(decoded, level - 1)

    visit(text[:MAX_TEXT_SCAN], depth)
    return found


# --- Collection -----------------------------------------------------------------

# Same matches as (?:[\x20-\x7e]\x00){5,}, about four times faster: the five required
# characters are unrolled, then a greedy tail. (No possessive `*+`: that needs 3.11.)
_WIDE_STRING = re.compile(rb"[\x20-\x7e]\x00[\x20-\x7e]\x00[\x20-\x7e]\x00[\x20-\x7e]\x00[\x20-\x7e]\x00(?:[\x20-\x7e]\x00)*")
_ASCII_STRING = re.compile(rb"[\x20-\x7e\t]{5,}")


def texts_of(data: bytes) -> list[str]:
    """Readable text views of bytes: UTF-8/UTF-16 text, or ASCII and UTF-16LE strings."""
    for bom, encoding in ((b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16")):
        if data.startswith(bom):
            return [data.decode(encoding, "replace")]
    try:
        text = data.decode("utf-8")
        if text.count("\x00") <= len(text) // 4:
            return [text]
        return [data.decode("utf-16-le", "replace")]
    except UnicodeDecodeError:
        pass
    ascii_strings = _ASCII_STRING.findall(data, 0, MAX_TEXT_SCAN)
    wide_strings = _WIDE_STRING.findall(data, 0, MAX_TEXT_SCAN)
    return [
        "\n".join(item.decode("ascii") for item in ascii_strings),
        "\n".join(item.decode("utf-16-le") for item in wide_strings),
    ]


def collect(
    artifact: bytes, members: tuple[Member, ...] = (), *,
    ioc_kinds: frozenset[str] | set[str] | None = None,
    want_metadata: bool = True, want_blobs: bool = True,
) -> Facts:
    """Everything by default (triage). A solver on the clock asks only for what it needs:
    `ioc_kinds` limits the IOC patterns (empty means none), and metadata or blob
    decoding can be skipped."""
    facts = Facts()
    scan_iocs = ioc_kinds is None or bool(ioc_kinds)
    for name, data in (("", artifact), *((member.name, member.data) for member in members)):
        if want_metadata:
            for key, values in metadata(data).items():
                for value in values:
                    _add(facts.metadata, f"{name}:{key}" if name else key, value)
        if not (scan_iocs or want_blobs):
            continue
        for text in texts_of(data):
            blobs = decoded_blobs(text) if want_blobs else []
            facts.blobs.extend((f"{name}:{label}" if name else label, value) for label, value in blobs)
            if not scan_iocs:
                continue
            for scanned in (text, *(value for _, value in blobs)):
                for kind, values in iocs(scanned, ioc_kinds).items():
                    for value in values:
                        _add(facts.iocs, kind, value)
    return facts
