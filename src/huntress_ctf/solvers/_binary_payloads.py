"""Public packed/resource overlay schemas; no executable code is loaded.

The caller selects a schema from issued instructions, never from the day or an
answer ID. A damaged final record cannot fall back to an earlier magic string.
"""
from dataclasses import dataclass
import hashlib

from ._binary_formats import ParseError, Reader

MAX_PAYLOAD = 16 * 1024 * 1024


@dataclass(frozen=True)
class Overlay:
    offset: int
    payload: bytes
    resource_size: int


def read_overlay(data: bytes, magic: bytes) -> Overlay:
    if magic not in (b"PK19", b"RS20"):
        raise ParseError("Unsupported public overlay schema")
    offset = data.rfind(magic)
    if offset < 0:
        raise ParseError("Missing final overlay magic")
    reader = Reader(data)
    header_size = 44 if magic == b"PK19" else 48
    reader.take(offset, header_size)
    size, = reader.unpack("I", offset + 8)
    if size > MAX_PAYLOAD:
        raise ParseError("Overlay payload exceeds bound")
    payload = reader.take(offset + header_size, size)
    if magic == b"PK19":
        if offset + header_size + size != len(data):
            raise ParseError("Packed overlay does not end at EOF")
        k1, k2 = data[offset + 5:offset + 7]
        decoded = bytearray(size)
        for index, value in enumerate(payload):
            value ^= k2
            decoded[index] = ((value >> 3) | ((value << 5) & 255)) ^ k1
        payload = bytes(decoded)
        if hashlib.sha256(payload).digest() != reader.take(offset + 12, 32):
            raise ParseError("Unpacked overlay SHA-256 mismatch")
    else:
        scratch_size, = reader.unpack("H", offset + 12)
        end = offset + header_size + size
        if end + scratch_size != len(data):
            raise ParseError("Resource overlay does not end at EOF")
        scratch = reader.take(end, scratch_size)
        if hashlib.sha256(scratch).digest() != reader.take(offset + 16, 32):
            raise ParseError("Resource scratch SHA-256 mismatch")
    return Overlay(offset, payload, size)
