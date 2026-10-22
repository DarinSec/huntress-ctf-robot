"""Optional WinZip AE-1/AE-2 reader. Authenticate before bounded decompression.

Only stored/deflated members are supported. No extraction or sample execution.
The external archive reader remains the primary backend.
"""
import hashlib
import hmac
import struct
import zipfile
import zlib
from io import BytesIO

from ..containers import winzip_counter_blocks
from ._binary_formats import ParseError

CHUNK = 64 * 1024


def _aes_extra(extra):
    found, at = [], 0
    while at < len(extra):
        if at + 4 > len(extra):
            raise ParseError("Truncated ZIP extra header")
        kind, size = struct.unpack_from("<HH", extra, at)
        at += 4
        if at + size > len(extra):
            raise ParseError("Truncated ZIP extra field")
        if kind == 0x9901:
            if size != 7:
                raise ParseError("Invalid AES extra length")
            version, vendor, strength, method = struct.unpack_from("<H2sBH", extra, at)
            if version not in (1, 2) or vendor != b"AE" or strength not in (1, 2, 3) or method not in (0, 8):
                raise ParseError("Unsupported WinZip AES parameters")
            found.append((version, strength, method))
        at += size
    if len(found) != 1:
        raise ParseError("No unique AES extra field")
    return found[0]


def aes_member(blob, info, password, limit, cipher_types=None):
    """Return one authenticated member or fail closed; never return partial bytes."""
    if cipher_types is None:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    else:
        Cipher, algorithms, modes = cipher_types
    if info.file_size < 0 or info.file_size > limit or info.compress_size > limit + max(65536, limit // 1000) or info.compress_type != 99 or not info.flag_bits & 1:
        raise ParseError("Invalid AES member size/method/flags")
    version, strength, method = _aes_extra(info.extra)
    start = info.header_offset
    if start < 0 or start + 30 > len(blob):
        raise ParseError("Truncated ZIP local header")
    signature, _, flags, compression, _, _, crc, compressed, size, namesize, extrasize = struct.unpack_from("<4s5H3I2H", blob, start)
    if signature != b"PK\x03\x04" or compression != 99 or flags != info.flag_bits or flags & 0x40:
        raise ParseError("Inconsistent AES local header")
    body = start + 30 + namesize + extrasize
    if body > len(blob) or info.compress_size < 0 or body + info.compress_size > len(blob):
        raise ParseError("Truncated AES body")
    local_name = blob[start + 30:start + 30 + namesize].decode("utf-8" if flags & 0x800 else "cp437")
    if local_name != info.orig_filename or _aes_extra(blob[body - extrasize:body]) != (version, strength, method):
        raise ParseError("AES local/central metadata disagree")
    if not flags & 8 and ((compressed not in (info.compress_size, 0xffffffff)) or (size not in (info.file_size, 0xffffffff)) or crc != info.CRC):
        raise ParseError("AES local sizes/CRC disagree")
    if version == 2 and info.CRC != 0:
        raise ParseError("AE-2 must omit CRC")
    keysize = {1: 16, 2: 24, 3: 32}[strength]
    saltsize = keysize // 2
    if info.compress_size < saltsize + 12:
        raise ParseError("Truncated AES salt/verifier/tag")
    salt = blob[body:body + saltsize]
    material = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), salt, 1000, 2 * keysize + 2)
    if not hmac.compare_digest(material[-2:], blob[body + saltsize:body + saltsize + 2]):
        raise ParseError("AES password verification failed")
    encrypted = memoryview(blob)[body + saltsize + 2:body + info.compress_size - 10]
    tag = blob[body + info.compress_size - 10:body + info.compress_size]
    if not hmac.compare_digest(hmac.new(material[keysize:2 * keysize], encrypted, "sha1").digest()[:10], tag):
        raise ParseError("AES authentication failed")
    # Bound compressed input as well as output; reject overlap with another entry
    # or the central directory, even if a malicious directory claims a huge body.
    with zipfile.ZipFile(BytesIO(blob)) as archive:
        following = [x.header_offset for x in archive.infolist() if x.header_offset > start]
        end = min([archive.start_dir, *following])
    if body + info.compress_size > end:
        raise ParseError("Overlapping AES member")
    encryptor = Cipher(algorithms.AES(material[:keysize]), modes.ECB()).encryptor()
    decompressor = zlib.decompressobj(-15) if method == 8 else None
    output, counter = bytearray(), 1
    try:
        for at in range(0, len(encrypted), CHUNK):
            chunk = encrypted[at:at + CHUNK]
            blocks = (len(chunk) + 15) // 16
            counters = winzip_counter_blocks(counter, blocks)
            stream = encryptor.update(counters)[:len(chunk)]
            counter += blocks
            plain = (int.from_bytes(chunk, "little") ^ int.from_bytes(stream, "little")).to_bytes(len(chunk), "little")
            if decompressor:
                plain = decompressor.decompress(plain, info.file_size - len(output) + 1)
                if decompressor.unconsumed_tail or decompressor.unused_data:
                    raise ParseError("AES deflate exceeds declared size or has trailing bytes")
            output.extend(plain)
            if len(output) > min(limit, info.file_size):
                raise ParseError("AES decompression exceeds bound")
        encryptor.finalize()
    except zlib.error as error:
        raise ParseError("Invalid AES deflate stream") from error
    if decompressor and not decompressor.eof:
        raise ParseError("Truncated AES deflate stream")
    if len(output) != info.file_size or version == 1 and zlib.crc32(output) != info.CRC:
        raise ParseError("AES member failed size/CRC check")
    return bytes(output)


def aes_members(blob, infos, passwords, member_limit, total_limit, selected):
    """Lazy optional fallback; unsupported input or missing dependency stays unknown."""
    if len(infos) > 1000 or sum(x.file_size for x in infos) > total_limit:
        return {}
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        return {}
    result = {}
    for index in sorted(selected):
        info = infos[index]
        for password in dict.fromkeys(passwords):
            try:
                result[index] = aes_member(blob, info, password, member_limit, (Cipher, algorithms, modes))
                break
            except (ParseError, UnicodeError, ValueError, zipfile.BadZipFile, struct.error):
                continue
    return result
