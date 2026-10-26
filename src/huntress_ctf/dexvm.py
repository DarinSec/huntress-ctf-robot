"""A small Dalvik bytecode emulator for computed answer codes (Mobile Android, Day 23 on).

Day 23's assets/huntress_puzzle.json only says {"codec": "analysis"}: the answer code is
computed by Java, `Release.code(Context)` = a chain of 64-bit mix functions over `token()`,
formatted as "ANS-" + 16 hex digits. A JNI `static native long f(long)` (Day 15's libarena.so)
may sit in the chain.

The app is never run. This module parses classes*.dex and interprets the bytecode of the
methods that chain reaches, with exact Java int/long semantics, in pure Python. Calls into
the platform are allowed only for a short list of pure library methods (StringBuilder,
String, Long/Integer, Math, Character, CRC32, MessageDigest, Base64), Context's package
name and the APK's own assets/ members (read from the bytes in memory; Day 20 loads a second
DEX from there with InMemoryDexClassLoader, and its classes are interpreted like the app's);
anything else (files, network, platform reflection, clocks, threads) stops the run with
`Unsupported`, so an answer is either computed exactly or not at all. A native method is evaluated by a
register-only x86-64 subset read from the APK's lib/x86_64 ELF (mov/add/sub/xor/and/or,
imul, rotates and shifts, not/neg, bswap), again without executing anything.
"""

from __future__ import annotations

import base64
import hashlib
from io import BytesIO
import math
import re
import struct
from typing import Any
import zipfile
import zlib

from .containers import ZIP_ERRORS, read_member

ANSWER = re.compile(r"ANS-[0-9A-F]{16}")
# An answer-code method is short: day 24's apps run ~55k steps (63 ms) at ~0.9M steps/s.
# A runaway or adversarial method that only hits the cap wins nothing anyway (the question
# then falls back to the literal scan), and the old 20M cap let it mill for ~23 s first --
# two such apps in a Mastery made its timed race 52 s and unresolved. 3M keeps ~55x headroom
# over a real app and fails a runaway in ~3.4 s instead.
MAX_STEPS = 3_000_000
# Day 20's payload.dex is ~700 bytes; an asset past this is not an answer-code module.
MAX_ASSET_BYTES = 16 << 20
M32, M64 = 0xFFFFFFFF, (1 << 64) - 1
ACC_STATIC, ACC_NATIVE = 0x8, 0x100


class Unsupported(Exception):
    """The code does something this emulator will not model; no answer is produced."""


def s32(value: int) -> int:
    value &= M32
    return value - (1 << 32) if value >> 31 else value


def s64(value: int) -> int:
    value &= M64
    return value - (1 << 64) if value >> 63 else value


def _uleb(data: bytes, at: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        byte = data[at]
        at += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, at
        shift += 7


def _mutf8(raw: bytes) -> str:
    text = raw.replace(b"\xc0\x80", b"\0").decode("utf-8", "surrogatepass")
    return text.encode("utf-16", "surrogatepass").decode("utf-16")


# --- DEX structure ------------------------------------------------------------------------------

class Method:
    def __init__(self, cls: str, name: str, params: list[str], ret: str, flags: int,
                 registers: int = 0, ins: int = 0, insns: tuple[int, ...] = ()) -> None:
        self.cls, self.name, self.params, self.ret, self.flags = cls, name, params, ret, flags
        self.registers, self.ins, self.insns = registers, ins, insns

    @property
    def signature(self) -> str:
        return f"({''.join(self.params)}){self.ret}"


class ClassDef:
    def __init__(self, name: str, superclass: str | None) -> None:
        self.name, self.superclass = name, superclass
        self.methods: dict[tuple[str, str], Method] = {}
        self.static_defaults: dict[str, Any] = {}
        self.instance_fields: list[tuple[str, str]] = []


class Dex:
    def __init__(self, data: bytes) -> None:
        if not data.startswith(b"dex\n"):
            raise Unsupported("not a DEX file")
        self.data = data
        (strings, strings_at, types, types_at, protos, protos_at, fields, fields_at,
         methods, methods_at, classes, classes_at) = struct.unpack_from("<12I", data, 0x38)
        self.strings = []
        for index in range(strings):
            at = struct.unpack_from("<I", data, strings_at + 4 * index)[0]
            _, at = _uleb(data, at)
            self.strings.append(_mutf8(data[at:data.index(b"\0", at)]))
        self.types = [self.strings[struct.unpack_from("<I", data, types_at + 4 * i)[0]] for i in range(types)]
        self.protos = []
        for index in range(protos):
            _, ret, params_at = struct.unpack_from("<III", data, protos_at + 12 * index)
            self.protos.append((self.types[ret], self._type_list(params_at)))
        self.fields = []
        for index in range(fields):
            cls, kind, name = struct.unpack_from("<HHI", data, fields_at + 8 * index)
            self.fields.append((self.types[cls], self.types[kind], self.strings[name]))
        self.methods = []
        for index in range(methods):
            cls, proto, name = struct.unpack_from("<HHI", data, methods_at + 8 * index)
            ret, params = self.protos[proto]
            self.methods.append((self.types[cls], self.strings[name], params, ret))
        self.classes: dict[str, ClassDef] = {}
        for index in range(classes):
            cls, _, superclass, _, _, _, data_at, values_at = struct.unpack_from("<8I", data, classes_at + 32 * index)
            definition = ClassDef(self.types[cls], self.types[superclass] if superclass != 0xFFFFFFFF else None)
            if data_at:
                self._class_data(definition, data_at)
            if values_at:
                statics = [name for name in definition.static_defaults]
                for name, value in zip(statics, self._encoded_array(values_at)):
                    definition.static_defaults[name] = value
            self.classes[definition.name] = definition

    def _type_list(self, at: int) -> list[str]:
        if not at:
            return []
        count = struct.unpack_from("<I", self.data, at)[0]
        return [self.types[struct.unpack_from("<H", self.data, at + 4 + 2 * i)[0]] for i in range(count)]

    def _class_data(self, definition: ClassDef, at: int) -> None:
        data = self.data
        statics, at = _uleb(data, at)
        instances, at = _uleb(data, at)
        directs, at = _uleb(data, at)
        virtuals, at = _uleb(data, at)
        index = 0
        for _ in range(statics):
            diff, at = _uleb(data, at)
            _, at = _uleb(data, at)
            index += diff
            _, kind, name = self.fields[index]
            definition.static_defaults[name] = _default(kind)
        index = 0
        for _ in range(instances):
            diff, at = _uleb(data, at)
            _, at = _uleb(data, at)
            index += diff
            _, kind, name = self.fields[index]
            definition.instance_fields.append((name, kind))
        for count in (directs, virtuals):
            index = 0
            for _ in range(count):
                diff, at = _uleb(data, at)
                flags, at = _uleb(data, at)
                code_at, at = _uleb(data, at)
                index += diff
                cls, name, params, ret = self.methods[index]
                method = Method(cls, name, params, ret, flags)
                if code_at:
                    registers, ins, _, _, _, size = struct.unpack_from("<HHHHII", data, code_at)
                    method.registers, method.ins = registers, ins
                    method.insns = struct.unpack_from(f"<{size}H", data, code_at + 16)
                definition.methods[(name, method.signature)] = method

    def _encoded_array(self, at: int) -> list[Any]:
        size, at = _uleb(self.data, at)
        values = []
        for _ in range(size):
            value, at = self._encoded_value(at)
            values.append(value)
        return values

    def _encoded_value(self, at: int) -> tuple[Any, int]:
        head = self.data[at]
        kind, arg = head & 0x1F, head >> 5
        at += 1
        if kind == 0x1E:
            return None, at
        if kind == 0x1F:
            return bool(arg), at
        if kind == 0x1C:
            size, at = _uleb(self.data, at)
            items = []
            for _ in range(size):
                item, at = self._encoded_value(at)
                items.append(item)
            return items, at
        raw = self.data[at:at + arg + 1]
        at += arg + 1
        if kind in (0x00, 0x02, 0x04, 0x06):  # byte, short, int, long: sign-extended
            value = int.from_bytes(raw, "little", signed=True)
            return (s64(value) if kind == 0x06 else s32(value)), at
        if kind == 0x03:
            return int.from_bytes(raw, "little"), at
        if kind == 0x10:
            return struct.unpack("<f", raw.ljust(4, b"\0")[-4:] if len(raw) < 4 else raw)[0], at
        if kind == 0x11:
            return struct.unpack("<d", raw.rjust(8, b"\0"))[0], at
        if kind == 0x17:
            return self.strings[int.from_bytes(raw, "little")], at
        if kind == 0x18:
            return JClass(self.types[int.from_bytes(raw, "little")]), at
        raise Unsupported(f"encoded value 0x{kind:02x}")


def _default(kind: str) -> Any:
    return 0 if kind in ("I", "J", "S", "B", "C") else False if kind == "Z" else 0.0 if kind in ("F", "D") else None


# --- Runtime objects ----------------------------------------------------------------------------

class JObject:
    def __init__(self, cls: str) -> None:
        self.cls = cls
        self.fields: dict[str, Any] = {}


class JClass:
    def __init__(self, name: str) -> None:
        self.name = name


class Builder:
    """java.lang.StringBuilder / StringBuffer."""

    def __init__(self) -> None:
        self.parts: list[str] = []


class Pending:
    """`new String`/`new Long` before its <init>; the constructor replaces it in the registers."""

    def __init__(self, cls: str) -> None:
        self.cls = cls


class Digest:
    def __init__(self, algorithm: str) -> None:
        names = {"MD5": "md5", "SHA-1": "sha1", "SHA1": "sha1", "SHA-256": "sha256", "SHA256": "sha256",
                 "SHA-512": "sha512", "SHA-384": "sha384"}
        if algorithm.upper() not in names:
            raise Unsupported(f"MessageDigest {algorithm}")
        self.hash = hashlib.new(names[algorithm.upper()])


class Crc:
    def __init__(self) -> None:
        self.value = 0


class Context:
    """getPackageName() and getAssets(); Day 23 only stores the argument. Assets are the APK's own
    assets/ members, read from the bytes in memory (Day 20 ships its second DEX there)."""

    def __init__(self, package: str | None, apk: bytes | None = None) -> None:
        self.package = package
        self.apk = apk

    def asset(self, name: str) -> bytes:
        if self.apk is None:
            raise Unsupported("Context.getAssets() without the APK")
        try:
            with zipfile.ZipFile(BytesIO(self.apk)) as apk:
                return read_member(apk, "assets/" + name.lstrip("/"), MAX_ASSET_BYTES)
        except KeyError:
            raise Unsupported(f"no asset {name}") from None
        except ZIP_ERRORS as error:  # Past the cap (TooLarge) or damaged: no data, never a crash.
            raise Unsupported(f"asset {name}: {error}") from None


class Assets:
    """android.content.res.AssetManager of a Context."""

    def __init__(self, context: Context) -> None:
        self.context = context


class Stream:
    """An InputStream over bytes in memory (AssetManager.open)."""

    def __init__(self, data: bytes) -> None:
        self.data, self.at = data, 0


class Sink:
    """java.io.ByteArrayOutputStream."""

    def __init__(self) -> None:
        self.data = bytearray()


class Buffer:
    """java.nio.ByteBuffer.wrap(byte[]); only ever handed to a class loader."""

    def __init__(self, data: bytes) -> None:
        self.data = data


class Loader:
    """The app's class loader (Class.getClassLoader) or an InMemoryDexClassLoader over DEX bytes the
    app read itself. Its classes are parsed like classes.dex and interpreted, never run."""

    def __init__(self) -> None:
        self.dexes: list[Dex] = []


# --- Platform APIs a later day may reach (none of days 1-25 did) ---------------------------------
# Charsets, javax.crypto with a key the app holds, BigInteger, and the app's own package: its
# PackageInfo (manifest version, v1 signing certificate) and its APK as a ZipFile. Each value
# is computed from the APK bytes in memory; what depends on the device stays Unsupported.


class Charset:
    """java.nio.charset.Charset: StandardCharsets.UTF_8, Charset.forName("US-ASCII"), ..."""

    CODECS = {"UTF-8": "utf-8", "UTF8": "utf-8", "US-ASCII": "ascii", "ASCII": "ascii", "ISO-8859-1": "latin-1",
              "LATIN1": "latin-1", "UTF-16": "utf-16", "UTF-16BE": "utf-16-be", "UTF-16LE": "utf-16-le"}

    def __init__(self, name: str) -> None:
        if not isinstance(name, str) or name.upper() not in self.CODECS:
            raise Unsupported(f"charset {name}")
        self.name, self.codec = name, self.CODECS[name.upper()]


def _codec(charset: Any) -> str:
    return "utf-8" if charset is None else (charset if isinstance(charset, Charset) else Charset(charset)).codec


def _encode(text: str, charset: Any) -> bytes:
    codec = _codec(charset)
    if codec == "utf-16":  # Java writes a big-endian byte-order mark.
        return b"\xfe\xff" + text.encode("utf-16-be")
    return text.encode(codec, "replace") if codec in ("ascii", "latin-1") else text.encode(codec)


def _decode(raw: bytes, charset: Any) -> str:
    codec = _codec(charset)
    if codec == "utf-16":  # Java honours a byte-order mark and reads big-endian without one.
        codec, raw = ("utf-16-le", raw[2:]) if raw[:2] == b"\xff\xfe" else ("utf-16-be", raw[2:] if raw[:2] == b"\xfe\xff" else raw)
    return raw.decode(codec, "replace")


class Spec:
    """javax.crypto.spec.SecretKeySpec / IvParameterSpec / GCMParameterSpec / PBEKeySpec, filled by <init>."""

    def __init__(self, cls: str) -> None:
        self.cls, self.data, self.algorithm, self.tag_bits = cls, b"", "", 128
        self.password, self.iterations, self.key_bits = "", 0, 0


class CipherState:
    """javax.crypto.Cipher: AES (ECB and CBC both ways, CTR, GCM decryption) and RC4, run by ciphers.py.
    update() returns what Java's would (whole blocks; a padded decryption holds back its last one)."""

    def __init__(self, transformation: str) -> None:
        parts = [part.strip().upper() for part in str(transformation).split("/")]
        if parts[0] in ("RC4", "ARCFOUR") and parts[2:] in ([], ["NOPADDING"]):
            self.mode, self.padded = "RC4", False
        elif parts[0] in ("AES", "AES_128", "AES_192", "AES_256") and len(parts) in (1, 3):
            self.mode, padding = (parts[1], parts[2]) if len(parts) == 3 else ("ECB", "PKCS5PADDING")
            if self.mode not in ("ECB", "CBC", "CTR", "GCM") or padding not in ("PKCS5PADDING", "PKCS7PADDING", "NOPADDING") \
                    or (self.mode in ("CTR", "GCM") and padding != "NOPADDING"):
                raise Unsupported(f"Cipher {transformation}")
            self.padded = padding != "NOPADDING"
        else:
            raise Unsupported(f"Cipher {transformation}")
        self.key = self.iv = None
        self.decrypt, self.tag_bytes = True, 16
        self.data, self.emitted = bytearray(), 0

    def init(self, opmode: int, key: Any, params: Any) -> None:
        if opmode not in (1, 2) or not isinstance(key, Spec) or not key.data:
            raise Unsupported("Cipher.init")
        self.decrypt, self.key = opmode == 2, key.data
        if self.mode in ("CBC", "CTR", "GCM"):
            if not isinstance(params, Spec) or not params.data:
                raise Unsupported("Cipher without its IV")  # Java would pick a random one.
            self.iv, self.tag_bytes = params.data, params.tag_bits // 8
        if self.mode == "GCM" and not self.decrypt:
            raise Unsupported("GCM encryption")
        if self.mode != "RC4" and len(self.key) not in (16, 24, 32):
            raise Unsupported("AES key length")
        self.data, self.emitted = bytearray(), 0

    def run(self, data: bytes, final: bool) -> list[int]:
        from . import ciphers  # Lazy: only an app that uses Cipher pays for the tables.

        if self.key is None:
            raise Unsupported("Cipher used before init")
        self.data += data
        whole = bytes(self.data)
        try:
            if self.mode == "RC4":
                out = ciphers.rc4(self.key, whole)
            elif self.mode == "CTR":
                out = ciphers.ctr(self.key, self.iv, whole)
            elif self.mode == "GCM":
                out = ciphers.gcm_decrypt(self.key, self.iv, whole, self.tag_bytes) if final else b""
            else:
                usable = len(whole) if final else len(whole) // 16 * 16
                if not final and self.decrypt and self.padded and usable == len(whole):
                    usable -= 16
                block = whole[:max(usable, 0)]
                if final and self.padded and not self.decrypt:
                    block = ciphers.pad(block)
                if self.decrypt:
                    out = ciphers.ecb_decrypt(self.key, block) if self.mode == "ECB" else ciphers.cbc_decrypt(self.key, self.iv, block)
                    out = ciphers.unpad(out) if final and self.padded else out
                else:
                    out = ciphers.ecb_encrypt(self.key, block) if self.mode == "ECB" else ciphers.cbc_encrypt(self.key, self.iv, block)
        except ValueError as error:  # BadPaddingException, IllegalBlockSizeException
            raise Unsupported(f"Cipher: {error}") from None
        chunk = out[self.emitted:]
        self.emitted = len(out)
        if final:  # doFinal resets the cipher to its initialized state.
            self.data, self.emitted = bytearray(), 0
        return _signed_bytes(chunk)


class MacState:
    """javax.crypto.Mac: HmacMD5 / HmacSHA1 / HmacSHA224 / HmacSHA256 / HmacSHA384 / HmacSHA512."""

    NAMES = {"HMACMD5": "md5", "HMACSHA1": "sha1", "HMACSHA224": "sha224", "HMACSHA256": "sha256",
             "HMACSHA384": "sha384", "HMACSHA512": "sha512"}

    def __init__(self, algorithm: str) -> None:
        if not isinstance(algorithm, str) or algorithm.upper() not in self.NAMES:
            raise Unsupported(f"Mac {algorithm}")
        self.digest, self.key, self.mac = self.NAMES[algorithm.upper()], None, None


class BigNum:
    """java.math.BigInteger as a Python int: new BigInteger(1, digest).toString(16) and its arithmetic."""

    def __init__(self, value: int = 0) -> None:
        self.value = value


class Unresolved:
    """A manifest value Android resolves from resources (versionName="@0x7f..."): any use stops the run."""


class PathToken:
    """The app's own APK path (getPackageCodePath, ApplicationInfo.sourceDir). Only ZipFile and File
    accept it: the real path holds a random install directory, so its text is never an answer."""


class FileModel:
    def __init__(self) -> None:
        self.path: Any = None


class ApkZip:
    """java.util.zip.ZipFile over the APK bytes in memory."""

    def __init__(self) -> None:
        self.archive: zipfile.ZipFile | None = None


class Entry:
    def __init__(self, info: zipfile.ZipInfo) -> None:
        self.info = info


class PackageManager:
    def __init__(self, context: "Context") -> None:
        self.context = context


class Signature:
    """android.content.pm.Signature: one v1 signer's DER certificate."""

    def __init__(self, data: bytes) -> None:
        self.data = data


class SigningInfo:
    def __init__(self, signers: list[Signature]) -> None:
        self.signers = signers


class Certificate:
    """java.security.cert.X509Certificate from CertificateFactory.generateCertificate."""

    def __init__(self, data: bytes) -> None:
        self.data = data


_PLATFORM_NEW = {
    **{kind: (lambda kind=kind: Spec(kind)) for kind in ("Ljavax/crypto/spec/SecretKeySpec;", "Ljavax/crypto/spec/IvParameterSpec;",
                                                          "Ljavax/crypto/spec/GCMParameterSpec;", "Ljavax/crypto/spec/PBEKeySpec;")},
    "Ljava/math/BigInteger;": BigNum, "Ljava/util/zip/ZipFile;": ApkZip, "Ljava/io/File;": FileModel,
    "Ljava/io/ByteArrayInputStream;": lambda: Stream(b""),
}
_PLATFORM_STATICS = {("Ljava/nio/charset/StandardCharsets;", name): Charset(name.replace("_", "-"))
                     for name in ("UTF_8", "US_ASCII", "ISO_8859_1", "UTF_16", "UTF_16BE", "UTF_16LE")}


def _chars(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, Builder):
        return "".join(value.parts)
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    raise Unsupported(f"string of {type(value).__name__}")


def _java_hash(text: str) -> int:
    value = 0
    raw = text.encode("utf-16-le", "surrogatepass")
    for unit in struct.unpack(f"<{len(raw) // 2}H", raw):
        value = (31 * value + unit) & M32
    return s32(value)


def _bytes(array: list[int]) -> bytes:
    return bytes(value & 0xFF for value in array)


def _signed_bytes(raw: bytes) -> list[int]:
    return [value - 256 if value > 127 else value for value in raw]


_FORMAT = re.compile(r"%([-#+ 0,(]*)(\d+)?(?:\.(\d+))?([dxXsSc%n])")


def _format(pattern: str, args: list[Any]) -> str:
    """String.format for the plain conversions (%d %x %X %s %c with flags/width)."""
    values = iter(args)

    def one(match: re.Match) -> str:
        flags, width, _, kind = match.groups()
        if kind == "%":
            return "%"
        if kind == "n":
            return "\n"
        value = next(values)
        if kind in "xX":
            # Boxing is transparent here, so Integer vs Long is told apart by range only.
            text = format(value & (M32 if -(1 << 31) <= value < (1 << 31) else M64), "x")
            text = text.upper() if kind == "X" else text
        elif kind == "d":
            text = str(value)
        elif kind == "c":
            text = chr(value) if isinstance(value, int) else str(value)
        else:
            text = _chars(value)
            text = text.upper() if kind == "S" else text
        if width:
            fill = "0" if "0" in flags and kind not in "sSc" else " "
            text = text.ljust(int(width), " ") if "-" in flags else text.rjust(int(width), fill)
        return text

    return _FORMAT.sub(one, pattern)


# --- Platform methods (pure ones only) ----------------------------------------------------------

def _platform(cls: str, name: str, sig: str, args: list[Any], vm: "Machine") -> Any:
    this = args[0] if args else None
    if cls in ("Ljava/lang/StringBuilder;", "Ljava/lang/StringBuffer;"):
        if name == "<init>":
            this.parts = [_chars(args[1])] if len(args) > 1 and not sig.startswith("(I)") else []
            return None
        if name == "append":
            value = args[1]
            this.parts.append(chr(value) if sig.startswith("(C)") else
                              ("true" if value else "false") if sig.startswith("(Z)") else _chars(value))
            return this
        text = "".join(this.parts)
        if name == "toString":
            return text
        if name == "length":
            return len(text)
        if name == "charAt":
            return ord(text[args[1]])
        if name == "reverse":
            this.parts = [text[::-1]]
            return this
        if name == "insert":
            this.parts = [text[:args[1]] + (chr(args[2]) if "C)" in sig else _chars(args[2])) + text[args[1]:]]
            return this
        if name == "setCharAt":
            this.parts = [text[:args[1]] + chr(args[2]) + text[args[1] + 1:]]
            return None
        if name == "deleteCharAt":
            this.parts = [text[:args[1]] + text[args[1] + 1:]]
            return this
        if name == "setLength":
            this.parts = [text[:args[1]].ljust(args[1], "\0")]
            return None
    if cls == "Ljava/lang/String;":
        if name == "<init>":
            source = args[1]
            ranged = sig.startswith(("([BII", "([CII"))
            if isinstance(source, list) and ranged:
                source = source[args[2]:args[2] + args[3]]
            if isinstance(source, list) and sig.startswith("([C"):
                return "".join(chr(c) for c in source)
            if isinstance(source, list):  # new String(bytes[, off, len][, charset])
                charset = args[4 if ranged else 2] if len(args) > (4 if ranged else 2) else None
                return _decode(_bytes(source), charset)
            return _chars(source)
        if name == "valueOf" or name == "copyValueOf":
            value = args[0]
            if sig.startswith("(C)"):
                return chr(value)
            if sig.startswith("(Z)"):
                return "true" if value else "false"
            if sig.startswith("([C"):
                return "".join(chr(c) for c in value)
            return _chars(value)
        if name == "format":
            return _format(args[0], args[1] or [])
        if name == "join":
            items = args[1] if isinstance(args[1], list) else []
            return _chars(args[0]).join(_chars(item) for item in items)
        text = this
        if not isinstance(text, str):
            raise Unsupported("String method on a non-string")
        simple = {
            "length": lambda: len(text), "isEmpty": lambda: not text, "toUpperCase": text.upper,
            "toLowerCase": text.lower, "trim": text.strip, "hashCode": lambda: _java_hash(text),
            "toCharArray": lambda: [ord(c) for c in text], "intern": lambda: text, "toString": lambda: text,
        }
        if name in simple and sig.startswith("()"):
            return simple[name]()
        if name == "getBytes":
            return _signed_bytes(_encode(text, args[1] if len(args) > 1 else None))
        if name == "charAt":
            return ord(text[args[1]])
        if name == "substring":
            return text[args[1]:args[2]] if len(args) > 2 else text[args[1]:]
        if name in ("equals", "contentEquals"):
            return isinstance(args[1], str) and text == args[1]
        if name == "equalsIgnoreCase":
            return isinstance(args[1], str) and text.lower() == args[1].lower()
        if name == "concat":
            return text + args[1]
        if name == "indexOf":
            needle = chr(args[1]) if isinstance(args[1], int) else args[1]
            return text.find(needle, args[2] if len(args) > 2 else 0)
        if name == "startsWith":
            return text.startswith(args[1])
        if name == "endsWith":
            return text.endswith(args[1])
        if name == "contains":
            return _chars(args[1]) in text
        if name == "replace":
            old, new = (chr(args[1]), chr(args[2])) if sig.startswith("(CC") else (_chars(args[1]), _chars(args[2]))
            return text.replace(old, new)
        if name == "compareTo":
            return (text > args[1]) - (text < args[1])
    if cls in ("Ljava/lang/Long;", "Ljava/lang/Integer;"):
        wide = cls == "Ljava/lang/Long;"
        bits, mask, fix = (64, M64, s64) if wide else (32, M32, s32)
        value = args[0] if args else None
        if name in ("valueOf", "longValue", "intValue", "hashCode") and not (name == "valueOf" and isinstance(value, str)):
            if name == "hashCode" and wide:
                return s32(value ^ (value >> 32 & M32))
            return s32(value) if name == "intValue" else value
        if name in ("toHexString", "toBinaryString", "toOctalString"):
            return format(value & mask, {"toHexString": "x", "toBinaryString": "b", "toOctalString": "o"}[name])
        if name == "toString" or name == "toUnsignedString":
            if len(args) > 1 and isinstance(args[1], int) and args[1] != 10:
                digits = "0123456789abcdefghijklmnopqrstuvwxyz"
                number, radix, out = abs(value) if name == "toString" else value & mask, args[1], ""
                while True:
                    number, digit = divmod(number, radix)
                    out = digits[digit] + out
                    if not number:
                        break
                return ("-" + out) if name == "toString" and value < 0 else out
            return str(value & mask if name == "toUnsignedString" else value)
        if name in ("parseLong", "parseInt", "valueOf", "decode"):
            return fix(int(value, args[1] if len(args) > 1 else 10))
        if name in ("parseUnsignedLong", "parseUnsignedInt"):
            return fix(int(value, args[1] if len(args) > 1 else 10))
        if name == "rotateLeft":
            shift = args[1] % bits
            return fix(((value & mask) << shift) | ((value & mask) >> (bits - shift)))
        if name == "rotateRight":
            shift = args[1] % bits
            return fix(((value & mask) >> shift) | ((value & mask) << (bits - shift)))
        if name == "bitCount":
            return bin(value & mask).count("1")
        if name == "reverse":
            return fix(int(format(value & mask, f"0{bits}b")[::-1], 2))
        if name == "reverseBytes":
            return fix(int.from_bytes((value & mask).to_bytes(bits // 8, "little"), "big"))
        if name == "numberOfLeadingZeros":
            return bits - (value & mask).bit_length()
        if name == "numberOfTrailingZeros":
            return bits if not value & mask else ((value & mask) & -(value & mask)).bit_length() - 1
        if name == "highestOneBit":
            return fix(1 << ((value & mask).bit_length() - 1)) if value & mask else 0
        if name == "signum":
            return (value > 0) - (value < 0)
        if name in ("compare", "compareUnsigned"):
            a, b = (args[0], args[1]) if name == "compare" else (args[0] & mask, args[1] & mask)
            return (a > b) - (a < b)
        if name in ("sum", "max", "min"):
            return fix({"sum": args[0] + args[1], "max": max(args[0], args[1]), "min": min(args[0], args[1])}[name])
        if name == "equals":
            return args[0] == args[1]
    if cls == "Ljava/lang/Math;" or cls == "Ljava/lang/StrictMath;":
        wide = "J" in sig
        fix = s64 if wide else s32
        if name == "abs":
            return fix(abs(args[0])) if isinstance(args[0], int) else abs(args[0])
        if name in ("max", "min"):
            return (max if name == "max" else min)(args[0], args[1])
        if name == "floorMod":
            return fix(args[0] % args[1])
        if name == "floorDiv":
            return fix(args[0] // args[1])
    if cls == "Ljava/lang/Character;":
        value = args[0]
        if name == "toUpperCase":
            return ord(chr(value).upper()[0])
        if name == "toLowerCase":
            return ord(chr(value).lower()[0])
        if name == "isDigit":
            return chr(value).isdigit()
        if name == "isLetter":
            return chr(value).isalpha()
        if name == "isLetterOrDigit":
            return chr(value).isalnum()
        if name == "forDigit":
            return ord("0123456789abcdefghijklmnopqrstuvwxyz"[value]) if 0 <= value < args[1] <= 36 else 0
        if name == "digit":
            try:
                return int(chr(value), args[1])
            except ValueError:
                return -1
        if name in ("valueOf", "charValue"):
            return value
    if cls == "Ljava/lang/Object;" and name == "<init>":
        return None
    if cls == "Ljava/util/zip/CRC32;":
        if name == "<init>":
            return None
        if name == "update":
            data = bytes([args[1] & 0xFF]) if sig.startswith("(I)") else _bytes(args[1])
            if sig.startswith("([BII)"):
                data = _bytes(args[1][args[2]:args[2] + args[3]])
            this.value = zlib.crc32(data, this.value)
            return None
        if name == "getValue":
            return this.value
        if name == "reset":
            this.value = 0
            return None
    if cls == "Ljava/security/MessageDigest;":
        if name == "getInstance":
            return Digest(args[0])
        if name == "update":
            this.hash.update(_bytes(args[1]) if isinstance(args[1], list) else bytes([args[1] & 0xFF]))
            return None
        if name == "digest":
            if len(args) > 1:
                this.hash.update(_bytes(args[1]))
            return _signed_bytes(this.hash.digest())
    if cls == "Landroid/util/Base64;":
        if name == "decode":
            raw = args[0] if isinstance(args[0], str) else _bytes(args[0]).decode("latin-1")
            return _signed_bytes(base64.b64decode(raw + "=" * (-len(raw) % 4), altchars=b"-_" if args[1] & 8 else None))
        if name in ("encodeToString", "encode"):
            text = base64.b64encode(_bytes(args[0]), altchars=b"-_" if args[1] & 8 else None).decode()
            text = text.rstrip("=") if args[1] & 1 else text
            return text if name == "encodeToString" else _signed_bytes(text.encode())
    if cls == "Ljava/util/Base64;" and name in ("getDecoder", "getEncoder", "getUrlDecoder", "getUrlEncoder"):
        return JClass(name)
    if cls in ("Ljava/util/Base64$Decoder;", "Ljava/util/Base64$Encoder;"):
        url = this.name.startswith("getUrl")
        if name == "decode":
            raw = args[1] if isinstance(args[1], str) else _bytes(args[1]).decode("latin-1")
            return _signed_bytes(base64.b64decode(raw + "=" * (-len(raw) % 4), altchars=b"-_" if url else None))
        if name in ("encodeToString", "encode"):
            text = base64.b64encode(_bytes(args[1]), altchars=b"-_" if url else None).decode()
            return text if name == "encodeToString" else _signed_bytes(text.encode())
    if cls == "Ljava/util/Arrays;" and name == "copyOfRange":
        return list(args[0][args[1]:args[2]])
    if cls == "Ljava/util/Arrays;" and name == "copyOf":
        return (list(args[0]) + [0] * args[1])[:args[1]]
    if cls == "Ljava/lang/System;" and name == "loadLibrary":
        return None  # Nothing is loaded: native methods are read from lib/x86_64 and emulated.
    if cls == "Ljava/lang/System;" and name == "arraycopy":
        args[2][args[3]:args[3] + args[4]] = args[0][args[1]:args[1] + args[4]]
        return None
    if isinstance(this, Context) and name == "getPackageName" and this.package:
        return this.package
    if cls == "Landroid/content/Context;" and name == "getPackageName" and vm.context.package:
        return vm.context.package
    for handler in (_secondary_dex, _reflection, _android_apis):
        handled = handler(cls, name, sig, args, vm)
        if handled is not _UNHANDLED:
            return handled
    raise Unsupported(f"{cls}->{name}{sig}")


_PRIMITIVE_TYPES = {"Ljava/lang/Long;": "J", "Ljava/lang/Integer;": "I", "Ljava/lang/Short;": "S",
                    "Ljava/lang/Byte;": "B", "Ljava/lang/Character;": "C", "Ljava/lang/Boolean;": "Z",
                    "Ljava/lang/Double;": "D", "Ljava/lang/Float;": "F", "Ljava/lang/Void;": "V"}
_UNHANDLED = object()


class JMethod:
    def __init__(self, method: "Method") -> None:
        self.method = method


def _secondary_dex(cls: str, name: str, sig: str, args: list[Any], vm: "Machine") -> Any:
    """Day 20's module loading (reused by Day 25 Mastery): Context.getAssets().open(name), read into a
    byte[] (InputStream or ByteArrayOutputStream), ByteBuffer.wrap, then new InMemoryDexClassLoader(
    buffer, parent).loadClass(name). The bytes are the APK's own asset; the loaded classes join the
    app's, and a class the app already defines keeps its definition (a loader asks its parent first)."""
    this = args[0] if args else None
    if isinstance(this, Context) and name == "getAssets":
        return Assets(this)
    if isinstance(this, Assets) and name == "open" and isinstance(args[1], str):
        return Stream(this.context.asset(args[1]))
    if isinstance(this, Stream):
        rest = this.data[this.at:]
        if name == "read" and sig.startswith("()"):
            this.at += bool(rest)
            return rest[0] if rest else -1
        if name == "read":
            start, count = (args[2], args[3]) if len(args) > 3 else (0, len(args[1]))
            chunk = rest[:count]
            if count and not chunk:
                return -1
            args[1][start:start + len(chunk)] = _signed_bytes(chunk)
            this.at += len(chunk)
            return len(chunk)
        if name == "readAllBytes":
            this.at = len(this.data)
            return _signed_bytes(rest)
        if name == "available":
            return len(rest)
        if name == "close":
            return None
    if isinstance(this, Sink):
        if name in ("<init>", "close", "flush"):
            return None
        if name == "write":
            if sig.startswith("(I)"):
                this.data.append(args[1] & 0xFF)
            else:
                start, count = (args[2], args[3]) if len(args) > 3 else (0, len(args[1]))
                this.data += _bytes(args[1][start:start + count])
            return None
        if name == "toByteArray":
            return _signed_bytes(bytes(this.data))
        if name == "size":
            return len(this.data)
    if cls == "Ljava/nio/ByteBuffer;" and name == "wrap" and isinstance(this, list):
        start, count = (args[1], args[2]) if len(args) > 2 else (0, len(this))
        return Buffer(_bytes(this[start:start + count]))
    if cls == "Ljava/lang/Class;" and name == "getClassLoader" and isinstance(this, JClass):
        return Loader()
    if isinstance(this, Loader):
        if name == "<init>":
            buffers = args[1] if isinstance(args[1], list) else [args[1]]
            if not buffers or not all(isinstance(buffer, Buffer) for buffer in buffers):
                raise Unsupported(f"{cls} from a file")  # DexClassLoader/PathClassLoader read a path
            this.dexes = [Dex(buffer.data) for buffer in buffers]
            return None
        if name == "loadClass" and isinstance(args[1], str):
            vm.load(this.dexes)
            target = "L" + args[1].replace(".", "/") + ";"
            if target not in vm.classes:
                raise Unsupported(f"loadClass {target}")
            return JClass(target)
    return _UNHANDLED


def _reflection(cls: str, name: str, sig: str, args: list[Any], vm: "Machine") -> Any:
    """Day 19's reflection maze (reused by Day 25 Mastery): Class.forName / getDeclaredMethod /
    Method.invoke, but only into the app's own classes; reflection into the platform stays Unsupported."""
    this = args[0] if args else None
    if cls == "Ljava/lang/Class;" and name == "forName" and isinstance(this, str):
        if len(args) > 2 and isinstance(args[2], Loader):  # forName(name, initialize, loader)
            vm.load(args[2].dexes)
        target = "L" + this.replace(".", "/") + ";"
        if target not in vm.classes:
            raise Unsupported(f"reflection into {target}")
        return JClass(target)
    if cls == "Ljava/lang/Class;" and name in ("getDeclaredMethod", "getMethod") and isinstance(this, JClass):
        if this.name not in vm.classes or not isinstance(args[1], str):
            raise Unsupported(f"reflection into {this.name}")
        kinds = args[2] if len(args) > 2 and args[2] is not None else []
        if not all(isinstance(kind, JClass) for kind in kinds):
            raise Unsupported("reflective parameter types")
        prefix = "(" + "".join(kind.name for kind in kinds) + ")"
        owner = this.name
        while owner in vm.classes:
            hits = [m for (n, sig), m in vm.classes[owner].methods.items() if n == args[1] and sig.startswith(prefix)]
            if len(hits) == 1:
                return JMethod(hits[0])
            owner = vm.classes[owner].superclass or ""
        raise Unsupported(f"no method {this.name}->{args[1]}{prefix}")
    if cls in ("Ljava/lang/reflect/Method;", "Ljava/lang/reflect/AccessibleObject;") and isinstance(this, JMethod):
        if name == "setAccessible":
            return None
        if name == "invoke":
            method = this.method
            values = list(args[2]) if len(args) > 2 and args[2] is not None else []
            static = bool(method.flags & ACC_STATIC)
            sig = "(" + "".join(method.params) + ")" + method.ret
            return vm.invoke(method.cls, method.name, sig, values if static else [args[1]] + values, not static)
    return _UNHANDLED

def _radix(value: int, radix: int) -> str:
    digits, number, out = "0123456789abcdefghijklmnopqrstuvwxyz", abs(value), ""
    if not 2 <= radix <= 36:
        radix = 10  # Java's own fallback for an out-of-range radix.
    while True:
        number, digit = divmod(number, radix)
        out = digits[digit] + out
        if not number:
            break
    return "-" + out if value < 0 else out


def _array_hash(array: list[int]) -> int:
    """java.util.Arrays.hashCode(byte[]) (and Signature.hashCode)."""
    value = 1
    for item in array:
        value = (31 * value + item) & M32
    return s32(value)


def _signers(apk: bytes) -> list[Signature]:
    """The v1 (JAR) signers' certificates: the first certificate of each META-INF/*.RSA|DSA|EC PKCS#7
    SignedData. Every Mastery APK of days 1-25 carries one beside its v2 block, the same certificate."""
    from .formats_dfir import der, der_children  # Lazy, like ciphers.

    found = []
    try:
        with zipfile.ZipFile(BytesIO(apk)) as archive:
            for name in sorted(n for n in archive.namelist() if re.fullmatch(r"META-INF/[^/]+\.(?:RSA|DSA|EC)", n)):
                blob = read_member(archive, name, 1 << 20)
                _, start, end = der(blob, 0)                          # ContentInfo
                content = der_children(blob, start, end)[1]           # [0] EXPLICIT SignedData
                _, start, end = der(blob, content[1])
                for tag, inner, _ in der_children(blob, start, end):
                    if tag == 0xA0:                                   # certificates [0] IMPLICIT
                        found.append(Signature(blob[inner:der(blob, inner)[2]]))
                        break
    except (*ZIP_ERRORS, KeyError, IndexError, ValueError) as error:
        raise Unsupported(f"signing certificate: {error}") from None
    if not found:
        raise Unsupported("no v1 signing certificate")  # A v2/v3-only APK: its signing block is not read.
    return found


def _manifest(apk: bytes) -> dict[str, str]:
    from .formats import axml

    try:
        with zipfile.ZipFile(BytesIO(apk)) as archive:
            elements = axml(read_member(archive, "AndroidManifest.xml", MAX_ASSET_BYTES))
    except (*ZIP_ERRORS, KeyError, IndexError, ValueError, struct.error) as error:
        raise Unsupported(f"manifest: {error}") from None
    return next((attributes for tag, attributes in elements if tag == "manifest"), {})


def _own_package(vm: "Machine", package: Any) -> None:
    if not isinstance(package, str) or package != vm.context.package or vm.context.apk is None:
        raise Unsupported(f"package {package}")  # Another app's state is the device's, not the APK's.


def _android_apis(cls: str, name: str, sig: str, args: list[Any], vm: "Machine") -> Any:
    """See the models above. Reached only by calls the older handlers do not take."""
    this = args[0] if args else None
    if cls == "Ljava/nio/charset/Charset;" and name == "forName":
        return Charset(this)
    if isinstance(this, Charset) and name in ("name", "displayName", "toString"):
        return this.name
    if isinstance(this, Spec):
        if name == "<init>":
            if this.cls == "Ljavax/crypto/spec/GCMParameterSpec;":
                this.tag_bits, raw = args[1], args[2]
                this.data = _bytes(raw[args[3]:args[3] + args[4]] if len(args) > 4 else raw)
            elif this.cls == "Ljavax/crypto/spec/PBEKeySpec;":
                this.password = "".join(chr(c) for c in args[1])
                if len(args) > 2:
                    this.data, this.iterations = _bytes(args[2]), args[3]
                    this.key_bits = args[4] if len(args) > 4 else 0
            else:  # SecretKeySpec(key, alg) / (key, off, len, alg); IvParameterSpec(iv) / (iv, off, len)
                raw = args[1]
                this.data = _bytes(raw[args[2]:args[2] + args[3]] if sig.startswith("([BII") else raw)
                this.algorithm = args[-1] if this.cls == "Ljavax/crypto/spec/SecretKeySpec;" else ""
            return None
        if name in ("getEncoded", "getIV"):
            return _signed_bytes(this.data)
        if name == "getAlgorithm":
            return this.algorithm
        if name == "getTLen":
            return this.tag_bits
    if cls == "Ljavax/crypto/Cipher;" and name == "getInstance":
        return CipherState(this)
    if isinstance(this, CipherState):
        if name == "init":
            this.init(args[1], args[2], args[3] if len(args) > 3 and isinstance(args[3], Spec) else None)
            return None
        if name in ("update", "doFinal"):
            if not sig.endswith(")[B"):
                raise Unsupported(f"Cipher.{name}{sig}")  # The overloads that fill an output buffer.
            raw = args[1] if len(args) > 1 and isinstance(args[1], list) else []
            raw = raw[args[2]:args[2] + args[3]] if sig.startswith("([BII") else raw
            return this.run(_bytes(raw), name == "doFinal")
        if name == "getIV":
            return _signed_bytes(this.iv) if this.iv is not None else None
        if name == "getBlockSize":
            return 0 if this.mode == "RC4" else 16
    if cls == "Ljavax/crypto/Mac;" and name == "getInstance":
        return MacState(this)
    if isinstance(this, MacState):
        import hmac

        if name == "init" and isinstance(args[1], Spec):
            this.key = args[1].data
            this.mac = hmac.new(this.key, digestmod=this.digest)
            return None
        if this.mac is None:
            raise Unsupported("Mac used before init")
        if name == "update":
            raw = [args[1]] if sig.startswith("(B)") else args[1][args[2]:args[2] + args[3]] if sig.startswith("([BII") else args[1]
            this.mac.update(_bytes(raw))
            return None
        if name == "doFinal":
            if not sig.endswith(")[B"):
                raise Unsupported(f"Mac.doFinal{sig}")  # doFinal(byte[] output, int offset)
            if len(args) > 1:
                this.mac.update(_bytes(args[1]))
            digest, this.mac = this.mac.digest(), hmac.new(this.key, digestmod=this.digest)
            return _signed_bytes(digest)
        if name == "getMacLength":
            return this.mac.digest_size
    if cls == "Ljavax/crypto/SecretKeyFactory;" and name == "getInstance":
        match = re.fullmatch(r"PBKDF2WithHmac(SHA1|SHA224|SHA256|SHA384|SHA512)", str(this), re.I)
        if not match:
            raise Unsupported(f"SecretKeyFactory {this}")
        return JClass(match[1].lower())
    if cls == "Ljavax/crypto/SecretKeyFactory;" and name == "generateSecret" and isinstance(this, JClass):
        spec = args[1]
        if not isinstance(spec, Spec) or not 0 < spec.iterations <= 1_000_000 or not 0 < spec.key_bits <= 4096:
            raise Unsupported("PBKDF2 parameters")
        key = Spec("Ljavax/crypto/spec/SecretKeySpec;")
        key.data = hashlib.pbkdf2_hmac(this.name, spec.password.encode("utf-8"), spec.data, spec.iterations, spec.key_bits // 8)
        return key
    if cls == "Ljava/math/BigInteger;":
        if name == "<init>" and isinstance(this, BigNum):
            if sig.startswith("(I[B"):
                this.value = int.from_bytes(_bytes(args[2]), "big") * (1 if args[1] >= 0 else -1)
            elif sig.startswith("([B"):
                this.value = int.from_bytes(_bytes(args[1]), "big", signed=True) if args[1] else 0
            elif sig.startswith("(Ljava/lang/String;"):
                this.value = int(args[1], args[2] if len(args) > 2 else 10)
            else:
                raise Unsupported(f"BigInteger{sig}")
            return None
        if name == "valueOf":
            return BigNum(this)
    if isinstance(this, BigNum):
        other = args[1].value if len(args) > 1 and isinstance(args[1], BigNum) else None
        value = this.value
        if name == "toString":
            return _radix(value, args[1] if len(args) > 1 else 10)
        if name in ("longValue", "intValue"):
            return s64(value) if name == "longValue" else s32(value)
        if name == "signum":
            return (value > 0) - (value < 0)
        if name == "bitLength":
            return (value if value >= 0 else ~value).bit_length()
        if name == "toByteArray":
            return _signed_bytes(value.to_bytes((value if value >= 0 else ~value).bit_length() // 8 + 1, "big", signed=True))
        if name in ("equals", "compareTo") and other is not None:
            return value == other if name == "equals" else (value > other) - (value < other)
        if name in ("shiftLeft", "shiftRight", "pow", "testBit") and isinstance(args[1], int):
            shift = args[1]
            return {"shiftLeft": lambda: BigNum(value << shift if shift >= 0 else value >> -shift),
                    "shiftRight": lambda: BigNum(value >> shift if shift >= 0 else value << -shift),
                    "pow": lambda: BigNum(value ** shift) if 0 <= shift <= 4096 else None,
                    "testBit": lambda: bool(value >> shift & 1)}[name]()
        if name in ("abs", "negate"):
            return BigNum(abs(value) if name == "abs" else -value)
        if other is not None:
            if name in ("divide", "remainder", "mod") and other == 0 or name == "mod" and other < 0:
                raise Unsupported("BigInteger division by zero")
            quotient = abs(value) // abs(other) * (1 if (value >= 0) == (other >= 0) else -1) if name in ("divide", "remainder") else 0
            results = {"add": lambda: value + other, "subtract": lambda: value - other, "multiply": lambda: value * other,
                       "xor": lambda: value ^ other, "and": lambda: value & other, "or": lambda: value | other,
                       "mod": lambda: value % other, "divide": lambda: quotient, "remainder": lambda: value - quotient * other,
                       "max": lambda: max(value, other), "min": lambda: min(value, other)}
            if name in results:
                return BigNum(results[name]())
            if name == "modPow" and len(args) > 2 and isinstance(args[2], BigNum) and args[2].value > 0 and other >= 0:
                return BigNum(pow(value, other, args[2].value))
    if cls == "Ljava/util/Arrays;" and name == "hashCode" and isinstance(this, list):
        return _array_hash(this)
    if (cls == "Ljava/util/Arrays;" and name == "equals" or cls == "Ljava/security/MessageDigest;" and name == "isEqual") \
            and len(args) == 2:
        return isinstance(args[0], list) and isinstance(args[1], list) and args[0] == args[1]
    if isinstance(this, Context):
        if name in ("getPackageCodePath", "getPackageResourcePath") and this.apk is not None:
            return PathToken()
        if name == "getPackageManager":
            return PackageManager(this)
        if name == "getApplicationInfo" and this.apk is not None and this.package:
            info = JObject("Landroid/content/pm/ApplicationInfo;")
            info.fields.update(packageName=this.package, sourceDir=PathToken(), publicSourceDir=PathToken())
            return info
    if isinstance(this, PackageManager):
        if name == "getPackageInfo":
            _own_package(vm, args[1])
            flags = args[2] if isinstance(args[2], int) else None
            if flags is None:
                raise Unsupported("PackageInfoFlags")
            manifest = _manifest(vm.context.apk)
            info = JObject("Landroid/content/pm/PackageInfo;")
            version_name, version_code = manifest.get("versionName"), manifest.get("versionCode", "")
            info.fields.update(packageName=vm.context.package, signatures=None, signingInfo=None,
                               versionName=Unresolved() if str(version_name).startswith("@") else version_name)
            if re.fullmatch(r"\d+|0x[0-9a-f]+", version_code):
                info.fields["versionCode"] = s32(int(version_code, 0))
            if flags & 0x40:  # GET_SIGNATURES
                info.fields["signatures"] = _signers(vm.context.apk)
            if flags & 0x08000000:  # GET_SIGNING_CERTIFICATES
                info.fields["signingInfo"] = SigningInfo(_signers(vm.context.apk))
            return info
        if name == "getApplicationInfo":
            _own_package(vm, args[1])
            return _android_apis("Landroid/content/Context;", "getApplicationInfo", "", [this.context], vm)
    if isinstance(this, JObject) and this.cls == "Landroid/content/pm/PackageInfo;" and name == "getLongVersionCode":
        code = this.fields.get("versionCode")
        if code is None:
            raise Unsupported("versionCode")
        return code & M32
    if isinstance(this, SigningInfo):
        if name in ("getApkContentsSigners", "getSigningCertificateHistory"):
            return list(this.signers)
        if name == "hasMultipleSigners":
            return len(this.signers) > 1
        if name == "hasPastSigningCertificates":
            return False
    if isinstance(this, Signature):
        if name == "toByteArray":
            return _signed_bytes(this.data)
        if name == "toCharsString":
            return this.data.hex()
        if name == "hashCode":
            return _array_hash(_signed_bytes(this.data))
        if name == "equals":
            return isinstance(args[1], Signature) and args[1].data == this.data
    if isinstance(this, FileModel) and name == "<init>":
        if not isinstance(args[1], PathToken):
            raise Unsupported("File outside the APK")
        this.path = args[1]
        return None
    if isinstance(this, FileModel) and name in ("length", "exists", "isFile"):
        return len(vm.context.apk) if name == "length" else True
    if isinstance(this, ApkZip):
        if name == "<init>":
            if not isinstance(args[1], PathToken) and not (isinstance(args[1], FileModel) and args[1].path is not None):
                raise Unsupported("ZipFile outside the APK")
            try:
                this.archive = zipfile.ZipFile(BytesIO(vm.context.apk))
            except ZIP_ERRORS as error:
                raise Unsupported(f"ZipFile: {error}") from None
            return None
        if this.archive is None:
            raise Unsupported("ZipFile before <init>")
        if name == "getEntry":
            try:
                return Entry(this.archive.getinfo(args[1]))
            except KeyError:
                return None
        if name == "size":
            return len(this.archive.infolist())
        if name == "getInputStream" and isinstance(args[1], Entry):
            try:
                return Stream(read_member(this.archive, args[1].info.filename, MAX_ASSET_BYTES))
            except ZIP_ERRORS as error:
                raise Unsupported(f"ZipFile entry: {error}") from None
        if name == "close":
            return None
    if isinstance(this, Entry):
        info = this.info
        simple = {"getCrc": lambda: info.CRC, "getSize": lambda: info.file_size, "getCompressedSize": lambda: info.compress_size,
                  "getName": lambda: info.filename, "isDirectory": info.is_dir, "getMethod": lambda: info.compress_type,
                  "toString": lambda: info.filename}
        if name in simple:
            return simple[name]()
    if isinstance(this, Stream) and name == "<init>" and isinstance(args[1], list):  # ByteArrayInputStream
        raw = args[1][args[2]:args[2] + args[3]] if sig.startswith("([BII") else args[1]
        this.data, this.at = _bytes(raw), 0
        return None
    if cls == "Ljava/security/cert/CertificateFactory;" and name == "getInstance":
        if str(this).upper() != "X.509":
            raise Unsupported(f"CertificateFactory {this}")
        return JClass("X.509")
    if cls == "Ljava/security/cert/CertificateFactory;" and name == "generateCertificate" and isinstance(args[1], Stream):
        from .formats_dfir import der

        stream = args[1]
        try:
            end = der(stream.data, stream.at)[2]
        except (IndexError, ValueError):
            raise Unsupported("certificate bytes") from None
        blob, stream.at = stream.data[stream.at:end], end
        return Certificate(blob)
    if isinstance(this, Certificate) and name == "getEncoded":
        return _signed_bytes(this.data)
    return _UNHANDLED


# --- x86-64 subset for JNI `long f(long)` -------------------------------------------------------

_X64_ARGS = (7, 6, 2, 1, 8, 9)  # rdi, rsi, rdx, rcx, r8, r9


def elf_symbol(lib: bytes, symbol: str) -> bytes | None:
    """The bytes of an ELF64 symbol's function, by its file offset."""
    if not lib.startswith(b"\x7fELF\x02\x01"):
        return None
    shoff, = struct.unpack_from("<Q", lib, 0x28)
    shentsize, shnum = struct.unpack_from("<HH", lib, 0x3A)
    sections = [struct.unpack_from("<IIQQQQIIQQ", lib, shoff + i * shentsize) for i in range(shnum)]
    for _, kind, _, _, offset, size, link, _, _, entsize in sections:
        if kind not in (2, 11) or not entsize:
            continue
        strtab = sections[link][4]
        for at in range(offset, offset + size, entsize):
            name_at, info, _, _, value, length = struct.unpack_from("<IBBHQQ", lib, at)
            end = lib.index(b"\0", strtab + name_at)
            if lib[strtab + name_at:end].decode("latin-1") != symbol or info & 0xF != 2:
                continue
            for _, _, _, addr, sh_offset, sh_size, _, _, _, _ in sections:
                if addr and addr <= value < addr + sh_size:
                    start = value - addr + sh_offset
                    return lib[start:start + (length or 4096)]
    return None


def _flags(kind: str, a: int, b: int, bits: int) -> tuple[int, int, int, int]:
    """(result, CF, OF, bits) after `kind` on a, b: what a later jcc/cmovcc/setcc reads."""
    mask, top = (1 << bits) - 1, 1 << (bits - 1)
    a, b = a & mask, b & mask
    if kind == "sub":
        result = (a - b) & mask
        return result, int(a < b), int(bool((a ^ b) & (a ^ result) & top)), bits
    if kind == "add":
        result = (a + b) & mask
        return result, int(a + b > mask), int(bool(~(a ^ b) & (a ^ result) & top)), bits
    return _alu(kind, a, b) & mask, 0, 0, bits


def _condition(cc: int, flags: tuple[int, int, int, int] | None) -> bool:
    if flags is None:
        raise Unsupported("x86-64 branch without flags")
    result, cf, of, bits = flags
    zf, sf = result == 0, (result >> (bits - 1)) & 1
    if cc in (0xA, 0xB):
        raise Unsupported("x86-64 parity branch")
    taken = {0: of, 2: cf, 4: zf, 6: cf or zf, 8: sf, 0xC: sf != of, 0xE: zf or sf != of}[cc & 0xE]
    return bool(taken) != bool(cc & 1)


def run_x64(code: bytes, arguments: list[int], wide: bool = True) -> int:
    regs = [0] * 16
    for index, value in zip(_X64_ARGS, arguments):
        regs[index] = value & M64
    stack: list[int] = []
    flags: tuple[int, int, int, int] | None = None
    at = 0

    def width_fix(value: int, is64: bool) -> int:
        return value & (M64 if is64 else M32)

    def byte_reg(index: int, rex: int) -> int:
        # Without REX, byte registers 4-7 are ah, ch, dh, bh.
        return regs[index] & 0xFF if rex or index < 4 else (regs[index - 4] >> 8) & 0xFF

    for _ in range(10_000):
        if code[at:at + 4] == b"\xf3\x0f\x1e\xfa":  # endbr64
            at += 4
            continue
        word = code[at] == 0x66  # operand-size prefix: only compares/tests read 16-bit operands
        at += 1 if word else 0
        rex = code[at] if 0x40 <= code[at] <= 0x4F else 0
        at += 1 if rex else 0
        w, r, b = bool(rex & 8), (rex >> 2) & 1, rex & 1
        op = code[at]
        at += 1
        if op == 0xC3:
            return regs[0] if wide else s32(regs[0])
        if op == 0x90:
            continue
        # Branches (Day 25's JNI boundary checks a narrowed length before it mixes).
        if 0x70 <= op <= 0x7F or op == 0xEB:
            rel = int.from_bytes(code[at:at + 1], "little", signed=True)
            at += 1
            if op == 0xEB or _condition(op - 0x70, flags):
                at += rel
            continue
        if op == 0xE9:
            rel = int.from_bytes(code[at:at + 4], "little", signed=True)
            at += 4 + rel
            continue
        if op == 0x0F and 0x80 <= code[at] <= 0x8F:
            cc = code[at] - 0x80
            rel = int.from_bytes(code[at + 1:at + 5], "little", signed=True)
            at += 5
            if _condition(cc, flags):
                at += rel
            continue
        if op in (0x3D, 0xA9):  # cmp/test eax|rax, imm32
            bits = 64 if w else 16 if word else 32
            size = 2 if word else 4
            imm = int.from_bytes(code[at:at + size], "little", signed=True)
            at += size
            flags = _flags("sub" if op == 0x3D else "and", regs[0], imm, bits)
            continue
        if word:
            if op not in (0x39, 0x3B, 0x81, 0x83, 0x85, 0xF7):
                raise Unsupported("x86-64 16-bit operand")
        if 0x50 <= op <= 0x57:
            stack.append(regs[(op - 0x50) | (b << 3)])
            continue
        if 0x58 <= op <= 0x5F:
            regs[(op - 0x58) | (b << 3)] = stack.pop() if stack else 0
            continue
        if 0xB8 <= op <= 0xBF:
            dest = (op - 0xB8) | (b << 3)
            if w:
                regs[dest] = int.from_bytes(code[at:at + 8], "little")
                at += 8
            else:
                regs[dest] = int.from_bytes(code[at:at + 4], "little")
                at += 4
            continue
        if op == 0x0F and 0xC8 <= code[at] <= 0xCF:
            dest = (code[at] - 0xC8) | (b << 3)
            at += 1
            size = 8 if w else 4
            regs[dest] = int.from_bytes(regs[dest].to_bytes(8, "little")[:size], "big")
            continue
        two = op == 0x0F
        if two:
            op = 0x0F00 | code[at]
            at += 1
        modrm = code[at]
        at += 1
        if modrm >> 6 != 3:
            raise Unsupported("x86-64 memory operand")
        reg, rm = ((modrm >> 3) & 7) | (r << 3), (modrm & 7) | (b << 3)
        bits = 64 if w else 16 if word else 32
        mask = (1 << bits) - 1
        alu = {0x01: "add", 0x03: "add", 0x29: "sub", 0x2B: "sub", 0x31: "xor", 0x33: "xor",
               0x21: "and", 0x23: "and", 0x09: "or", 0x0B: "or", 0x89: "mov", 0x8B: "mov"}
        if op in alu:
            dest, source = (rm, reg) if op & 2 == 0 else (reg, rm)
            if alu[op] != "mov":
                flags = _flags(alu[op], regs[dest], regs[source], bits)
            regs[dest] = width_fix(_alu(alu[op], regs[dest], regs[source]), w)
            continue
        if op in (0x39, 0x3B, 0x85):  # cmp r/m,r | cmp r,r/m | test r/m,r
            first, second = (rm, reg) if op != 0x3B else (reg, rm)
            flags = _flags("and" if op == 0x85 else "sub", regs[first], regs[second], bits)
            continue
        if op in (0x81, 0x83, 0xC7):
            size = 1 if op == 0x83 else 2 if word else 4
            imm = int.from_bytes(code[at:at + size], "little", signed=True)
            at += size
            kind = "mov" if op == 0xC7 else {0: "add", 1: "or", 4: "and", 5: "sub", 6: "xor", 7: "cmp"}.get((modrm >> 3) & 7)
            if kind is None:
                raise Unsupported("x86-64 add/sub with carry")
            if kind == "cmp":
                flags = _flags("sub", regs[rm], imm & mask, bits)
                continue
            if kind != "mov":
                flags = _flags(kind, regs[rm], imm & mask, bits)
            regs[rm] = width_fix(_alu(kind, regs[rm], imm & mask), w)
            continue
        if op in (0x0FB6, 0x0FB7, 0x0FBE, 0x0FBF, 0x63):  # movzx / movsx / movsxd
            if op in (0x0FB6, 0x0FBE):
                value, size = byte_reg(rm, rex), 8
            elif op == 0x63:
                value, size = regs[rm] & M32, 32
            else:
                value, size = regs[rm] & 0xFFFF, 16
            if op != 0x0FB6 and op != 0x0FB7 and value >> (size - 1):
                value -= 1 << size
            regs[reg] = width_fix(value, w)
            continue
        if 0x0F40 <= op <= 0x0F4F:  # cmovcc (32-bit form zero-extends even when not taken)
            regs[reg] = width_fix(regs[rm] if _condition(op - 0x0F40, flags) else regs[reg], w)
            continue
        if 0x0F90 <= op <= 0x0F9F:  # setcc r/m8
            if not rex and rm >= 4:
                raise Unsupported("x86-64 setcc into ah..bh")
            regs[rm] = (regs[rm] & ~0xFF) | int(_condition(op - 0x0F90, flags))
            continue
        if op == 0x0FAF:
            regs[reg] = width_fix(regs[reg] * regs[rm], w)
            continue
        if op in (0x69, 0x6B):
            size = 1 if op == 0x6B else 4
            imm = int.from_bytes(code[at:at + size], "little", signed=True)
            at += size
            regs[reg] = width_fix(regs[rm] * imm, w)
            continue
        if op in (0xC1, 0xD1, 0xD3):
            if op == 0xC1:
                count = code[at]
                at += 1
            else:
                count = 1 if op == 0xD1 else regs[1] & 0xFF
            count &= bits - 1
            value = regs[rm] & mask
            kind = (modrm >> 3) & 7
            if kind == 0:
                value = ((value << count) | (value >> (bits - count))) & mask if count else value
            elif kind == 1:
                value = ((value >> count) | (value << (bits - count))) & mask if count else value
            elif kind == 4:
                value = (value << count) & mask
            elif kind == 5:
                value >>= count
            elif kind == 7:
                value = (s64(value) if w else s32(value)) >> count & mask
            else:
                raise Unsupported("x86-64 rotate through carry")
            regs[rm] = value
            continue
        if op == 0xF7 and (modrm >> 3) & 7 == 0:  # test r/m, imm32
            size = 2 if word else 4
            imm = int.from_bytes(code[at:at + size], "little", signed=True)
            at += size
            flags = _flags("and", regs[rm], imm & mask, bits)
            continue
        if op == 0xF7 and (modrm >> 3) & 7 in (2, 3):
            regs[rm] = width_fix(~regs[rm] if (modrm >> 3) & 7 == 2 else -regs[rm], w)
            continue
        raise Unsupported(f"x86-64 opcode 0x{op:x}")
    raise Unsupported("x86-64 function too long")


def _alu(kind: str, a: int, b: int) -> int:
    return {"add": a + b, "sub": a - b, "xor": a ^ b, "and": a & b, "or": a | b, "mov": b}[kind]


def jni_name(cls: str, method: str) -> str:
    def mangle(text: str) -> str:
        out = []
        for char in text:
            if char == "/":
                out.append("_")
            elif char == "_":
                out.append("_1")
            elif char == ";":
                out.append("_2")
            elif char == "[":
                out.append("_3")
            elif char.isascii() and char.isalnum():
                out.append(char)
            else:
                out.append(f"_0{ord(char):04x}")
        return "".join(out)
    return f"Java_{mangle(cls[1:-1])}_{mangle(method)}"


# --- The interpreter ---------------------------------------------------------------------------

_ARRAY_KINDS = "ijozbcs"  # aget, -wide, -object, -boolean, -byte, -char, -short (same order for aput, iget, sget)


class Machine:
    def __init__(self, dexes: list[Dex], natives: dict[str, bytes] | None = None, package: str | None = None,
                 apk: bytes | None = None) -> None:
        self.classes: dict[str, ClassDef] = {}
        self.dexes: list[Dex] = []
        self.load(dexes)
        self.natives = natives or {}
        self.context = Context(package, apk)
        self.statics: dict[tuple[str, str], Any] = {}
        self.initialized: set[str] = set()
        self.steps = 0

    def load(self, dexes: list[Dex]) -> None:
        """classes*.dex, or a DEX the app loads itself: a class already defined keeps its definition."""
        for dex in dexes:
            if not any(known is dex for known in self.dexes):
                self.dexes.append(dex)
                for name, definition in dex.classes.items():
                    self.classes.setdefault(name, definition)

    def _init_class(self, cls: str) -> None:
        if cls in self.initialized or cls not in self.classes:
            return
        self.initialized.add(cls)
        definition = self.classes[cls]
        if definition.superclass:
            self._init_class(definition.superclass)
        for name, value in definition.static_defaults.items():
            self.statics[(cls, name)] = value
        clinit = definition.methods.get(("<clinit>", "()V"))
        if clinit is not None:
            self.call(clinit, [])

    def find(self, cls: str, name: str, sig: str) -> Method | None:
        while cls in self.classes:
            method = self.classes[cls].methods.get((name, sig))
            if method is not None:
                return method
            cls = self.classes[cls].superclass or ""
        return None

    def invoke(self, cls: str, name: str, sig: str, args: list[Any], virtual: bool) -> Any:
        if virtual and args and isinstance(args[0], JObject):
            cls = args[0].cls
        method = self.find(cls, name, sig)
        if method is None:
            return _platform(cls, name, sig, args, self)
        if method.flags & ACC_STATIC:
            self._init_class(method.cls)
        return self.call(method, args)

    def call(self, method: Method, args: list[Any]) -> Any:
        if method.flags & ACC_NATIVE:
            return self._native(method, args)
        if not method.insns:
            raise Unsupported(f"no code for {method.cls}->{method.name}")
        regs: list[Any] = [None] * method.registers
        at = method.registers - method.ins
        for value, kind in zip(args, ([] if method.flags & ACC_STATIC else ["L"]) + method.params):
            regs[at] = value
            at += 2 if kind in ("J", "D") else 1
        return self._run(method, regs)

    def _native(self, method: Method, args: list[Any]) -> Any:
        symbol = jni_name(method.cls, method.name)
        if symbol not in self.natives:
            raise Unsupported(f"native {symbol}")
        if not all(kind in ("J", "I") for kind in method.params) or method.ret not in ("J", "I"):
            raise Unsupported("native signature")
        statics = method.flags & ACC_STATIC
        values = [0, 0] + list(args if statics else args[1:])  # JNIEnv*, jclass/jobject
        result = run_x64(self.natives[symbol], values, wide=method.ret == "J")
        return s64(result) if method.ret == "J" else s32(result)

    def _arguments(self, regs: list[Any], registers: list[int], params: list[str], static: bool) -> list[Any]:
        out, index = [], 0
        if not static:
            out.append(regs[registers[0]])
            index = 1
        for kind in params:
            out.append(regs[registers[index]])
            index += 2 if kind in ("J", "D") else 1
        return out

    def _run(self, method: Method, regs: list[Any]) -> Any:
        code, dex = method.insns, self._dex_of(method)
        pc, result = 0, None
        while True:
            self.steps += 1
            if self.steps > MAX_STEPS:
                raise Unsupported("step limit")
            word = code[pc]
            op = word & 0xFF
            a = word >> 8
            if op == 0x00:
                pc += 1
            elif 0x01 <= op <= 0x09:  # move, move-wide, move-object (12x, 22x, 32x)
                form = (op - 1) % 3
                if form == 0:
                    regs[a & 0xF] = regs[a >> 4]
                    pc += 1
                elif form == 1:
                    regs[a] = regs[code[pc + 1]]
                    pc += 2
                else:
                    regs[code[pc + 1]] = regs[code[pc + 2]]
                    pc += 3
            elif 0x0A <= op <= 0x0C:
                regs[a] = result
                pc += 1
            elif op == 0x0E:
                return None
            elif 0x0F <= op <= 0x11:
                return regs[a]
            elif op == 0x12:
                value = a >> 4
                regs[a & 0xF] = value - 16 if value > 7 else value
                pc += 1
            elif op == 0x13 or op == 0x16:
                regs[a] = struct.unpack("<h", struct.pack("<H", code[pc + 1]))[0]
                pc += 2
            elif op == 0x14 or op == 0x17:
                regs[a] = s32(code[pc + 1] | code[pc + 2] << 16)
                pc += 3
            elif op == 0x15:
                regs[a] = s32(code[pc + 1] << 16)
                pc += 2
            elif op == 0x18:
                regs[a] = s64(code[pc + 1] | code[pc + 2] << 16 | code[pc + 3] << 32 | code[pc + 4] << 48)
                pc += 5
            elif op == 0x19:
                regs[a] = s64(code[pc + 1] << 48)
                pc += 2
            elif op == 0x1A:
                regs[a] = dex.strings[code[pc + 1]]
                pc += 2
            elif op == 0x1B:
                regs[a] = dex.strings[code[pc + 1] | code[pc + 2] << 16]
                pc += 3
            elif op == 0x1C:
                regs[a] = JClass(dex.types[code[pc + 1]])
                pc += 2
            elif op in (0x1D, 0x1E):
                pc += 1
            elif op == 0x1F:
                pc += 2
            elif op == 0x20:
                value, kind = regs[a >> 4], dex.types[code[pc + 1]]
                regs[a & 0xF] = int(isinstance(value, JObject) and self._is_a(value.cls, kind)
                                    or isinstance(value, str) and kind == "Ljava/lang/String;")
                pc += 2
            elif op == 0x21:
                regs[a & 0xF] = len(regs[a >> 4])
                pc += 1
            elif op == 0x22:
                kind = dex.types[code[pc + 1]]
                if kind in ("Ljava/lang/StringBuilder;", "Ljava/lang/StringBuffer;"):
                    regs[a] = Builder()
                elif kind == "Ljava/util/zip/CRC32;":
                    regs[a] = Crc()
                elif kind == "Ljava/io/ByteArrayOutputStream;":
                    regs[a] = Sink()
                elif kind == "Ldalvik/system/InMemoryDexClassLoader;":
                    regs[a] = Loader()
                elif kind in self.classes:
                    self._init_class(kind)
                    regs[a] = JObject(kind)
                    for name, field_kind in self._instance_fields(kind):
                        regs[a].fields[name] = _default(field_kind)
                elif kind in ("Ljava/lang/String;", "Ljava/lang/Object;"):
                    regs[a] = Pending(kind)
                elif kind in _PLATFORM_NEW:
                    regs[a] = _PLATFORM_NEW[kind]()
                else:
                    raise Unsupported(f"new {kind}")
                pc += 2
            elif op == 0x23:
                kind = dex.types[code[pc + 1]]
                regs[a & 0xF] = [_default(kind[1:])] * regs[a >> 4]
                pc += 2
            elif op in (0x24, 0x25):
                registers = self._registers(code, pc, op == 0x25)
                kind = dex.types[code[pc + 1]]
                result = [regs[r] for r in registers]
                pc += 3
            elif op == 0x26:
                offset = s32(code[pc + 1] | code[pc + 2] << 16)
                table = pc + offset
                width = code[table + 1]
                count = code[table + 2] | code[table + 3] << 16
                raw = struct.pack(f"<{(width * count + 1) // 2 + 1}H", *code[table + 4:table + 4 + (width * count + 1) // 2 + 1])
                fmt = {1: "b", 2: "h", 4: "i", 8: "q"}[width]
                regs[a][:count] = list(struct.unpack_from(f"<{count}{fmt}", raw))
                pc += 3
            elif op == 0x27:
                raise Unsupported("throw")
            elif op == 0x28:
                pc += a - 256 if a > 127 else a
            elif op == 0x29:
                pc += struct.unpack("<h", struct.pack("<H", code[pc + 1]))[0]
            elif op == 0x2A:
                pc += s32(code[pc + 1] | code[pc + 2] << 16)
            elif op in (0x2B, 0x2C):
                table = pc + s32(code[pc + 1] | code[pc + 2] << 16)
                size = code[table + 1]
                value = regs[a]
                jump = 3
                if op == 0x2B:
                    first = s32(code[table + 2] | code[table + 3] << 16)
                    if 0 <= value - first < size:
                        index = table + 4 + 2 * (value - first)
                        jump = s32(code[index] | code[index + 1] << 16)
                else:
                    for index in range(size):
                        key = s32(code[table + 2 + 2 * index] | code[table + 3 + 2 * index] << 16)
                        if key == value:
                            target = table + 2 + 2 * size + 2 * index
                            jump = s32(code[target] | code[target + 1] << 16)
                            break
                pc += jump
            elif 0x2D <= op <= 0x31:
                left, right = regs[code[pc + 1] & 0xFF], regs[code[pc + 1] >> 8]
                if left != left or right != right:  # NaN
                    regs[a] = 1 if op in (0x2E, 0x30) else -1
                else:
                    regs[a] = (left > right) - (left < right)
                pc += 2
            elif 0x32 <= op <= 0x37:
                left, right = regs[a & 0xF], regs[a >> 4]
                if self._test(op - 0x32, left, right):
                    pc += struct.unpack("<h", struct.pack("<H", code[pc + 1]))[0]
                else:
                    pc += 2
            elif 0x38 <= op <= 0x3D:
                value = regs[a]
                value = 0 if value is None or value is False else 1 if not isinstance(value, (int, float)) else value
                if self._test(op - 0x38, value, 0):
                    pc += struct.unpack("<h", struct.pack("<H", code[pc + 1]))[0]
                else:
                    pc += 2
            elif 0x44 <= op <= 0x51:
                array, index = regs[code[pc + 1] & 0xFF], regs[code[pc + 1] >> 8]
                if op <= 0x4A:
                    regs[a] = array[index]
                else:
                    value = regs[a]
                    kind = _ARRAY_KINDS[op - 0x4B]
                    array[index] = s32(value) if kind == "i" else ((value + 128) & 0xFF) - 128 if kind == "b" \
                        else value & 0xFFFF if kind == "c" else ((value + 32768) & 0xFFFF) - 32768 if kind == "s" else value
                pc += 2
            elif 0x52 <= op <= 0x5F:
                _, _, name = dex.fields[code[pc + 1]]
                target = regs[a >> 4]
                if not isinstance(target, JObject):
                    raise Unsupported("instance field of a platform object")
                if op <= 0x58:
                    regs[a & 0xF] = target.fields.get(name)
                else:
                    target.fields[name] = regs[a & 0xF]
                pc += 2
            elif 0x60 <= op <= 0x6D:
                cls, _, name = dex.fields[code[pc + 1]]
                if cls in _PRIMITIVE_TYPES and name == "TYPE" and op <= 0x66:
                    regs[a] = JClass(_PRIMITIVE_TYPES[cls])  # Long.TYPE -> "J": a reflective lookup's parameter
                    pc += 2
                    continue
                if cls not in self.classes:
                    if op <= 0x66 and (cls, name) in _PLATFORM_STATICS:
                        regs[a] = _PLATFORM_STATICS[(cls, name)]
                        pc += 2
                        continue
                    raise Unsupported(f"static field {cls}->{name}")
                self._init_class(cls)
                owner = self._field_owner(cls, name)
                if op <= 0x66:
                    regs[a] = self.statics.get((owner, name))
                else:
                    self.statics[(owner, name)] = regs[a]
                pc += 2
            elif 0x6E <= op <= 0x72 or 0x74 <= op <= 0x78:
                ranged = op >= 0x74
                kind = op - (0x74 if ranged else 0x6E)
                cls, name, params, ret = dex.methods[code[pc + 1]]
                registers = self._registers(code, pc, ranged)
                args = self._arguments(regs, registers, params, kind == 3)
                sig = f"({''.join(params)}){ret}"
                result = self.invoke(cls, name, sig, args, kind in (0, 4))
                if name == "<init>" and isinstance(args[0], Pending):
                    placeholder = args[0]
                    built = result if placeholder.cls == "Ljava/lang/String;" else JObject(placeholder.cls)
                    for index, value in enumerate(regs):
                        if value is placeholder:
                            regs[index] = built
                pc += 3
            elif 0x7B <= op <= 0x8F:
                regs[a & 0xF] = _unary(op, regs[a >> 4])
                pc += 1
            elif 0x90 <= op <= 0xAF:
                left, right = regs[code[pc + 1] & 0xFF], regs[code[pc + 1] >> 8]
                regs[a] = _binary(op - 0x90, left, right)
                pc += 2
            elif 0xB0 <= op <= 0xCF:
                regs[a & 0xF] = _binary(op - 0xB0, regs[a & 0xF], regs[a >> 4])
                pc += 1
            elif 0xD0 <= op <= 0xD7:
                literal = struct.unpack("<h", struct.pack("<H", code[pc + 1]))[0]
                kind = op - 0xD0
                regs[a & 0xF] = _binary((0, 1, 2, 3, 4, 5, 6, 7)[kind], regs[a >> 4], literal, reverse=kind == 1)
                pc += 2
            elif 0xD8 <= op <= 0xE2:
                source, literal = code[pc + 1] & 0xFF, code[pc + 1] >> 8
                literal = literal - 256 if literal > 127 else literal
                kind = op - 0xD8
                regs[a] = _binary((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)[kind], regs[source], literal, reverse=kind == 1)
                pc += 2
            else:
                raise Unsupported(f"opcode 0x{op:02x}")

    def _registers(self, code: tuple[int, ...], pc: int, ranged: bool) -> list[int]:
        word = code[pc]
        if ranged:
            return list(range(code[pc + 2], code[pc + 2] + (word >> 8)))
        count, last = word >> 12, (word >> 8) & 0xF
        packed = code[pc + 2]
        return [packed & 0xF, (packed >> 4) & 0xF, (packed >> 8) & 0xF, packed >> 12, last][:count]

    @staticmethod
    def _test(kind: int, left: Any, right: Any) -> bool:
        if kind == 0:
            return left is right if not isinstance(left, (int, float)) else left == right
        if kind == 1:
            return left is not right if not isinstance(left, (int, float)) else left != right
        return (left < right, left >= right, left > right, left <= right)[kind - 2]

    def _dex_of(self, method: Method) -> Dex:
        for dex in self.dexes:
            if dex.classes.get(method.cls) is self.classes.get(method.cls):
                return dex
        return self.dexes[0]

    def _is_a(self, cls: str, kind: str) -> bool:
        while cls:
            if cls == kind:
                return True
            cls = self.classes[cls].superclass if cls in self.classes else ""
        return False

    def _instance_fields(self, cls: str) -> list[tuple[str, str]]:
        fields = []
        while cls in self.classes:
            fields += self.classes[cls].instance_fields
            cls = self.classes[cls].superclass or ""
        return fields

    def _field_owner(self, cls: str, name: str) -> str:
        current = cls
        while current in self.classes:
            if name in self.classes[current].static_defaults:
                return current
            current = self.classes[current].superclass or ""
        return cls


def _unary(op: int, value: Any) -> Any:
    if op == 0x7B:
        return s32(-value)
    if op == 0x7C:
        return s32(~value)
    if op == 0x7D:
        return s64(-value)
    if op == 0x7E:
        return s64(~value)
    if op in (0x7F, 0x80):
        return -value
    if op == 0x81:
        return value
    if op in (0x82, 0x83, 0x85, 0x86, 0x89, 0x8C):
        return float(value)
    if op == 0x84:
        return s32(value)
    if op in (0x87, 0x8A):
        return 0 if value != value else max(-(1 << 31), min((1 << 31) - 1, int(value)))
    if op in (0x88, 0x8B):
        return 0 if value != value else max(-(1 << 63), min((1 << 63) - 1, int(value)))
    if op == 0x8D:
        return ((value + 128) & 0xFF) - 128
    if op == 0x8E:
        return value & 0xFFFF
    if op == 0x8F:
        return ((value + 32768) & 0xFFFF) - 32768
    raise Unsupported(f"unary 0x{op:02x}")


def _binary(kind: int, left: Any, right: Any, reverse: bool = False) -> Any:
    """kind: 0-10 int, 11-21 long, 22-26 float, 27-31 double (Dalvik's binop order)."""
    if reverse:  # rsub-int: literal - value
        return s32(right - left)
    if kind >= 22:
        operation = (kind - 22) % 5
        if operation == 3 and right == 0:
            return float("inf") if left > 0 else float("-inf") if left < 0 else float("nan")
        value = (left + right, left - right, left * right, left / right if right else 0.0,
                 math.fmod(left, right) if right else float("nan"))[operation]
        return struct.unpack("<f", struct.pack("<f", value))[0] if kind < 27 else value
    wide = kind >= 11
    operation = kind - 11 if wide else kind
    bits, fix = (64, s64) if wide else (32, s32)
    if operation == 0:
        return fix(left + right)
    if operation == 1:
        return fix(left - right)
    if operation == 2:
        return fix(left * right)
    if operation in (3, 4):
        if right == 0:
            raise Unsupported("ArithmeticException")
        quotient = abs(left) // abs(right) * (1 if (left >= 0) == (right >= 0) else -1)
        return fix(quotient if operation == 3 else left - right * quotient)
    if operation == 5:
        return fix(left & right)
    if operation == 6:
        return fix(left | right)
    if operation == 7:
        return fix(left ^ right)
    shift = right & (bits - 1)
    if operation == 8:
        return fix(left << shift)
    if operation == 9:
        return fix(left >> shift)
    return fix((left & (M64 if wide else M32)) >> shift)


# --- Entry point ----------------------------------------------------------------------------------

def answer_code(apk_bytes: bytes, package: str | None = None) -> str | None:
    """The app's computed answer code (Release.code and similar), or None when it cannot be derived."""
    try:
        with zipfile.ZipFile(BytesIO(apk_bytes)) as apk:
            names = apk.namelist()
            dexes = [Dex(read_member(apk, name)) for name in sorted(names) if re.fullmatch(r"classes\d*\.dex", name)]
            libraries = [read_member(apk, name) for name in names if name.startswith("lib/x86_64/") and name.endswith(".so")]
    except (*ZIP_ERRORS, KeyError, struct.error, IndexError, UnicodeDecodeError, Unsupported):
        return None
    if not dexes:
        return None
    natives: dict[str, bytes] = {}
    for dex in dexes:
        for definition in dex.classes.values():
            for method in definition.methods.values():
                if method.flags & ACC_NATIVE:
                    symbol = jni_name(method.cls, method.name)
                    for library in libraries:
                        try:
                            body = elf_symbol(library, symbol)
                        except (struct.error, IndexError, ValueError):
                            body = None
                        if body:
                            natives[symbol] = body
                            break
    machine = Machine(dexes, natives, package, apk_bytes)
    candidates = []
    for definition in machine.classes.values():
        for method in definition.methods.values():
            if (method.flags & ACC_STATIC and method.ret == "Ljava/lang/String;"
                    and all(kind == "Landroid/content/Context;" for kind in method.params)):
                rank = (0 if definition.name.endswith("/Release;") and method.name == "code" else
                        1 if method.name in ("code", "answer", "answerCode", "release") else 2)
                candidates.append((rank, definition.name, method))
    found = set()
    for rank, _, method in sorted(candidates, key=lambda item: item[:2]):
        if rank == 2 and found:
            break
        try:
            machine._init_class(method.cls)
            value = machine.call(method, [machine.context] * len(method.params))
        except (Unsupported, RecursionError, IndexError, KeyError, TypeError, AttributeError, ValueError,
                ZeroDivisionError, OverflowError, struct.error):
            continue
        if isinstance(value, str) and ANSWER.fullmatch(value):
            found.add(value)
            if rank == 0:
                break
    return found.pop() if len(found) == 1 else None
