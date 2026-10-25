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
            if isinstance(source, list) and sig.startswith("([C"):
                return "".join(chr(c) for c in source)
            if isinstance(source, list):
                return _bytes(source).decode("utf-8", "replace")
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
            return _signed_bytes(text.encode("utf-8"))
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
    for handler in (_secondary_dex, _reflection):
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
