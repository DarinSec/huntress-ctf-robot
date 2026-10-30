"""Mobile Android: the answer code an app's assets/huntress_puzzle.json encodes.

Day 20 and 21 apps carry {"schema": "huntress.mobile.puzzle.v1", "codec": ..., "data": ...};
the backend answer code is the data decoded by the codec ("reverse" on day 21:
"FEDCBA9876543210-SNA" -> "ANS-0123456789ABCDEF", CORRECT live). Mastery bundles earlier
days' codecs: "split" puts parts[i] at position order[i], "reflection" carries the code
as is, "dynamic" names a payload DEX that holds it. Unknown codecs get the value as is,
reversed, and one strict layer from decoders.py, and a key that steps by position is read
off the known "ANS-" prefix (day 29 "table").
Day 23 ("huntress.mobile.puzzle.v2", codec "analysis") carries no data: the code is computed
by the app's Java (Release.code), so dexvm.py emulates that bytecode (and a JNI long f(long)
from lib/x86_64) without running the app. A puzzle whose data decodes to nothing is tried the
same way, and as a last resort a code the app ships as text in any member is read.
Only a value that is exactly an answer code ("ANS-" + 16 uppercase hex) is returned.
"""

from __future__ import annotations

import base64
import binascii
import codecs
from io import BytesIO
import json
import re
import zipfile

from .. import dexvm, formats
from ..containers import ZIP_ERRORS, read_member
from ..decoders import LAYERS
from .base import AnswerCandidate, SolveContext, fits_format, question_items

ANSWER = re.compile(r"ANS-[0-9A-F]{16}")
_PACKAGE = re.compile(r"\bin package ([A-Za-z0-9_.]+)")
_IN_TEXT = re.compile(rb"ANS-[0-9A-F]{16}")
MAX_MEMBER_BYTES = 8 * 1024 * 1024  # A code is a string; whole libraries are not read.


def _split(puzzle: dict) -> set[str]:
    parts, order = puzzle.get("parts"), puzzle.get("order")
    if not (isinstance(parts, list) and isinstance(order, list) and sorted(order) == list(range(len(parts)))):
        return set()
    placed = [""] * len(parts)
    for part, position in zip(parts, order):
        placed[position] = str(part)
    return {"".join(placed), "".join(str(parts[index]) for index in order)}  # Both readings of "order".


def _decoded(codec: str, data: str, apk: zipfile.ZipFile, puzzle: dict) -> set[str]:
    codec = codec.lower()
    found: set[str] = set()
    if codec == "split":
        found |= _split(puzzle)
    elif codec in ("reflection", "plain", "none", "identity"):
        found.add(data)
    elif codec == "reverse":
        found.add(data[::-1])
    elif codec == "rot13":
        found.add(codecs.decode(data, "rot13"))
    elif codec in ("hex", "base16"):
        try:
            found.add(bytes.fromhex(data).decode("utf-8", "replace"))
        except ValueError:
            pass
    elif codec in ("base64", "b64"):
        try:
            found.add(base64.b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "replace"))
        except (binascii.Error, ValueError):
            pass
    elif codec == "base32":
        try:
            found.add(base64.b32decode(data + "=" * (-len(data) % 8)).decode("utf-8", "replace"))
        except (binascii.Error, ValueError):
            pass
    elif codec == "caesar" and isinstance(puzzle.get("key"), int):
        # Every character moved by key code points (day 7, key 15: "P]b<" -> "ANS-").
        for shift in (-puzzle["key"], puzzle["key"]):
            if all(0 <= ord(char) + shift < 0x110000 for char in data):
                found.add("".join(chr(ord(char) + shift) for char in data))
    elif codec == "xor" and isinstance(puzzle.get("key"), int):
        # Base64 of the code's bytes XORed with one key byte (days 4, 11 and 18).
        try:
            raw = base64.b64decode(data, validate=True)
        except (binascii.Error, ValueError):
            raw = b""
        found.add(bytes(byte ^ (puzzle["key"] & 0xFF) for byte in raw).decode("latin-1"))
    elif codec == "indexed":
        # data[i] belongs at position order[i] (day 17); both readings, as for "split".
        order = puzzle.get("order")
        if isinstance(order, list) and sorted(order) == list(range(len(data))):
            placed = [""] * len(data)
            for char, position in zip(data, order):
                placed[position] = char
            found |= {"".join(placed), "".join(data[index] for index in order)}
    elif codec == "dynamic" and data in apk.namelist():
        found.update(match.decode() for match in _IN_TEXT.findall(read_member(apk, data)))
    elif codec == "rot47":
        found.add(_rot47(data))
    elif codec == "atbash":
        found.add(_atbash(data))
    elif codec == "vigenere" and isinstance(puzzle.get("key"), str) and puzzle["key"].isalpha():
        found |= {_vigenere(data, puzzle["key"], sign) for sign in (-1, 1)}
    elif codec == "xor" and isinstance(puzzle.get("key"), str) and puzzle["key"]:
        # Repeating string key over Base64 or hex bytes (anticipated: days so far used one key byte).
        key = puzzle["key"].encode()
        for raw in _raw_bytes(data):
            found.add(bytes(byte ^ key[i % len(key)] for i, byte in enumerate(raw)).decode("latin-1"))
    elif codec == "base58":
        found.add(_base58(data))
    elif codec == "packet":
        found |= _packets(data)
    elif codec == "layered" and isinstance(puzzle.get("key"), int):
        # Day 30: Base64 of the code's bytes XORed with (key + index), then reversed. The
        # neighbouring orders are read too; only an exact ANS- code survives the caller.
        key = puzzle["key"]
        for raw in _raw_bytes(data):
            stepped = bytes(byte ^ ((key + i) & 0xFF) for i, byte in enumerate(raw))
            backwards = bytes(byte ^ ((key + i) & 0xFF) for i, byte in enumerate(raw[::-1]))
            flat = bytes(byte ^ (key & 0xFF) for byte in raw)
            for candidate in (stepped[::-1], backwards, flat[::-1], stepped, flat):
                found.add(candidate.decode("latin-1"))
    elif codec == "table":
        found |= _progression(data)
    else:
        found |= _search(data) | _split(puzzle) | _progression(data)
    return {value.strip() for value in found}


# --- Codecs no day has used yet, and a bounded search for unknown codec names --------------------
# Only a result that is exactly an answer code is ever kept, so trying more never invents one.

def _rot47(text: str) -> str:
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in text)


def _atbash(text: str) -> str:
    return "".join(chr(ord("Z") - ord(c) + ord("A")) if "A" <= c <= "Z" else
                   chr(ord("z") - ord(c) + ord("a")) if "a" <= c <= "z" else c for c in text)


def _vigenere(text: str, key: str, sign: int) -> str:
    out, index = [], 0
    for char in text:
        if char.isascii() and char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shift = ord(key[index % len(key)].upper()) - ord("A")
            out.append(chr((ord(char) - base + sign * shift) % 26 + base))
            index += 1
        else:
            out.append(char)
    return "".join(out)


_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58(text: str) -> str:
    if not text or any(c not in _BASE58 for c in text):
        return ""
    number = 0
    for char in text:
        number = number * 58 + _BASE58.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return (b"\0" * (len(text) - len(text.lstrip("1"))) + raw).decode("latin-1")


def _raw_bytes(text: str) -> list[bytes]:
    out = []
    try:
        out.append(base64.b64decode(text + "=" * (-len(text) % 4), validate=True))
    except (binascii.Error, ValueError):
        pass
    try:
        out.append(bytes.fromhex(text))
    except ValueError:
        pass
    return out


def _frames(raw: bytes) -> list[bytes] | None:
    """Payloads of back-to-back frames: magic (2 bytes), length byte, payload, XOR check byte.

    The check byte is the XOR of every byte before it in its frame; one bad check or a
    frame that runs past the end rejects the whole stream (None).
    """
    payloads, i = [], 0
    while i < len(raw):
        if raw[i:i + 2] != raw[:2] or i + 3 > len(raw):
            return None
        end = i + 3 + raw[i + 2]
        if end >= len(raw):
            return None
        check = 0
        for byte in raw[i:end]:
            check ^= byte
        if check != raw[end]:
            return None
        payloads.append(raw[i + 3:end])
        i = end + 1
    return payloads or None


def _packets(data: str) -> set[str]:
    """Day 28 "packet": hex of one framed message, "HA" + 0x14 + "ANS-0000000000000028" + 0x11.

    A code is a verified frame's payload, or all payloads joined in order; a stream
    that does not parse as frames falls back to the codes in its bytes.
    """
    found: set[str] = set()
    for raw in _raw_bytes(data):
        payloads = _frames(raw)
        if payloads:
            found.update(payload.decode("latin-1") for payload in payloads)
            found.add(b"".join(payloads).decode("latin-1"))
        else:
            found.update(match.decode() for match in _IN_TEXT.findall(raw))
    return found


_PREFIX = b"ANS-"


def _progression(data: str) -> set[str]:
    """Bytes moved or XORed by key + step * position, the key and step read off the "ANS-" prefix.

    Day 29 "table": hex of (code[i] + 41 + 3 * i) mod 256 with "key": 41, the step only in the
    bytes. Every code starts "ANS-", so its first four bytes give any key and step; a stream
    whose four offsets do not step evenly gives nothing.
    """
    found: set[str] = set()
    for raw in _raw_bytes(data) + [data.encode("latin-1", "replace")]:
        if len(raw) != 20:  # "ANS-" + 16 hex digits.
            continue
        for undo in (lambda byte, key: (byte - key) & 0xFF, lambda byte, key: byte ^ key):
            keys = [undo(raw[i], _PREFIX[i]) for i in range(4)]
            step = (keys[1] - keys[0]) & 0xFF
            if all((keys[i] - keys[i - 1]) & 0xFF == step for i in (2, 3)):
                found.add(bytes(undo(byte, (keys[0] + step * i) & 0xFF) for i, byte in enumerate(raw)).decode("latin-1"))
    return found


def _steps(text: str) -> set[str]:
    """One decoding step: every strict layer, plus the keyless text transforms."""
    out = {text[::-1], codecs.decode(text, "rot13"), _rot47(text), _atbash(text), _base58(text)}
    for _, layer in LAYERS:
        decoded = layer(text.encode())
        if decoded:
            out.add(decoded.decode("utf-8", "replace"))
    return {value for value in out if value and len(value) <= 4096}


def _search(data: str) -> set[str]:
    """Up to two steps, then every Caesar shift and single-byte XOR of the results' bytes."""
    seen = {data}
    frontier = {data}
    for _ in range(2):
        frontier = {value for text in frontier for value in _steps(text)} - seen
        seen |= frontier
    found = {value for value in seen if ANSWER.fullmatch(value.strip())}
    if found:
        return found
    for text in seen:
        if len(text) > 256:
            continue
        for shift in range(1, 26):
            moved = "".join(chr((ord(c) - 65 + shift) % 26 + 65) if "A" <= c <= "Z" else c for c in text)
            if ANSWER.fullmatch(moved):
                found.add(moved)
        for raw in _raw_bytes(text) + [text.encode("latin-1", "replace")]:
            for key in range(1, 256):
                candidate = bytes(byte ^ key for byte in raw)
                if _IN_TEXT.fullmatch(candidate):
                    found.add(candidate.decode())
    return found


def _in_app(apk: zipfile.ZipFile) -> set[str]:
    """Every answer code the app ships as text, for an asset that carries no payload.

    The last resort, after the asset's own data and the emulated code: where the app
    holds the code as a string (a DEX string, a resource, another asset) reading it is
    deterministic, and where the code has to be computed nothing matches, so the question
    stays unanswered rather than guessed. NUL bytes are dropped so a UTF-16LE string
    reads as text too.
    """
    found: set[str] = set()
    for item in apk.infolist():
        if item.is_dir() or item.file_size > MAX_MEMBER_BYTES:
            continue
        data = read_member(apk, item)
        found.update(match.decode() for match in _IN_TEXT.findall(data))
        if b"\0" in data:
            found.update(match.decode() for match in _IN_TEXT.findall(data.replace(b"\0", b"")))
    return found


def answer_code(apk_bytes: bytes, feature_parts: dict[int, str] | None = None,
                splits: list[bytes] | None = None) -> str | None:
    """The one answer code the APK's puzzle asset decodes to, or None.

    feature_parts fills the empty "split" parts a base APK leaves to its feature splits, and splits
    are those split APKs for code that opens them (splitSourceDirs; both day 26).
    """
    try:
        with zipfile.ZipFile(BytesIO(apk_bytes)) as apk:
            names = [name for name in apk.namelist() if name.endswith("huntress_puzzle.json")]
            if len(names) != 1:
                return None
            puzzle = json.loads(read_member(apk, names[0]))
            if not isinstance(puzzle, dict):
                return None
            if feature_parts and isinstance(puzzle.get("parts"), list):
                puzzle["parts"] = [feature_parts.get(i, part) if part == "" else part
                                   for i, part in enumerate(puzzle["parts"])]
            codes: set[str] = set()
            if isinstance(puzzle.get("data"), str):
                codes = {value for value in _decoded(str(puzzle.get("codec", "")), puzzle["data"], apk, puzzle)
                         if ANSWER.fullmatch(value)}
            literal = _in_app(apk) if not codes else set()  # Read while the zip is open.
    except (*ZIP_ERRORS, KeyError, UnicodeDecodeError):
        return None
    if not codes:
        manifest = formats.apk(apk_bytes) or {}
        computed = dexvm.answer_code(apk_bytes, manifest.get("package_name"), splits)
        # A code the app merely ships as text counts only where nothing computed one, so
        # a literal left in another member can never contradict the emulated answer.
        codes = {computed} if computed else literal
    return codes.pop() if len(codes) == 1 else None


def _apks(context: SolveContext) -> dict[str, bytes]:
    """Every APK in the assignment by base name: the artifact itself, or its members."""
    found = {}
    if context.artifact.startswith(b"PK"):
        try:
            with zipfile.ZipFile(BytesIO(context.artifact)) as archive:
                if "AndroidManifest.xml" in archive.namelist():
                    found["artifact"] = context.artifact
        except ZIP_ERRORS:
            pass
    for member in context.members:
        if member.name.endswith(".apk"):
            found[re.sub(r"^delivery \d+:\s*", "", member.name.rsplit("/", 1)[-1])] = member.data
    return found


def _package_apks(context: SolveContext, package: str) -> list[bytes]:
    """Every APK (artifact or member, split bundles included) whose manifest names the package."""
    blobs = [member.data for member in context.members if member.name.endswith(".apk")]
    if context.artifact.startswith(b"PK"):
        blobs.append(context.artifact)
    # A Mastery delivery can itself be an .apks bundle, kept whole by the unpacker: open it here.
    for data in [context.artifact] + [member.data for member in context.members if member.name.endswith(".apks")]:
        blobs.extend(_bundle_apks(data))
    unique = list({blob: None for blob in blobs})  # A bundle's APKs may also be unpacked members.
    return [blob for blob in unique if (formats.apk(blob) or {}).get("package_name") == package]


# An .aab module's directories and where an APK keeps them (bundletool's layout).
_AAB_PLACES = {"dex": "", "root": "", "manifest": "", "assets": "assets/", "lib": "lib/", "res": "res/"}
MAX_AAB_ENTRIES = 4096


def _bundle_apks(data: bytes) -> list[bytes]:
    """The split APKs inside an .apks bundle (a ZIP of APKs without its own manifest), or each
    module of an Android App Bundle (.aab: base/manifest/AndroidManifest.xml) as an APK, bounded."""
    if not data.startswith(b"PK"):
        return []
    try:
        with zipfile.ZipFile(BytesIO(data)) as bundle:
            names = bundle.namelist()
            if "AndroidManifest.xml" in names:
                return []
            modules = sorted({name.split("/", 1)[0] for name in names
                              if name.count("/") == 2 and name.endswith("/manifest/AndroidManifest.xml")})
            if modules and len(names) <= MAX_AAB_ENTRIES:
                return [_module_apk(bundle, names, module) for module in modules[:16]]
            return [read_member(bundle, name, MAX_MEMBER_BYTES) for name in names
                    if name.endswith(".apk") and not name.endswith("/")][:16]
    except (*ZIP_ERRORS, KeyError):
        return []


def _module_apk(bundle: zipfile.ZipFile, names: list[str], module: str) -> bytes:
    """One .aab module laid out as an APK: base/dex/classes.dex -> classes.dex, base/assets/x ->
    assets/x, base/manifest/AndroidManifest.xml -> AndroidManifest.xml (still protobuf)."""
    out = BytesIO()
    with zipfile.ZipFile(out, "w") as apk:
        for name in names:
            head, _, rest = name.partition("/")
            place, _, path = rest.partition("/")
            if head == module and place in _AAB_PLACES and path and not name.endswith("/"):
                apk.writestr(_AAB_PLACES[place] + path, read_member(bundle, name, MAX_MEMBER_BYTES))
    return out.getvalue()


def _with_asset(blob: bytes, suffix: str) -> list[str]:
    try:
        with zipfile.ZipFile(BytesIO(blob)) as apk:
            return [name for name in apk.namelist() if name.endswith(suffix)]
    except ZIP_ERRORS:
        return []


def _feature_parts(blobs: list[bytes]) -> dict[int, str]:
    """Day 26 split APKs: each feature split's assets/huntress_feature.json carries one part."""
    parts: dict[int, str] = {}
    for blob in blobs:
        for name in _with_asset(blob, "huntress_feature.json"):
            try:
                with zipfile.ZipFile(BytesIO(blob)) as apk:
                    feature = json.loads(read_member(apk, name))
            except (*ZIP_ERRORS, KeyError, UnicodeDecodeError, ValueError):
                continue
            if isinstance(feature, dict) and isinstance(feature.get("part_index"), int) \
                    and isinstance(feature.get("part"), str):
                parts[feature["part_index"]] = feature["part"]
    return parts


class MobilePuzzleSolver:
    name = "mobile-puzzle"
    lanes = frozenset({"mobile-android"})

    def solve(self, context: SolveContext) -> list[AnswerCandidate]:
        lane = context.challenge.get("lane") or context.challenge_id.split("-day-")[0]
        if lane not in self.lanes:
            return []
        apks = _apks(context)
        candidates = []
        for question in question_items(context):
            name = (question.artifact or "").rsplit("->", 1)[-1].strip().rsplit("/", 1)[-1]
            name = re.sub(r"^delivery \d+:\s*", "", name)
            blob = apks.get(name) or (apks.get("artifact") if len(apks) == 1 or name not in apks else None)
            # "For case ... in package <name>": never answer one app's question from another app
            # (a Mastery delivery that is missing must not borrow the first app's code).
            wanted = _PACKAGE.search(question.text)
            features: dict[int, str] = {}
            if wanted:
                same = _package_apks(context, wanted[1])
                if blob is None or (formats.apk(blob) or {}).get("package_name") != wanted[1]:
                    # Day 26 .apks bundle: the base split holds the puzzle, feature splits the parts.
                    bases = [b for b in same if _with_asset(b, "huntress_puzzle.json")]
                    blob = bases[0] if len(bases) == 1 else None
                features = _feature_parts(same)
            if blob is None:
                continue
            splits = [other for other in same if other is not blob] if wanted else []
            code = answer_code(blob, features, splits)
            if code and fits_format(code, question.answer_format):
                candidates.append(AnswerCandidate(
                    question.answer_id, code, self.name,
                    f"{name or 'the APK'}: assets/huntress_puzzle.json (or the code it names) gives this answer code.",
                ))
        return candidates


SOLVERS = (MobilePuzzleSolver(),)
