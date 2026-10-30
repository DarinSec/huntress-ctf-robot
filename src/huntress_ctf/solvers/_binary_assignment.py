"""Public Binary unit selectors and CRC-validated HCFG records in assigned archives.

Selectors come from issued questions, never from executable content. The existing
archive reader handles AES; parsing and decoding remain static, stdlib operations.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import binascii
from io import BytesIO
import hashlib
import json
from pathlib import PurePosixPath
import re
import struct
import zipfile
import zlib

from ..containers import ZIP_ERRORS, decompress, read_member
from ..state import GameMasterError, current_fields, deliveries
from ._binary_formats import ELF, MachO, Neko, PE, ParseError, parse_images
from ._binary_answers import strict_json
from ._binary_files import BinaryFiles, MAX_BINARY_MEMBER_BYTES
from ._binary_managed import Jar, cli_runtime, clr_version
from ._binary_native import array_decoder_reference
from ._binary_payloads import Overlay, read_overlay
from ._binary_wasm import Wasm
from .base import Question, SolveContext, question_items
from .metadata import Files


def namespace(question: Question) -> str | None:
    match = re.match(r"(.+?)_(?:analysis|artifact)_", question.answer_id)
    return match[1] if match else None


@dataclass(frozen=True)
class Config:
    offset: int
    version: int
    key: int
    crc: int
    values: dict
    storage: str = "raw"


def config_at(data: bytes, offset: int) -> Config | None:
    if offset < 0 or offset + 12 > len(data) or data[offset:offset + 4] != b"HCFG":
        return None
    version, key, length, crc = struct.unpack_from("<BBHI", data, offset + 4)
    if not length or offset + 12 + length > len(data):
        return None
    decoded = bytes(value ^ key for value in data[offset + 12:offset + 12 + length])
    if zlib.crc32(decoded) != crc:
        return None

    try:
        values = strict_json(decoded.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        return None
    return Config(offset, version, key, crc, values) if isinstance(values, dict) else None


def _leaves(values: dict, prefix: str = "") -> dict[str, object]:
    out = {}
    for key, value in values.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(_leaves(value, path + "."))
        else:
            out[path] = value
    return out


_FIELD_ID = re.compile(r"_config_([a-z0-9]+(?:_[a-z0-9]+)*)$")
_NOT_FIELDS = {"crc32_hex", "crc32", "xor_key_hex", "version", "offset", "storage"}


def _config_field(question: Question, values: dict | None):
    """The config value a question asks for, however it is worded.

    "top-level campaign property" (days 20-23), "decoded HCFG JSON config.campaign" (day 19),
    or failing both the answer ID ("..._config_campaign"), which only counts when exactly one
    key of that name exists in the CRC-validated record. With values=None: whether it asks one.
    """
    q = question.text
    top = re.search(r"top-level ([a-z_]+) property", q)
    path = re.search(r"decoded HCFG JSON (?!(?:object|record|payload)\b)((?:[A-Za-z0-9_]+\.)*[A-Za-z0-9_]+)", q)
    name = _FIELD_ID.search(question.answer_id)
    wanted = name[1] if name and name[1] not in _NOT_FIELDS and "HCFG" in q else None
    if values is None:
        return True if (top or path or wanted) else None
    if top:
        return values.get(top[1])
    leaves = _leaves(values)
    if path and path[1] in leaves:
        return leaves[path[1]]
    if wanted:
        hits = [value for key, value in leaves.items() if key.rsplit(".", 1)[-1] == wanted]
        return hits[0] if len(hits) == 1 else None
    return None


# Container kinds by the tokens a classification question may list for them, the token days
# 19-25 accepted first. A later day can add a kind (Mach-O, DEX, .pyc, ...) or rename one;
# the question's accepted_values says which, so only a token the grader offers is sent.
CONTAINER_TOKENS = {
    "elf": ("elf",), "pe": ("pe", "native_pe"), "pe_cli": ("pe_cli", "dotnet", "pe_dotnet", "clr", "managed_pe"),
    "jar": ("jar", "java_archive"), "wasm": ("wasm", "webassembly"), "neko": ("neko_bytecode", "neko"),
    "macho": ("macho", "mach_o", "mach-o"),
    "macho_fat": ("macho_fat", "macho_universal", "fat_macho", "universal_macho", "macho", "mach_o", "mach-o"),
    "java_class": ("java_class", "class", "classfile", "jvm_class"), "dex": ("dex", "dalvik_dex", "dalvik"),
    "apk": ("apk", "android_apk"), "zip": ("zip",), "pyc": ("pyc", "python_bytecode", "python_pyc"),
    "lua": ("lua_bytecode", "luac", "lua"), "beam": ("beam", "erlang_beam", "beam_bytecode"),
}
_DAY25_KINDS = {"elf", "pe", "pe_cli", "jar", "wasm", "neko"}


def _offered(question: Question) -> set[str] | None:
    """The question's accepted_values, or None when its format lists none."""
    accepted = question.answer_format.get("accepted_values")
    if isinstance(accepted, (list, tuple)):
        return {value for value in accepted if isinstance(value, str)}
    return None


def _bytecode_kind(data: bytes) -> str | None:
    """Kinds that need only their magic and one header check (none parses as an image)."""
    if data[:4] == b"dex\n" and data[7:8] == b"\0" and len(data) >= 0x70:
        return "dex"
    if len(data) >= 16 and data[2:4] == b"\r\n" and 3000 <= int.from_bytes(data[:2], "little") < 4000:
        return "pyc"
    if data[:4] == b"\x1bLua" and len(data) >= 12:
        return "lua"
    if data[:4] == b"FOR1" and data[8:12] == b"BEAM":
        return "beam"
    return None


# codec -> (whole-run pattern, encoded HCFG magic, run alphabet) for encoded_config.
_ENCODED_RUNS = {
    "hex": (re.compile(rb"[0-9a-fA-F]{24,}"), b"48434647", frozenset(b"0123456789abcdefABCDEF")),
    "base64url": (re.compile(rb"[A-Za-z0-9_-]{24,}={0,2}"), b"SENG",
                  frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")),
    "base64": (re.compile(rb"[A-Za-z0-9+/]{100,}={0,2}"), b"SENG",
               frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")),
}

_JSON_MEMBER = re.compile(r"\bParse ([\w./-]+\.json)\b", re.I)
_KEY = r"([A-Za-z_][\w.]*)"
_JSON_ASKS = (  # (pattern on the text after "Parse <member>.json", what to take)
    (re.compile(rf"\b(first|last|final) (?:\w+ )?(?:string|value|element|entry|item|integer|number) in its {_KEY} (?:array|list)\b", re.I), "end"),
    (re.compile(rf"\b(?:number|count) of (?:\w+ )?(?:strings|values|elements|entries|items|integers|objects|frames) in its {_KEY} (?:array|list)\b", re.I), "count"),
    (re.compile(rf"\bhow many (?:\w+ )?(?:strings|values|elements|entries|items|integers|objects|frames)? ?(?:are )?in its {_KEY} (?:array|list)\b", re.I), "count"),
    (re.compile(rf"\bits {_KEY} (?:array|list) as (?:a |one )?(?:compact )?JSON\b", re.I), "json"),
    (re.compile(rf"\b(?:value|string|text|integer|number) (?:of|in) its {_KEY} (?:field|property|key|member)\b", re.I), "scalar"),
    (re.compile(rf"\bits {_KEY} (?:field|property|key|member)(?: value)?\b", re.I), "scalar"),
)


def json_member_answer(text: str, read) -> tuple[bool, str | None]:
    """'Parse <member>.json and submit ...' for a JSON member no rule names (Day 26: crash/trace.json).

    Takes the first or last element of a named array, its length, the array as compact JSON,
    or a named scalar field (dotted paths and list indexes allowed). Unrecognized wording is
    not handled; a member that is missing or not JSON, or a value of the wrong shape, answers
    nothing rather than a guess.
    """
    named = _JSON_MEMBER.search(text)
    if named is None:
        return False, None
    rest = text[named.end():]
    for pattern, take in _JSON_ASKS:
        asked = pattern.search(rest)
        if asked:
            break
    else:
        return False, None
    try:
        value = json.loads(read(named.group(1)))
    except (ValueError, UnicodeDecodeError, KeyError, zipfile.BadZipFile):
        return True, None
    end, key = (asked.group(1).casefold(), asked.group(2)) if take == "end" else (None, asked.group(1))
    for part in key.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            return True, None
    if take == "count":
        return True, str(len(value)) if isinstance(value, list) else None
    if take == "json":
        return True, json.dumps(value, separators=(",", ":")) if isinstance(value, list) else None
    if take == "end":
        if not (isinstance(value, list) and value):
            return True, None
        value = value[0] if end == "first" else value[-1]
    if isinstance(value, bool):
        return True, str(value).lower()
    if isinstance(value, (str, int)):
        return True, str(value)
    return True, None


def sorted_lf_sha256(values) -> str:
    """'sort strings by ascending code-unit order, join with one LF byte and no trailing LF, then
    SHA-256 those UTF-8 bytes' (UTF-16 code units, as JavaScript sorts)."""
    ordered = sorted(values, key=lambda value: value.encode("utf-16-be", "surrogatepass"))
    return hashlib.sha256("\n".join(ordered).encode("utf-8", "surrogatepass")).hexdigest()


def symbol_names(image: ELF) -> list[str]:
    """Nonempty names "across the parsed symbol tables used by the ELF parser": .symtab when the
    binary has one, else .dynsym. Day 28 accepted 771 for d13's /Crystal|...|GC_/ count (.symtab
    alone) and rejected 1255 (.symtab plus .dynsym); d05, d11 and d18 agree either way."""
    symbols = image.static_symbols if any(s.kind == 2 for s in image.sections) else image.all_symbols
    return [s.name for s in symbols if s.name]


def contains_clauses(text: str) -> list[tuple[str, str]] | None:
    """'NimString or NimMain', 'FPC or any nonempty ELF symbol name contains FPC_' (day 28) as
    [(where, needle)]: "bytes" or "symbol"; a bare token after a symbol clause stays a symbol one.
    None for a clause no rule reads."""
    clauses, where = [], "bytes"
    for part in text.split(" or "):
        symbol = re.fullmatch(r"any nonempty (?:ELF )?symbol name contains (\S+)", part)
        if symbol:
            where, part = "symbol", symbol[1]
        elif not re.fullmatch(r"[A-Za-z0-9_.$:@-]+", part):
            return None
        clauses.append((where, part))
    return clauses or None


class AssignedArchive:
    def __init__(self, context: SolveContext, files: Files):
        self.context = context
        self.files = files if isinstance(files, BinaryFiles) else BinaryFiles(context)
        self.questions = question_items(context)
        self.groups: dict[tuple[str, str | None], list[Question]] = {}
        for question in self.questions:
            group = namespace(question)
            if group is not None:
                self.groups.setdefault((group, question.artifact), []).append(question)
        self.archives: dict[str, tuple[bytes, list[zipfile.ZipInfo]]] = {}
        self.content = self.files.content
        self.images: dict[int, object] = {}
        self.configs: dict[tuple[int, str], Config | None] = {}
        self.jars: dict[int, Jar] = {}
        self.wasms: dict[int, Wasm] = {}
        self.overlays: dict[tuple[int, bytes], Overlay] = {}
        self.digests: dict[tuple[int, str], str] = {}
        self.records: dict[tuple[int, int], tuple[bytes, Config | None]] = {}
        self.family_texts = {key: "\n".join(q.text for q in group) for key, group in self.groups.items()}
        self.prefixes = {key: set(re.findall(r"\b([a-zA-Z0-9_.-]+--)", text))
                         for key, text in self.family_texts.items()}
        self.primary_selectors = {key: "\n".join(sorted({q.text for q in group if "primary managed assembly" in q.text}))
                                  for key, group in self.groups.items()}
        self.ordered_members = {}
        self.issued = deliveries(context.attempt)
        self.direct_references = set()
        try:
            fields = current_fields(context.attempt)
        except GameMasterError:
            fields = {}
        self.timed = bool(fields.get("run_for_time") or fields.get("deadline"))

    def release(self) -> None:
        """Forget every member-keyed cache (a Mastery moving to its next delivery, see binary.py).

        Keyed by id(): once the members are freed an id may be reused, so all of them go together."""
        for cache in (self.archives, self.ordered_members, self.images, self.configs, self.jars,
                      self.wasms, self.overlays, self.digests, self.records):
            cache.clear()

    def digest(self, data: bytes, algorithm="sha256") -> str:
        key = (id(data), algorithm)
        if key not in self.digests:
            self.digests[key] = hashlib.new(algorithm, data).hexdigest()
        return self.digests[key]

    def record(self, data: bytes, offset: int) -> Config | None:
        key = (id(data), offset)
        if key not in self.records:
            self.records[key] = (data, config_at(data, offset))
        return self.records[key][1]

    def encoded_config(self, data: bytes, codec: str, first: bool) -> Config | None:
        pattern, magic, alphabet = _ENCODED_RUNS[codec]
        found = []
        candidates = 0
        # A record is only ever read from byte 0 of the carrier (`record(raw, 0)`) and begins
        # with b"HCFG", so a carrier is a whole run of the codec's alphabet that starts with that
        # magic encoded: "48434647" in hex, "SENG" in both Base64 alphabets (base64(b"HCF")).
        # Finding the magic first skips the look-alike runs a binary is full of: walking every
        # run of the 64 MiB ELF in days 25/26 Mastery cost 1.9-5 s, and day 25 hit the old
        # 4096-run bound before its record. The bound now counts carriers that start with the magic.
        at = data.find(magic)
        while at >= 0:
            match = pattern.match(data, at) if at == 0 or data[at - 1] not in alphabet else None
            at = data.find(magic, at + 1)
            if match is None:
                continue  # Mid-run, or a run too short to be a carrier.
            candidates += 1
            if candidates > 4096 or len(match.group()) > 1024 * 1024:
                raise ParseError("Encoded HCFG scan exceeds bound")
            try:
                encoded = match.group()
                if codec == "hex":
                    raw = bytes.fromhex(encoded.decode("ascii"))
                elif codec == "base64url":
                    if (match.start() and data[match.start() - 1] in b"+/=") or (match.end() < len(data) and data[match.end()] in b"+/="):
                        continue  # Not a complete URL-safe carrier.
                    raw = base64.b64decode(encoded + b"=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
                else:
                    raw = base64.b64decode(encoded, validate=True)
                candidate = self.record(raw, 0)
            except (ValueError, binascii.Error):
                continue
            if candidate:
                found.append(Config(match.start(), candidate.version, candidate.key, candidate.crc, candidate.values, codec))
                if first:
                    break
        if len(found) > 1:
            raise ParseError("Multiple valid encoded HCFG records")
        return found[0] if found else None

    def discover(self, data: bytes, depth: int = 0) -> Config | None:
        """The one HCFG record hidden anywhere a day has hidden one, or might next.

        Carriers the course used (raw, hex, base64, base64url, PK19/RS20 overlays, Wasm data
        segments, sections, JAR constants) plus the likely next ones: zlib/gzip/xz/bzip2
        streams, a single-byte XOR over the whole record, reversed bytes, UTF-16 strings
        (.NET #US heap) and nested ZIP members. A record counts only when its CRC32 and JSON
        validate; two different records make the answer ambiguous, so nothing is returned.
        Offsets are kept only for a literal record in the member itself (storage "discovered_raw").
        """
        found: dict[tuple[int, str], Config] = {}
        ambiguous = False

        def add(node: Config | None, how: str) -> None:
            if node is not None:
                offset = node.offset if how == "raw" else -1
                found.setdefault((node.crc, json.dumps(node.values, sort_keys=True)),
                                 Config(offset, node.version, node.key, node.crc, node.values, "discovered_" + how))

        def literal(blob: bytes, how: str) -> None:
            start = 0
            for _ in range(4096):
                at = blob.find(b"HCFG", start)
                if at < 0:
                    return
                add(config_at(blob, at), how)
                start = at + 4

        def encoded(blob: bytes, how: str) -> None:
            nonlocal ambiguous
            for codec in ("hex", "base64url", "base64"):
                try:
                    node = self.encoded_config(blob, codec, False)
                except ParseError:
                    ambiguous = True
                    continue
                add(node, how or codec)

        literal(data, "raw")
        encoded(data, "")
        literal(data[::-1], "reversed")
        text = b"\n".join(m.group()[::2] for m in re.finditer(rb"(?:[\x20-\x7e]\x00){24,}", data[:64 * 1024 * 1024]))
        if text:
            encoded(text, "utf16")
        for magic in (b"PK19", b"RS20"):
            if magic in data:
                try:
                    add(config_at(read_overlay(data, magic).payload, 0), "overlay")
                except ParseError:
                    pass
        if data.startswith(b"\0asm"):
            try:
                for _, payload in self.wasm(data).data_segments:
                    literal(payload, "wasm_data_segment")
            except ParseError:
                pass
        if len(data) <= 32 * 1024 * 1024:
            for key in range(1, 256):  # The whole record XORed with one more byte.
                marker, start = bytes(c ^ key for c in b"HCFG"), 0
                for _ in range(64):
                    at = data.find(marker, start)
                    if at < 0:
                        break
                    length = struct.unpack("<H", bytes(c ^ key for c in data[at + 6:at + 8]))[0] if at + 8 <= len(data) else 0
                    add(config_at(bytes(c ^ key for c in data[at:at + 12 + length]), 0), "xor")
                    start = at + 4
        if depth == 0:
            blobs = []
            for magic, open_stream in ((b"\x78\x9c", lambda: zlib.decompressobj()), (b"\x78\xda", lambda: zlib.decompressobj()),
                                       (b"\x78\x01", lambda: zlib.decompressobj()), (b"\x78\x5e", lambda: zlib.decompressobj()),
                                       (b"\x1f\x8b\x08", lambda: zlib.decompressobj(16 + zlib.MAX_WBITS))):
                start = 0
                for _ in range(256):
                    at = data.find(magic, start)
                    if at < 0:
                        break
                    try:
                        out = open_stream().decompress(data[at:], 16 * 1024 * 1024)
                    except zlib.error:
                        out = b""
                    if len(out) >= 12:
                        blobs.append(out)
                    start = at + 2
            for magic, kind in ((b"\xfd7zXZ\x00", "xz"), (b"BZh", "bz2")):
                at = data.find(magic)
                if at >= 0:
                    try:
                        blobs.append(decompress(data[at:], kind, 16 * 1024 * 1024, head=True))
                    except ZIP_ERRORS:
                        pass
            if data.startswith(b"PK"):
                try:
                    with zipfile.ZipFile(BytesIO(data)) as archive:
                        for info in archive.infolist()[:4096]:
                            if not info.is_dir() and info.file_size <= 16 * 1024 * 1024 and not info.flag_bits & 1:
                                blobs.append(read_member(archive, info))
                except ZIP_ERRORS:
                    pass
            for blob in blobs:
                try:
                    node = self.discover(blob, depth + 1)
                except ParseError:
                    ambiguous = True
                    continue
                if node is not None:
                    add(Config(-1, node.version, node.key, node.crc, node.values), "nested")
        if ambiguous or len(found) != 1:
            return None
        return next(iter(found.values()))

    def wasm(self, data: bytes) -> Wasm:
        if id(data) not in self.wasms:
            self.wasms[id(data)] = Wasm(data)
        return self.wasms[id(data)]

    def overlay(self, question: Question, data: bytes) -> Overlay:
        text = "\n".join(q.text for q in self.family(question))
        schemas = set(re.findall(r"final (PK19|RS20) (?:resource )?overlay", text))
        if len(schemas) != 1:
            raise ParseError("No unique public overlay schema")
        magic = next(iter(schemas)).encode("ascii")
        key = (id(data), magic)
        if key not in self.overlays:
            self.overlays[key] = read_overlay(data, magic)
        return self.overlays[key]

    def jar(self, data: bytes) -> Jar:
        if id(data) not in self.jars:
            self.jars[id(data)] = Jar(data)
        return self.jars[id(data)]

    def family(self, question: Question) -> list[Question]:
        group = namespace(question)
        return self.groups.get((group, question.artifact), []) if group is not None else []

    def load(self, reference: str) -> tuple[bytes, list[zipfile.ZipInfo]] | None:
        """The archive (or direct member) a question's artifact reference names, with its directory."""
        if reference not in self.archives:
            parts = reference.split(" -> ")
            root = parts[0]
            if root.startswith("delivery ") and root not in self.files.deliveries:
                if not (len(self.issued) == 1 and root == f"delivery 1: {self.issued[0]['filename']}"):
                    return None
            if len(self.issued) > 1 and root not in self.files.deliveries:
                return None  # Never substitute another delivery with the same basename.
            if len(self.issued) == 1 and self.issued[0]['filename'] != 'artifact' and root not in {
                    self.issued[0]['filename'], f"delivery 1: {self.issued[0]['filename']}",
                    "artifact", "assigned artifact", "sample", "binary"}:
                if self.files.member(self.context.artifact, root) is None:
                    return None
            blob = self.files.container(root)
            for part in parts[1:]:
                blob = self.files.member(blob, part) if blob is not None else None
            if blob is None:
                return None
            if len(parts) > 1 and not blob.startswith(b"PK"):
                info = zipfile.ZipInfo(parts[-1])
                info.file_size = len(blob)
                infos = [info]
                self.direct_references.add(reference)
            else:
                infos = self.files.directory(blob)
            self.archives[reference] = blob, infos
        return self.archives[reference]

    def structural(self, question: Question) -> tuple[bool, str | None]:
        """Questions about the archive's member list, not one member's bytes (day 28 d01 block):
        "Count the d01-- members in the ZIP central directory" and "Compute each d01-- member's
        lowercase SHA-256 in ZIP central-directory order, join those digests with ASCII colon
        characters ..., then SHA-256 the resulting UTF-8 bytes"."""
        q = question.text
        count = re.search(r"Count the ([A-Za-z0-9_.-]+--) members in the ZIP central directory", q)
        joined = re.search(r"Compute each ([A-Za-z0-9_.-]+--) member's lowercase SHA-256 in ZIP central-directory "
                           r"order, join those digests with ASCII colon characters and no trailing newline, "
                           r"then SHA-256 the resulting UTF-8 bytes", q)
        if not (count or joined):
            return False, None
        if not question.artifact or self.load(question.artifact) is None:
            return True, None
        reference = question.artifact
        blob, infos = self.archives[reference]
        prefix = (count or joined)[1]
        chosen = [(index, info) for index, info in enumerate(infos)
                  if not info.is_dir() and PurePosixPath(info.filename).name.startswith(prefix)]
        if count:
            return True, str(len(chosen))
        digests = [self.digest(self.member(reference, blob, index, info)) for index, info in chosen]
        return True, hashlib.sha256(":".join(digests).encode("utf-8")).hexdigest() if digests else None

    def resolve(self, question: Question) -> bytes | None:
        family = self.family(question)
        if not family or not question.artifact:
            return None
        group_key = (namespace(question), question.artifact)
        family_text = self.family_texts[group_key]
        prefixes = self.prefixes[group_key]
        if len(prefixes) != 1:
            return None
        prefix = next(iter(prefixes))
        reference = question.artifact
        if self.load(reference) is None:
            return None
        blob, infos = self.archives[reference]
        ordered_key = (reference if reference in self.direct_references else id(blob), prefix)
        if ordered_key not in self.ordered_members:
            self.ordered_members[ordered_key] = [(index, info) for index, info in enumerate(infos)
                if not info.is_dir() and PurePosixPath(info.filename).name.startswith(prefix)]
        chosen = self.ordered_members[ordered_key]
        q = question.text
        member = re.search(r"exact bytes of member (\d+)", q, re.I)
        if member:
            index = int(member[1]) - 1
            chosen = chosen[index:index + 1] if 0 <= index < len(chosen) else []
        else:
            # Primary-assembly selectors apply to its analysis siblings, never to
            # member-ordinal hashes. Enforce both predicates even for one member.
            selector = q
            if "primary managed assembly" in family_text:
                selector = self.primary_selectors[group_key]
            starts = set(re.findall(r"basename starts\s+[`\"']?([A-Za-z0-9_.-]+)", selector))
            ends = set(re.findall(r"(?:basename ends|and ends)\s+[`\"']?([A-Za-z0-9_.-]+)", selector))
            if len(starts) > 1 or len(ends) > 1:
                return None
            if starts:
                chosen = [(i, x) for i, x in chosen if PurePosixPath(x.filename).name.startswith(next(iter(starts)))]
            if ends:
                suffix = next(iter(ends)).rstrip(";")
                # A final sentence period follows the suffix; a leading . is part of it.
                suffix = suffix[:-1] if suffix.endswith(".") else suffix
                chosen = [(i, x) for i, x in chosen if PurePosixPath(x.filename).name.endswith(suffix)]
            else:
                # The role a question names, from a "Use the d21-- plugin.cmxs member" phrase or
                # its answer ID (d15_analysis_stripped_machine), picks the one member named
                # <prefix>...-<role>.<ext>: stripped/symbolized, compact/direct, loader/plugin and
                # vulnerable/corrected so far, so a new day's pair needs no new code.
                named = re.search(r"Use the (?:unique )?[A-Za-z0-9_.-]+-- ([A-Za-z0-9_.-]+) member", q)
                role = re.match(r"(?:set\d+\.)?d\d+_analysis_([a-z0-9]+)_", question.answer_id)
                pair = re.search(r"Decode ([A-Za-z0-9_.-]+) and ([A-Za-z0-9_.-]+) and require their config objects", q)
                if pair:
                    # Day 28: "Decode family-a.elf and family-b.elf and require ... byte-for-byte
                    # equal ...; do not use false-friend.elf": exactly the two named members.
                    hits = [[hit for hit in chosen if PurePosixPath(hit[1].filename).name.endswith(name)]
                            for name in pair.groups()]
                    ok = all(len(found) == 1 for found in hits) and hits[0] != hits[1]
                    chosen, picked = ([found[0] for found in hits] if ok else []), []
                elif named:
                    picked = [(i, x) for i, x in chosen if PurePosixPath(x.filename).name.endswith(named[1])]
                elif role:
                    picked = [(i, x) for i, x in chosen if PurePosixPath(x.filename).stem.endswith("-" + role[1])]
                else:
                    picked = []
                if len(picked) == 1:
                    chosen = picked
            if len(chosen) > 1 and "primary managed assembly" in family_text:
                # The primary assembly has its own .runtimeconfig.json, a dependency DLL has
                # none (day 22: d22--sample.dll beside d22--FSharp.Core.dll).
                configs = {PurePosixPath(x.filename).name for x in infos if x.filename.endswith(".runtimeconfig.json")}
                chosen = [(i, x) for i, x in chosen
                          if PurePosixPath(x.filename).name.rsplit(".", 1)[0] + ".runtimeconfig.json" in configs]
        if "require their config objects to be byte-for-byte equal" in q:
            # Day 24, 27, 28: "Decode both role members" or "Decode family-a.elf and family-b.elf"
            if "do not use false-friend" in q or "family-a.elf and family-b.elf" in q:
                chosen = [(i, x) for i, x in chosen if not PurePosixPath(x.filename).name.endswith("false-friend.elf")]
            if len(chosen) == 2:
                members = [self.member(reference, blob, index, info) for index, info in chosen]
                shared = {(c.crc, json.dumps(c.values, sort_keys=True)) for c in (self.config(question, m) for m in members)}
                return members[0] if len(shared) == 1 else None
        if len(chosen) > 1 and not self.timed and "HCFG" in q and _config_field(question, None) is not None:
            # Untimed only: a selector no rule knows left several members. Answer the config
            # that every member carrying a CRC32/JSON-valid one agrees on, else nothing; a
            # wrong one costs a single answer there (learn splits a rejected kind).
            found = []
            for index, info in chosen:
                data = self.member(reference, blob, index, info)
                try:
                    found.append((data, self.config(question, data)))
                except (ParseError, ValueError, zipfile.BadZipFile):
                    continue
            shared = {(c.crc, json.dumps(c.values, sort_keys=True)) for _, c in found}
            return found[0][0] if len(shared) == 1 else None
        if len(chosen) != 1:
            return None
        return self.member(reference, blob, *chosen[0])

    def member(self, reference: str, blob: bytes, index: int, info: zipfile.ZipInfo) -> bytes:
        key = (id(blob), index)
        if key in self.content:
            return self.content[key]
        if info.file_size > MAX_BINARY_MEMBER_BYTES:
            raise ParseError("Binary member exceeds bound")
        if reference in self.direct_references:
            self.content[key] = blob
            return blob
        return self.files.read_index(blob, index)

    def container_kind(self, data: bytes) -> str | None:
        """What the final bytes are, each kind validated as days 19-25 did (malformed -> ParseError)."""
        if data.startswith(b"\0asm"):
            self.wasm(data)
            return "wasm"
        if data.startswith(b"PK"):
            try:
                self.jar(data).main
                return "jar"
            except ParseError:
                names = set(self.jar(data).archive.namelist())
                if "AndroidManifest.xml" in names and any(n.startswith("classes") and n.endswith(".dex") for n in names):
                    return "apk"
                if any(n.endswith(".class") for n in names):
                    raise  # Classfiles without a unique Main-Class: what day 19 skipped.
                return "zip"
        if data.startswith(b"NEKO"):
            Neko(data)                      # validate the header; malformed -> ParseError -> skipped
            return "neko"
        if kind := _bytecode_kind(data):
            return kind
        try:
            image = self.image(data)
        except ParseError:
            if data[:4] == b"\xca\xfe\xba\xbe" and 45 <= int.from_bytes(data[6:8], "big") < 100:
                return "java_class"       # Shares its magic with a fat Mach-O; the major version tells.
            if len(parse_images(data)) > 1:
                return "macho_fat"
            raise
        if isinstance(image, ELF):
            return "elf"
        if isinstance(image, PE):
            if image.directory(14)[0]:
                clr_version(image)
                return "pe_cli"
            return "pe"
        return "macho" if isinstance(image, MachO) else None

    def image(self, data: bytes):
        if id(data) not in self.images:
            self.images[id(data)] = None
            images = parse_images(data)
            if len(images) != 1:
                raise ParseError("One executable is required")
            self.images[id(data)] = images[0]
        if self.images[id(data)] is None:
            raise ParseError("Cached unsupported executable")
        return self.images[id(data)]

    @staticmethod
    def scope(q: str) -> str | None:
        """The carrier rule a question names, or None for a wording no rule knows."""
        if "Find the final PK19 overlay" in q:
            scope_key = "packed_overlay"
        elif "Find the final RS20 overlay" in q:
            scope_key = "resource_overlay"
        elif "Parse the WebAssembly section stream" in q:
            scope_key = "wasm_data_segment"
        elif "section named exactly .hcfg" in q:
            scope_key = "section"
        elif "classfile constant pool" in q:
            scope_key = "jar"
        elif "First test literal HCFG occurrences" in q:
            codec = "base64url" if re.search(r"base64url|url-safe base64", q, re.I) else "hex" if re.search(r"hex-decod|hex(?:adecimal)?-encoded", q, re.I) else "base64"
            scope_key = "literal_then_" + codec
        elif re.search(r"base64url|url-safe base64", q, re.I):
            scope_key = "base64url_first" if "first" in q.casefold() else "base64url_unique"
        elif re.search(r"hex-decod|hex(?:adecimal)?-encoded", q, re.I):
            scope_key = "hex_first" if "first" in q.casefold() else "hex_unique"
        elif "Test every non-overlapping Latin-1 run" in q:
            scope_key = "base64"
        elif "literal HCFG" in q and re.search(r"[Ss]can backward from the end", q):
            scope_key = "last_literal"  # Day 28: the first valid record from the end is the last one.
        elif "literal HCFG" in q and ("Scan" in q or "scan" in q):
            scope_key = "first_literal" if "first record" in q else "unique_literal"
        else:
            return None
        return scope_key

    def config(self, question: Question, data: bytes) -> Config:
        q = question.text
        scope_key = None
        if "Apply these mutually exclusive rules" in q:
            # The storage question lists every rule (.hcfg included); the carrier is the one
            # its siblings name: a "top-level" one (day 22), else the one rule all agree on
            # (day 19: "Test every non-overlapping Latin-1 run ..." beside the storage rules).
            q = next((other.text for other in self.family(question) if "top-level" in other.text), q)
            if q is question.text:
                named = {self.scope(other.text) for other in self.family(question)
                         if "HCFG" in other.text and "Apply these mutually exclusive rules" not in other.text}
                if len(named) == 1 and None not in named:
                    scope_key = named.pop()
        scope_key = scope_key or self.scope(q)
        if scope_key is None:
            if self.timed:
                raise ParseError("No implemented HCFG storage rule matches the public question")
            # A storage worded in a way no rule knows (a new day): search every carrier, keep
            # only a CRC32/JSON-valid record that all of them agree on (see discover()). Untimed
            # only: there an "incorrect" is resent kind by kind, so a wrong record costs one
            # kind; a timed race keeps to the public storage rules.
            scope_key = "discover"
        key = (id(data), scope_key)
        if key not in self.configs:
            self.configs[key] = None  # Cache failed validation as well as success.
            node = self._carrier(question, data, scope_key)
            if node is None and not self.timed and scope_key != "discover":
                # A named rule that finds nothing is searched like an unknown one (untimed only):
                # day 24's "every JAR classfile" rule was known, but read only the Main-Class.
                # A rule that raises found something inconsistent (bounds, a second record) and
                # stays refused: the payload tests pin that.
                node = self.discover(data)
            if node is None:
                raise ParseError("No bounds/CRC/JSON-valid HCFG record")
            self.configs[key] = node
        if self.configs[key] is None:
            raise ParseError("Cached unsupported HCFG carrier")
        return self.configs[key]

    def _carrier(self, question: Question, data: bytes, scope_key: str) -> Config | None:
        """The record the named storage rule finds: None or ParseError when it finds none."""
        if scope_key in ("packed_overlay", "resource_overlay"):
            node = self.record(self.overlay(question, data).payload, 0)
        elif scope_key == "wasm_data_segment":
            found = []
            for start, payload in self.wasm(data).data_segments:
                at, count = 0, 0
                while (at := payload.find(b"HCFG", at)) >= 0:
                    count += 1
                    if count > 4096:
                        raise ParseError("WebAssembly HCFG scan exceeded bound")
                    candidate = self.record(payload, at)
                    if candidate:
                        found.append(Config(start + at, candidate.version, candidate.key,
                                            candidate.crc, candidate.values, "wasm_data_segment"))
                    at += 4
            if len(found) != 1:
                raise ParseError("No unique valid HCFG in WebAssembly data segments")
            node = found[0]
        elif scope_key == "discover":
            node = self.discover(data)
        elif scope_key == "section":
            sections = [s for s in self.image(data).sections if s.name == ".hcfg"]
            if len(sections) != 1:
                raise ParseError("No unique .hcfg section")
            section = sections[0]
            node = self.record(data[section.offset:section.offset + section.size], 0)
            if node:
                node = Config(section.offset, node.version, node.key, node.crc, node.values, "raw_hcfg_section")
        elif scope_key == "jar":
            node = None
            for javaclass in self.jar(data).classes():
                for offset, text in javaclass.utf8:
                    if len(text) < 80 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text):
                        continue
                    try:
                        raw = base64.b64decode(text, validate=True)
                    except binascii.Error:
                        continue
                    candidate = self.record(raw, 0)
                    if candidate:
                        node = Config(offset, candidate.version, candidate.key, candidate.crc, candidate.values, "base64")
                        break
                if node:
                    break
        elif scope_key.startswith(("hex_", "base64url_")):
            codec = scope_key.split("_")[0]
            node = self.encoded_config(data, codec, scope_key.endswith("_first"))
        elif scope_key == "last_literal":
            node, end = None, len(data)
            for _ in range(4096):
                offset = data.rfind(b"HCFG", 0, end)
                if offset < 0:
                    break
                node = self.record(data, offset)
                if node:
                    break
                end = offset + 3  # An earlier magic may overlap this one by at most three bytes.
            else:
                raise ParseError("HCFG scan exceeded candidate bound")
        else:
            node, start, found = None, 0, []
            if scope_key != "base64":
                for _ in range(4096):
                    offset = data.find(b"HCFG", start)
                    if offset < 0:
                        break
                    candidate = self.record(data, offset)
                    if candidate:
                        found.append(candidate)
                        if scope_key != "unique_literal":
                            break
                    start = offset + 4
                else:
                    raise ParseError("HCFG scan exceeded candidate bound")
                if len(found) > 1:
                    raise ParseError("Multiple valid literal HCFG records")
                node = found[0] if found else None
            if node is None and (scope_key == "base64" or scope_key.startswith("literal_then_")):
                codec = scope_key.removeprefix("literal_then_")
                node = self.encoded_config(data, codec, True)
        return node

    def answer(self, question: Question, data: bytes) -> tuple[bool, str | None]:
        """handled/answer: recognized but unsupported templates must not fall through."""
        q = question.text
        low = q.casefold()
        if "Compute SHA-256 over the exact bytes of member" in q:
            return True, self.digest(data)
        if "Classify final bytes by magic and parsed container:" in q:
            kind, offered = self.container_kind(data), _offered(question)
            tokens = CONTAINER_TOKENS.get(kind, ())
            if offered is None:
                if kind in _DAY25_KINDS:
                    return True, tokens[0]
                offered = set(re.findall(r"\b([a-z][a-z0-9_-]*) for\b", q))  # "macho for Mach-O, ..."
            return True, next((token for token in tokens if token in offered), None)
        if "Report x86-64 for an ELF/PE machine field identifying AMD64" in q:
            if data.startswith(b"\0asm"):
                self.wasm(data)
                return True, "wasm32"
            image = self.image(data)
            return True, "x86-64" if image.arch == "x86_64" else None
        if "Locate the final overlay magic named by this unit" in q:
            return True, str(self.overlay(question, data).offset)
        if "member byte length minus the located overlay magic" in q:
            return True, str(len(data) - self.overlay(question, data).offset)
        if "In the final RS20 resource overlay" in q and "size field" in q:
            return True, str(self.overlay(question, data).resource_size)
        packing = re.search(r"packing_key_(\d+)_hex$", question.answer_id)
        if packing and "final PK19 overlay" in q and "packing key" in q:
            # Day 28 asks day 19's "k1 at +5, k2 at +6" by the answer ID alone.
            if packing[1] not in ("1", "2"):
                return True, None
            offset = self.overlay(question, data).offset
            return True, f"0x{data[offset + 4 + int(packing[1])]:02x}"
        asks_field = _config_field(question, None) is not None
        if "HCFG" in q and (asks_field or any(word in q for word in ("top-level", "header bytes", "header byte", "HCFG byte 4", "winning encoded carrier", "Apply these mutually exclusive rules"))):
            config = self.config(question, data)
            if asks_field:
                value = _config_field(question, config.values)
                return True, value if isinstance(value, str) else None
            if "bytes 8..11 and render" in q:
                return True, f"0x{config.crc:08x}"
            if "header byte 5 as 0x" in q:
                return True, f"0x{config.key:02x}"
            if "HCFG byte 4" in q:
                return True, str(config.version)
            if config.storage.startswith("discovered") and ("winning encoded carrier" in q
                                                            or "Apply these mutually exclusive rules" in q):
                return True, None  # Offset and storage label are defined by the rule the question names.
            if "winning encoded carrier" in q:
                return True, str(config.offset)
            if "Apply these mutually exclusive rules" in q:
                if config.storage in ("base64", "base64url", "hex"):
                    return True, config.storage
                if config.storage == "wasm_data_segment":
                    return True, "wasm_data_segment"
                image = self.image(data)
                containing = [s for s in image.sections if s.offset <= config.offset < s.offset + s.size]
                if len(containing) == 1 and containing[0].name == ".hcfg":
                    return True, "raw_hcfg_section"
                if len(containing) == 1 and array_decoder_reference(image, config.offset) is not None:
                    return True, "raw_const_array"
                return True, "raw" if not containing else None  # A mapped array needs instruction/relocation proof.
            return True, None
        if "HCFG" in q:
            return True, None
        text = re.search(r"true exactly when the final bytes interpreted as Latin-1 or UTF-16LE contain the case-sensitive text (\S+)", q)
        if text:
            needle = text[1].removesuffix(".")
            return True, str(needle.encode("latin-1") in data or needle.encode("utf-16-le") in data).lower()
        either = re.search(r"true exactly when the final bytes contain (?!the case-sensitive)(.+?)\.?\s*$", q)
        if either:
            clauses = contains_clauses(either[1])
            if clauses is None:
                return True, None
            if any(where == "bytes" and needle.encode("latin-1") in data for where, needle in clauses):
                return True, "true"
            wanted = [needle for where, needle in clauses if where == "symbol"]
            if not wanted:
                return True, "false"
            image = self.image(data) if data.startswith(b"\x7fELF") else None
            names = symbol_names(image) if isinstance(image, ELF) else []
            return True, str(any(needle in name for needle in wanted for name in names)).lower()
        if data.startswith(b"PK"):
            jar = self.jar(data)
            if "archive container" in low:
                jar.main  # Verify manifest and selected class, not ZIP magic alone.
                return True, "JAR"
            if "distinct ZIP compression methods" in q:
                return True, json.dumps(sorted({i.compress_type for i in jar.infos}), separators=(",", ":"))
            if "crash/trace.json" in q:
                # Day 26: a synthetic crash trace shipped in the JAR ({"kind", "frames": [innermost first]}).
                try:
                    trace = json.loads(jar.read("crash/trace.json"))
                except (ValueError, UnicodeDecodeError):
                    return True, None
                frames = trace.get("frames") if isinstance(trace, dict) else None
                if not (isinstance(frames, list) and frames and all(isinstance(f, str) for f in frames)):
                    return True, None
                if "first string in its frames array" in q:
                    return True, frames[0]
                if "every string in crash/trace.json frames is present in the primary classfile method-name set" in q:
                    return True, str(set(frames) <= set(jar.main.methods)).lower()
            handled, value = json_member_answer(q, jar.read)
            if handled or "crash/trace.json" in q:
                return True, value
            if "method names in classfile method-table order" in q:
                return True, json.dumps(jar.main.methods, separators=(",", ":"))
            if "classfile access_flags" in q:
                return True, str(jar.main.access_flags)
            if "classfile method-table count" in q:
                return True, str(len(jar.main.methods))
            if "JAR central directory contains kotlin/coroutines/Continuation.class" in q:
                return True, str(any(i.filename == "kotlin/coroutines/Continuation.class" for i in jar.infos)).lower()
            entries = re.search(r"Count JAR central-directory entries whose names end (\.[A-Za-z0-9_$]+)", q)
            if entries:
                return True, str(sum(1 for i in jar.infos if i.filename.endswith(entries[1])))
            if "resolve its this_class constant-pool name" in q:
                return True, jar.main.this_class
            if "primary classfile's unique method names, sort strings by ascending code-unit order" in q and "SHA-256" in q:
                return True, sorted_lf_sha256(set(jar.main.methods))
            return False, None
        if data.startswith(b"\0asm"):
            return False, None  # Generic question-directed Wasm metadata below.
        image = self.image(data)
        if re.search(r"every (?:ELF )?section name in section-header-table index order", q):
            return True, json.dumps([s.name for s in image.sections], separators=(",", ":"))
        if "true exactly when any parsed executable section name contains the lowercase substring hcfg" in q:
            return True, str(any("hcfg" in s.name for s in image.sections)).lower()
        if "true exactly when the parsed ELF section names contain .hcfg" in q:
            return True, str(isinstance(image, ELF) and any(s.name == ".hcfg" for s in image.sections)).lower()
        if isinstance(image, PE) and "Read the CLI header major and minor runtime bytes" in q:
            return True, cli_runtime(image)
        if isinstance(image, PE) and ("managed-runtime format classification" in q or "CLR metadata-root version string" in q):
            version = clr_version(image)
            return True, "PE_CLI" if "managed-runtime format classification" in q else version
        if "executable container" in low or "executable-container" in low:
            return True, image.format
        if isinstance(image, ELF):
            if "ei_class" in low:
                return True, "ELF" + str(image.bits) if "ELF32 or ELF64 exactly" in q else str(image.bits)
            if "e_type value" in low:
                return True, str(image.file_type)
            if "ei_data" in low:
                return True, "little" if image.endian == "<" else "big"
            if "e_machine field" in low and "unsigned base-10" in low:
                return True, str(image.machine)
            if "elf header entry address" in low:
                return True, hex(image.entry)
            if "true exactly when the ELF section-header name table contains .symtab" in q:
                return True, str(any(s.name == ".symtab" for s in image.sections)).lower()
            if "Count ELF symbol-table entries whose resolved name is nonempty, across the parsed symbol tables" in q:
                return True, str(len(symbol_names(image)))
            pattern = re.search(r"(count names that match|Count the nonempty ELF symbol names matching|"
                                r"Collect every nonempty ELF symbol name matching) /(.+?)/(?=[\s,.;]|$)", q)
            if pattern:
                # Day 28: a JavaScript-style /.../ over the parsed table (symbol_names()).
                if len(pattern[2]) > 200:
                    return True, None
                try:
                    expression = re.compile(pattern[2], re.ASCII)
                except re.error:
                    return True, None
                names = [name for name in symbol_names(image) if expression.search(name)]
                if pattern[1].startswith("Collect"):
                    if "sort strings by ascending code-unit order, join with one LF byte and no trailing LF, then SHA-256" not in q:
                        return True, None
                    return True, sorted_lf_sha256(names)
                return True, str(len(names))
            opcodes = re.search(r"In the ELF (\.[A-Za-z0-9_.]+?) bytes, count every 0x([0-9a-f]{2})\.\.0x([0-9a-f]{2}) byte "
                                r"and every two-byte sequence 0x([0-9a-f]{2}) followed by 0x([0-9a-f]{2})\.\.0x([0-9a-f]{2})", q, re.I)
            if opcodes:
                # Day 28 d17: Jcc rel8 (0x70..0x7f) and Jcc rel32 (0x0f 0x80..0x8f) bytes; every
                # position is tested once, so both kinds are counted independently.
                sections = [s for s in image.sections if s.name == opcodes[1] and s.kind != 8]
                if len(sections) != 1:
                    return True, None
                raw = image.take(sections[0].offset, sections[0].size)
                low, high, lead, second_low, second_high = (int(value, 16) for value in opcodes.groups()[1:])
                single = sum(raw.count(bytes([value])) for value in range(low, high + 1))
                pairs = len(re.findall(b"(?=%s[\\x%02x-\\x%02x])" % (re.escape(bytes([lead])), second_low, second_high), raw))
                return True, str(single + pairs)
            if "Read the .huntress section bytes as UTF-8 and remove trailing NUL bytes only" in q:
                sections = [s for s in image.sections if s.name == ".huntress"]
                if len(sections) != 1:
                    return True, None
                section = sections[0]
                return True, data[section.offset:section.offset + section.size].rstrip(b"\0").decode("utf-8")
            if "SHT_SYMTAB symbol name" in q:
                return True, json.dumps([s.name for s in image.static_symbols if s.name], separators=(",", ":"))
            if "recover_code" in q:
                symbols = [s for s in image.static_symbols if s.name == "recover_code" and s.kind == 2]
                disassembly = "disassemble its bytes" in q
                if not symbols:
                    return True, "[]" if disassembly else "none"
                if len(symbols) != 1 or image.arch not in ("x86", "x86_64"):
                    return True, None
                raw = image.symbol_bytes(symbols[0])
                if len(raw) != 6 or raw[0] != 0xb8 or raw[5] != 0xc3:
                    return True, None
                value = int.from_bytes(raw[1:5], "little")
                return True, json.dumps([f"mov eax, {hex(value)}", "ret"], separators=(",", ":")) if disassembly else str(value)
        if "true exactly when the final bytes contain the case-sensitive Latin-1 text runtime.main" in q:
            return True, str(b"runtime.main" in data).lower()
        if isinstance(image, ELF) and "any nonempty ELF symbol name starts _ZN or _R" in q:
            return True, str(any(s.name.startswith(("_ZN", "_R")) for s in image.all_symbols)).lower()
        if "nonempty symbol name matches /" in q or "first exact remaining name matching /" in q:
            if not isinstance(image, (PE, ELF)):
                return True, None
            match = re.search(r"matching /([^/]+)/|matches /([^/]+)/", q)
            expression = (match[1] or match[2]) if match else ""
            if not expression or len(expression) > 128 or not re.fullmatch(r"[A-Za-z0-9_.$^*?+\-]+", expression):
                return True, None
            names = [s.name for s in image.static_symbols if s.name and re.search(expression, s.name)]
            return True, str(bool(names)).lower() if "true exactly when" in q else names[0] if names else None
        return False, None
