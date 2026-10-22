"""Public Binary unit selectors and CRC-validated HCFG records in assigned archives.

Selectors come from issued questions, never from executable content. The existing
archive reader handles AES; parsing and decoding remain static, stdlib operations.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import binascii
import hashlib
import json
from pathlib import PurePosixPath
import re
import struct
import zipfile
import zlib

from ..state import deliveries
from ._binary_formats import ELF, PE, ParseError, parse_images
from ._binary_answers import strict_json
from ._binary_files import BinaryFiles, MAX_BINARY_MEMBER_BYTES
from ._binary_managed import Jar, clr_version
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
        patterns = {"hex": rb"[0-9a-fA-F]{24,}", "base64url": rb"[A-Za-z0-9_-]{24,}={0,2}",
                    "base64": rb"[A-Za-z0-9+/]{100,}={0,2}"}
        found = []
        for index, match in enumerate(re.finditer(patterns[codec], data)):
            if index >= 4096 or len(match.group()) > 1024 * 1024:
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
                explicit = [word for word in ("plugin.cmxs", "loader.elf", "stripped.elf", "symbolized.elf", "compact.wasm", "direct.wasm") if word in q]
                if len(explicit) == 1:
                    chosen = [(i, x) for i, x in chosen if x.filename.endswith(explicit[0])]
        if len(chosen) != 1:
            return None
        index, info = chosen[0]
        key = (id(blob), index)
        if key in self.content:
            return self.content[key]
        if info.file_size > MAX_BINARY_MEMBER_BYTES:
            raise ParseError("Binary member exceeds bound")
        if reference in self.direct_references:
            self.content[key] = blob
            return blob
        return self.files.read_index(blob, index)

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

    def config(self, question: Question, data: bytes) -> Config:
        q = question.text
        if "Apply these mutually exclusive rules" in q:
            q = next((other.text for other in self.family(question) if "top-level" in other.text), q)
        section_scope = "section named exactly .hcfg" in q
        if "Find the final PK19 overlay" in q:
            scope_key = "packed_overlay"
        elif "Find the final RS20 overlay" in q:
            scope_key = "resource_overlay"
        elif "Parse the WebAssembly section stream" in q:
            scope_key = "wasm_data_segment"
        elif section_scope:
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
        elif "literal HCFG" in q and ("Scan" in q or "scan" in q):
            scope_key = "first_literal" if "first record" in q else "unique_literal"
        else:
            raise ParseError("No implemented HCFG storage rule matches the public question")
        key = (id(data), scope_key)
        if key not in self.configs:
            self.configs[key] = None  # Cache failed validation as well as success.
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
            elif section_scope:
                sections = [s for s in self.image(data).sections if s.name == ".hcfg"]
                if len(sections) != 1:
                    raise ParseError("No unique .hcfg section")
                section = sections[0]
                node = self.record(data[section.offset:section.offset + section.size], 0)
                if node:
                    node = Config(section.offset, node.version, node.key, node.crc, node.values, "raw_hcfg_section")
            elif scope_key == "jar":
                node = None
                for offset, text in self.jar(data).main.utf8:
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
            elif scope_key.startswith(("hex_", "base64url_")):
                codec = scope_key.split("_")[0]
                node = self.encoded_config(data, codec, scope_key.endswith("_first"))
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
            if node is None:
                raise ParseError("No bounds/CRC/JSON-valid HCFG record")
            self.configs[key] = node
        if self.configs[key] is None:
            raise ParseError("Cached unsupported HCFG carrier")
        return self.configs[key]

    def answer(self, question: Question, data: bytes) -> tuple[bool, str | None]:
        """handled/answer: recognized but unsupported templates must not fall through."""
        q = question.text
        low = q.casefold()
        if "Compute SHA-256 over the exact bytes of member" in q:
            return True, self.digest(data)
        if "Classify final bytes by magic and parsed container:" in q:
            if data.startswith(b"\0asm"):
                self.wasm(data)
                return True, "wasm"
            if data.startswith(b"PK"):
                self.jar(data).main
                return True, "jar"
            image = self.image(data)
            if isinstance(image, ELF):
                return True, "elf"
            if isinstance(image, PE):
                if image.directory(14)[0]:
                    clr_version(image)
                    return True, "pe_cli"
                return True, "pe"
            return True, None
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
        if "HCFG" in q and any(word in q for word in ("top-level", "header bytes", "header byte", "HCFG byte 4", "winning encoded carrier", "Apply these mutually exclusive rules")):
            config = self.config(question, data)
            field = re.search(r"top-level ([a-z_]+) property", q)
            if field:
                value = config.values.get(field[1])
                return True, value if isinstance(value, str) else None
            if "bytes 8..11 and render" in q:
                return True, f"0x{config.crc:08x}"
            if "header byte 5 as 0x" in q:
                return True, f"0x{config.key:02x}"
            if "HCFG byte 4" in q:
                return True, str(config.version)
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
        if data.startswith(b"PK"):
            jar = self.jar(data)
            if "archive container" in low:
                jar.main  # Verify manifest and selected class, not ZIP magic alone.
                return True, "JAR"
            if "distinct ZIP compression methods" in q:
                return True, json.dumps(sorted({i.compress_type for i in jar.infos}), separators=(",", ":"))
            if "method names in classfile method-table order" in q:
                return True, json.dumps(jar.main.methods, separators=(",", ":"))
            if "classfile access_flags" in q:
                return True, str(jar.main.access_flags)
            if "classfile method-table count" in q:
                return True, str(len(jar.main.methods))
            if "JAR central directory contains kotlin/coroutines/Continuation.class" in q:
                return True, str(any(i.filename == "kotlin/coroutines/Continuation.class" for i in jar.infos)).lower()
            return False, None
        if data.startswith(b"\0asm"):
            return False, None  # Generic question-directed Wasm metadata below.
        image = self.image(data)
        if "every section name in section-header-table index order" in q:
            return True, json.dumps([s.name for s in image.sections], separators=(",", ":"))
        if "true exactly when any parsed executable section name contains the lowercase substring hcfg" in q:
            return True, str(any("hcfg" in s.name for s in image.sections)).lower()
        if "true exactly when the parsed ELF section names contain .hcfg" in q:
            return True, str(isinstance(image, ELF) and any(s.name == ".hcfg" for s in image.sections)).lower()
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
