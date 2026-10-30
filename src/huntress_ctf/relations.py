"""Relations between the artifacts of a cluster ZIP: Day 30 "Seeing Double" and its siblings.

Day 30's prompt: "Build a relationship map from exact identity, semantic identity, containment,
and claimed provenance - then expose the fabricated cluster." Day 30 asked one of them,
`relation.identical_sha256_groups`, and the grader took artifact ids (no "artifacts/" folder),
each group sorted, then the groups sorted; full paths were refused. `relation_property()`
answers the other relations the prompt names in that same naming, picking the relation by the
property name's keywords and the shape by its suffix (`_groups`, `_pairs`, `_count`, else a
sorted id list), so a sibling that appears in a later block is answered without a new parser.
Where the bytes support a second reading, it rides along as an untimed alternative.

What the Day 30 clusters hold: exact copies, one-byte forgeries beside them (text "Prefereoce",
a nested ZIP whose local name differs from its central one, a nested member changed without its
CRC), nested ZIPs of one text file, and (Single Solve) a delivery manifest whose entries claim a
producer ("duplicate_ref" for a copy), a sha256 and a size. A damaged member never raises: it is
just bytes, and a ZIP that does not read has no members.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from io import BytesIO
from itertools import combinations
import json
from pathlib import PurePosixPath
import struct
from typing import Callable
import zipfile
import zlib

from .containers import ZIP_ERRORS, read_member

MANIFEST = "delivery-manifest.json"
MAX_MEMBERS = 4096
MAX_INFLATE = 16 * 1024 * 1024


@dataclass(frozen=True)
class Artifact:
    id: str
    path: str
    data: bytes = field(repr=False)
    sha256: str
    claim: dict


class Reading(str):
    """An answer plus the other readings an untimed attempt may try (AnswerCandidate.alternatives)."""
    alternatives: tuple[str, ...] = ()


def _reading(answer: str | None, *others: str | None) -> Reading | None:
    if answer is None:
        return None
    value = Reading(answer)
    value.alternatives = tuple(dict.fromkeys(o for o in others if o is not None and o != answer))
    return value


def _compact(value) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def zip_members(data: bytes) -> list[tuple[str, bytes]] | None:
    """(name, bytes) of every file in a ZIP, or None when it does not read (Day 30's forgeries)."""
    if not data.startswith(b"PK"):
        return None
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            infos = [i for i in archive.infolist() if not i.is_dir()][:MAX_MEMBERS]
            return [(info.filename, read_member(archive, info)) for info in infos]
    except ZIP_ERRORS:
        return None


def artifacts(data: bytes) -> list[Artifact] | None:
    """The cluster's artifacts in archive order, each named by its id: the delivery manifest's id
    where it lists the path, else the base name (Day 30 TT/Mastery: artifacts/<id>, no extension)."""
    members = zip_members(data)
    if members is None:
        return None
    claims: dict[str, dict] = {}
    for name, body in members:
        if PurePosixPath(name).name == MANIFEST:
            try:
                listed = json.loads(body).get("artifacts")
                claims = {a["path"]: a for a in listed if isinstance(a, dict) and isinstance(a.get("path"), str)}
            except (ValueError, AttributeError, TypeError):
                claims = {}
    found = []
    for name, body in members:
        if PurePosixPath(name).name == MANIFEST:
            continue
        claim = claims.get(name, {})
        named = claim.get("id") if isinstance(claim.get("id"), str) else PurePosixPath(name).name
        found.append(Artifact(named, name, body, hashlib.sha256(body).hexdigest(), claim))
    return found


def _groups(arts: list[Artifact], key: Callable[[Artifact], str]) -> list[list[str]]:
    by_key: dict[str, list[str]] = {}
    for art in arts:
        by_key.setdefault(key(art), []).append(art.id)
    return sorted(sorted(ids) for ids in by_key.values() if len(ids) > 1)


def exact_groups(arts: list[Artifact]) -> list[list[str]]:
    return _groups(arts, lambda art: art.sha256)


def _png_pixels(data: bytes, strict: bool = True) -> bytes | None:
    """IHDR plus the inflated IDAT stream: the image without its ancillary (metadata) chunks.

    Strict: the zlib stream must end. Day 30 TT forged a PNG by clearing its final-block bit
    (lagoon-06 beside ridge-54): a lenient inflate still gives the same pixels, a decoder does not."""
    at, header, idat = 8, b"", []
    while at + 12 <= len(data):
        length, kind = struct.unpack_from(">I4s", data, at)
        body = data[at + 8:at + 8 + length]
        if kind == b"IHDR":
            header = body
        elif kind == b"IDAT":
            idat.append(body)
        elif kind == b"IEND":
            break
        at += 12 + length
    if not header:
        return None
    stream = zlib.decompressobj()
    try:
        pixels = stream.decompress(b"".join(idat), MAX_INFLATE)
    except zlib.error:
        return None
    return header + pixels if stream.eof or not strict else None


def semantic_key(data: bytes, strict: bool = True) -> str:
    """What the bytes say, not how they are stored: JSON with sorted keys and no spacing; text
    without a BOM, CR, trailing blanks or trailing empty lines; a PNG's pixels without metadata
    chunks; a ZIP's sorted (name, content) pairs; gzip's content. Anything else is its bytes."""
    canonical = None
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        pixels = _png_pixels(data, strict)
        canonical = b"png:" + pixels if pixels is not None else None
    elif data.startswith(b"PK"):
        members = zip_members(data)
        if members is not None:
            canonical = b"zip:" + _compact(sorted((n, hashlib.sha256(b).hexdigest()) for n, b in members)).encode()
    elif data.startswith(b"\x1f\x8b"):
        try:
            canonical = b"gzip:" + semantic_key(zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(data, MAX_INFLATE), strict).encode()
        except zlib.error:
            canonical = None
    else:
        for encoding in (("utf-16",) if data[:2] in (b"\xff\xfe", b"\xfe\xff") else ("utf-8-sig",)):
            try:
                text = data.decode(encoding)
            except UnicodeDecodeError:
                break
            try:
                canonical = b"json:" + json.dumps(json.loads(text), sort_keys=True, separators=(",", ":")).encode()
            except ValueError:
                lines = [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
                canonical = b"text:" + "\n".join(lines).rstrip("\n").encode()
    return hashlib.sha256(canonical if canonical is not None else b"raw:" + data).hexdigest()


def near_copies(arts: list[Artifact]) -> list[tuple[str, str]]:
    """(forgery id, original id): an artifact that is no exact copy but differs from one in exactly one
    byte at equal length (Day 30's decoys). Originals are exact-group members, or any artifact when
    a cluster has no exact group."""
    counts: dict[str, int] = {}
    for art in arts:
        counts[art.sha256] = counts.get(art.sha256, 0) + 1
    originals = [art for art in arts if counts[art.sha256] > 1] or arts
    pairs = []
    for art in arts:
        if counts[art.sha256] > 1:
            continue
        for original in originals:
            if original is not art and len(original.data) == len(art.data) and original.sha256 != art.sha256 \
                    and sum(a != b for a, b in zip(original.data, art.data)) == 1:
                pairs.append((art.id, original.id))
                break
    return sorted(pairs)


def claim_breaks(arts: list[Artifact]) -> tuple[list[str], list[str]] | None:
    """Manifest entries the bytes contradict: (any claim - sha256, size_bytes, or a "duplicate_ref"
    producer with no identical twin -, sha256 claims only). None without a manifest."""
    if not any(art.claim for art in arts):
        return None
    counts: dict[str, int] = {}
    for art in arts:
        counts[art.sha256] = counts.get(art.sha256, 0) + 1
    wrong_digest = sorted(art.id for art in arts if isinstance(art.claim.get("sha256"), str)
                          and art.claim["sha256"].lower() != art.sha256)
    wrong_any = sorted(art.id for art in arts if art.id in wrong_digest
                       or (isinstance(art.claim.get("size_bytes"), int) and art.claim["size_bytes"] != len(art.data))
                       or (art.claim.get("producer_id") == "duplicate_ref" and counts[art.sha256] < 2))
    return wrong_any, wrong_digest


def containment(arts: list[Artifact]) -> tuple[list[list[str]], list[list[str]]]:
    """([container id, contained artifact id] where a nested file is byte for byte another artifact,
    [container id, nested file base name] for every nested file)."""
    by_digest: dict[str, list[str]] = {}
    for art in arts:
        by_digest.setdefault(art.sha256, []).append(art.id)
    by_id, by_name = set(), set()
    for art in arts:
        for name, body in zip_members(art.data) or []:
            by_name.add((art.id, PurePosixPath(name).name))
            for other in by_digest.get(hashlib.sha256(body).hexdigest(), []):
                if other != art.id:
                    by_id.add((art.id, other))
    return sorted(map(list, by_id)), sorted(map(list, by_name))


_KINDS = (  # First match wins: "semantic_duplicate_groups" is semantic, not exact.
    ("semantic", ("semantic", "normalized", "normalised", "canonical", "equivalent", "same_content")),
    ("contain", ("contain", "nested", "embedded", "inner", "parent", "child")),
    ("fabricated", ("fabricat", "decoy", "near", "tamper", "forg", "lookalike", "spoof", "one_byte", "hamming")),
    ("claim", ("provenance", "claim", "manifest", "mismatch", "producer")),
    ("exact", ("identical", "exact", "sha256", "duplicate", "copies", "copy")),
)
_SHAPES = ((("_count", "_number", "_total"), "count"),
           (("_groups", "_clusters", "_sets", "_classes", "_families"), "groups"),
           (("_pairs", "_edges", "_links", "_map", "_relations", "_graph"), "pairs"))


def _render(shape: str, name: str, groups=None, pairs=None, ids=None) -> str | None:
    """One relation in the shape the property's suffix asks for (None where it has no such shape)."""
    if ids is None:
        ids = sorted({i for group in (groups or pairs or []) for i in group}) if (groups or pairs) is not None else None
    if shape == "count":
        unit = groups if "group" in name or "cluster" in name else pairs if "pair" in name or "edge" in name else ids
        unit = unit if unit is not None else groups if groups is not None else pairs if pairs is not None else ids
        return None if unit is None else str(len(unit))
    if shape == "groups":
        if groups is None and ids is not None:
            groups = [ids] if ids else []  # A relation of single ids is one group.
        return None if groups is None else _compact(groups)
    if shape == "pairs":
        if pairs is None and groups is not None:
            pairs = sorted(list(p) for group in groups for p in combinations(group, 2))
        return None if pairs is None else _compact(pairs)
    return None if ids is None else _compact(ids)


def relation_property(name: str) -> Callable[[bytes], str | None] | None:
    """A reader for a `relation.<field>` property no exact parser names (see the module doc)."""
    if not name.startswith("relation."):
        return None
    field_name = name[len("relation."):]
    kind = next((k for k, words in _KINDS if any(w in field_name for w in words)), None)
    if kind is None:
        return None
    shape = next((s for suffixes, s in _SHAPES if field_name.endswith(suffixes)), "ids")

    def parse(data: bytes) -> str | None:
        arts = artifacts(data)
        if arts is None:
            return None
        render = lambda **reading: _render(shape, field_name, **reading)
        if kind == "exact":
            return _reading(render(groups=exact_groups(arts)))
        if kind == "semantic":
            groups = _groups(arts, lambda art: semantic_key(art.data))
            digest = {art.id: art.sha256 for art in arts}
            only = [g for g in groups if len({digest[i] for i in g}) > 1]  # Semantic but not exact copies.
            lenient = _groups(arts, lambda art: semantic_key(art.data, strict=False))
            return _reading(render(groups=groups), render(groups=lenient), render(groups=only))
        if kind == "contain":
            by_id, by_name = containment(arts)
            if not by_name:
                return _reading(render(pairs=[]))
            inner = "contained" in field_name or "child" in field_name or "inner" in field_name
            if shape == "ids":
                containers = sorted({p[0] for p in by_name})
                contained = sorted({p[1] for p in by_id}) or sorted({p[1] for p in by_name})
                return _reading(_compact(contained if inner else containers), _compact(containers if inner else contained))
            first, second = (by_id, by_name) if by_id else (by_name, by_id or None)
            return _reading(render(pairs=first), render(pairs=second) if second else None)
        if kind == "fabricated":
            pairs = near_copies(arts)
            forged = sorted({p[0] for p in pairs})
            originals = {art.id: art.sha256 for art in arts}
            grouped: dict[str, list[str]] = {}
            for forgery, original in pairs:
                grouped.setdefault(originals[original], []).append(forgery)
            groups = sorted(sorted(ids) for ids in grouped.values())
            # The other grouping: each imitated copy group together with its forgeries.
            imitated = sorted(sorted([a.id for a in arts if a.sha256 == sha] + ids) for sha, ids in grouped.items())
            claims = claim_breaks(arts)
            primary = render(groups=groups, pairs=[list(p) for p in pairs], ids=forged)
            return _reading(primary, render(groups=imitated) if shape == "groups" else None,
                            render(ids=claims[0]) if claims else None)
        claims = claim_breaks(arts)
        if claims is None:
            return None  # No manifest: nothing claims a provenance.
        return _reading(render(ids=claims[0]), render(ids=claims[1]))

    return parse
