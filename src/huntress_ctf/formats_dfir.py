"""Header fields of the forensic formats the course has not asked about yet (Day 24+ candidates).

Each Metadata day so far added one `Determine <format>.<field>` property on a new format
(JPEG, PNG, PDF, ZIP, PE, .NET, MSI, LNK, OOXML, e-mail, audio, video, ELF, Mach-O, APK,
JAR, SQLite). The remaining DFIR staples are read here, header fields only, from the
published specifications, so `suggest.confident()` and `autoprop` can map a new property to
a field on release day. Same shape as formats.py: (label, fields) pairs, one parser per
format, every parser guarded so damaged bytes give `damaged` instead of an exception.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import plistlib
import re
import struct
from typing import Callable


def _guarded(parse: Callable[[bytes, dict], None], data: bytes) -> dict:
    fields: dict = {}
    try:
        parse(data, fields)
    except (struct.error, IndexError, ValueError, UnicodeDecodeError, KeyError, OverflowError) as exc:
        fields["damaged"] = f"{type(exc).__name__} while reading"
    return fields


def _utf16(blob: bytes) -> str:
    return blob.decode("utf-16-le", "replace").split("\0", 1)[0]


def _filetime(value: int) -> str | None:
    if not value or value >= 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        moment = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value // 10)
    except OverflowError:  # Past the year 9999: a damaged field, not a time.
        return None
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _guid(raw: bytes) -> str:
    a, b, c = struct.unpack_from("<IHH", raw)
    return f"{a:08x}-{b:04x}-{c:04x}-{raw[8:10].hex()}-{raw[10:16].hex()}"


# --- Windows event log (EVTX) ------------------------------------------------------------------

def _evtx(data: bytes, f: dict) -> None:
    first, last, next_id, header_size, minor, major, block, chunks = struct.unpack_from("<QQQIHHHH", data, 8)
    flags, checksum = struct.unpack_from("<II", data, 0x78)
    f.update(first_chunk_number=first, last_chunk_number=last, next_record_id=next_id,
             header_size=header_size, version=f"{major}.{minor}", major_version=major, minor_version=minor,
             header_block_size=block, chunk_count=chunks, flags=flags, dirty=bool(flags & 1), full=bool(flags & 2),
             checksum=checksum)
    found, records, ids = 0, 0, []
    at = block or 4096
    while at + 0x28 <= len(data) and data[at:at + 8] == b"ElfChnk\0":
        first_id, last_id = struct.unpack_from("<QQ", data, at + 0x18)
        found += 1
        if last_id >= first_id:
            records += last_id - first_id + 1
            ids += [first_id, last_id]
        at += 0x10000
    f.update(chunks_present=found, record_count=records,
             first_record_id=min(ids) if ids else None, last_record_id=max(ids) if ids else None)


# --- Registry hive (regf) ----------------------------------------------------------------------

REGF_TYPES = {0: "primary", 1: "transaction_log", 2: "transaction_log", 6: "transaction_log_new"}


def _regf(data: bytes, f: dict) -> None:
    primary, secondary, written, major, minor, kind, fmt, root, size, cluster = struct.unpack_from(
        "<IIQIIIIIII", data, 4)
    checksum = 0
    for (word,) in struct.iter_unpack("<I", data[:508]):
        checksum ^= word
    f.update(primary_sequence_number=primary, secondary_sequence_number=secondary,
             dirty=primary != secondary, last_written_utc=_filetime(written), version=f"{major}.{minor}",
             major_version=major, minor_version=minor, file_type=kind, file_type_name=REGF_TYPES.get(kind, "unknown"),
             file_format=fmt, root_cell_offset=root, hive_bins_data_size=size, clustering_factor=cluster,
             file_name=_utf16(data[0x30:0x70]), checksum=struct.unpack_from("<I", data, 0x1FC)[0],
             checksum_valid=checksum == struct.unpack_from("<I", data, 0x1FC)[0])
    cell = 0x1000 + root + 4  # Cells start with a signed size; the key node follows.
    if data[0x1000:0x1004] == b"hbin" and data[cell:cell + 2] == b"nk":
        flags, written = struct.unpack_from("<HQ", data, cell + 2)
        subkeys, values = struct.unpack_from("<I", data, cell + 0x14)[0], struct.unpack_from("<I", data, cell + 0x24)[0]
        length = struct.unpack_from("<H", data, cell + 0x48)[0]
        raw = data[cell + 0x4C:cell + 0x4C + length]
        f.update(root_key_name=raw.decode("latin-1") if flags & 0x20 else raw.decode("utf-16-le", "replace"),
                 root_key_last_written_utc=_filetime(written), root_subkey_count=subkeys, root_value_count=values)


# --- Prefetch (SCCA; Windows 10+ MAM-compressed files report only their header) ----------------

PREFETCH_OFFSETS = {17: (0x78, 0x90), 23: (0x80, 0x98), 26: (0x80, 0xD0), 30: (0x80, 0xD0), 31: (0x80, 0xD0)}


def _prefetch(data: bytes, f: dict) -> None:
    if data[:3] == b"MAM":
        f.update(compressed=True, compression="xpress_huffman" if data[3] == 4 else f"0x{data[3]:02x}",
                 uncompressed_size=struct.unpack_from("<I", data, 4)[0])
        return
    version, _, size = struct.unpack_from("<I4sI", data, 0)
    f.update(compressed=False, version=version, file_size=size, executable_name=_utf16(data[0x10:0x4C]),
             prefetch_hash=struct.unpack_from("<I", data, 0x4C)[0])
    f["prefetch_hash_hex"] = f"{f['prefetch_hash']:08X}"
    if version in PREFETCH_OFFSETS:
        last_run, count = PREFETCH_OFFSETS[version]
        runs = 1 if version in (17, 23) else 8
        times = [_filetime(value) for (value,) in struct.iter_unpack("<Q", data[last_run:last_run + 8 * runs])]
        f.update(run_count=struct.unpack_from("<I", data, count)[0], last_run_utc=times[0],
                 last_run_times_utc=[time for time in times if time])


# --- Property lists (binary bplist00 and XML) --------------------------------------------------

def _plist(data: bytes, f: dict) -> None:
    value = plistlib.loads(data)
    f.update(format="binary" if data.startswith(b"bplist") else "xml", root_type=type(value).__name__)
    if data.startswith(b"bplist"):
        offset_size, ref_size, objects, top, table = struct.unpack_from(">6xBBQQQ", data, len(data) - 32)
        f.update(version=data[6:8].decode("ascii", "replace"), offset_int_size=offset_size,
                 object_ref_size=ref_size, object_count=objects, top_object=top, offset_table_offset=table)
    if isinstance(value, dict):
        f["keys"] = sorted(str(key) for key in value)
        for key, item in value.items():
            if isinstance(item, (str, int, float, bool)) and isinstance(key, str):
                f.setdefault(key, item)  # CFBundleIdentifier, Label, ProgramArguments' siblings ...
            elif isinstance(item, list) and all(isinstance(x, str) for x in item) and isinstance(key, str):
                f.setdefault(key, item)


# --- Images and media --------------------------------------------------------------------------

def _webp(data: bytes, f: dict) -> None:
    f["riff_size"] = struct.unpack_from("<I", data, 4)[0]
    kind = data[12:16]
    f["variant"] = kind.decode("ascii").strip()
    if kind == b"VP8X":
        flags = data[20]
        width = int.from_bytes(data[24:27], "little") + 1
        height = int.from_bytes(data[27:30], "little") + 1
        f.update(has_alpha=bool(flags & 0x10), animated=bool(flags & 0x02), has_icc=bool(flags & 0x20),
                 has_exif=bool(flags & 0x08), has_xmp=bool(flags & 0x04))
    elif kind == b"VP8L":
        bits = struct.unpack_from("<I", data, 21)[0]
        width, height = (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
        f["has_alpha"] = bool((bits >> 28) & 1)
    elif kind == b"VP8 ":
        if data[23:26] != b"\x9d\x01\x2a":
            raise ValueError("VP8 start code")
        width, height = struct.unpack_from("<HH", data, 26)
        width, height = width & 0x3FFF, height & 0x3FFF
    else:
        raise ValueError("WebP chunk")
    f.update(width=width, height=height, dimensions=f"{width}x{height}")


TIFF_TAGS = {256: "image_width", 257: "image_length", 258: "bits_per_sample", 259: "compression",
             262: "photometric", 270: "image_description", 271: "make", 272: "model", 274: "orientation",
             282: "x_resolution", 283: "y_resolution", 296: "resolution_unit", 305: "software",
             306: "date_time", 315: "artist", 33432: "copyright"}
_TIFF_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8, 11: 4, 12: 8}


def _tiff(data: bytes, f: dict) -> None:
    order = "<" if data[:2] == b"II" else ">"
    magic, ifd = struct.unpack_from(order + "HI", data, 2)
    f.update(byte_order="little" if order == "<" else "big", magic=magic, first_ifd_offset=ifd)
    count = struct.unpack_from(order + "H", data, ifd)[0]
    f["ifd0_entry_count"] = count
    for index in range(min(count, 512)):
        tag, kind, number, raw = struct.unpack_from(order + "HHI4s", data, ifd + 2 + 12 * index)
        name = TIFF_TAGS.get(tag)
        if name is None or kind not in _TIFF_SIZES:
            continue
        size = _TIFF_SIZES[kind] * number
        blob = raw[:size] if size <= 4 else data[struct.unpack(order + "I", raw)[0]:][:size]
        if kind == 2:
            f[name] = blob.split(b"\0", 1)[0].decode("utf-8", "replace")
        elif kind == 3:
            f[name] = struct.unpack_from(order + "H", blob)[0]
        elif kind == 4:
            f[name] = struct.unpack_from(order + "I", blob)[0]
        elif kind == 5:
            top, bottom = struct.unpack_from(order + "II", blob)
            f[name] = top / bottom if bottom else None
    if "image_width" in f and "image_length" in f:
        f["dimensions"] = f"{f['image_width']}x{f['image_length']}"


def _vint(data: bytes, at: int, keep_marker: bool = False) -> tuple[int, int]:
    first = data[at]
    length = 1
    while length <= 8 and not first & (0x80 >> (length - 1)):
        length += 1
    if length > 8:
        raise ValueError("EBML length")
    value = first if keep_marker else first & (0xFF >> length)
    for byte in data[at + 1:at + length]:
        value = (value << 8) | byte
    return value, at + length


def _ebml(data: bytes, f: dict) -> None:
    _, at = _vint(data, 0, keep_marker=True)
    size, at = _vint(data, at)
    end = at + size
    names = {0x4286: "ebml_version", 0x42F7: "ebml_read_version", 0x4282: "doc_type",
             0x4287: "doc_type_version", 0x4285: "doc_type_read_version"}
    while at < end:
        element, at = _vint(data, at, keep_marker=True)
        length, at = _vint(data, at)
        value = data[at:at + length]
        if element in names:
            f[names[element]] = value.decode("ascii", "replace") if element == 0x4282 else int.from_bytes(value, "big")
        at += length
    f["container"] = {"webm": "webm", "matroska": "matroska"}.get(f.get("doc_type", ""), f.get("doc_type"))


def _avi(data: bytes, f: dict) -> None:
    at = data.find(b"avih")
    if at < 0:
        raise ValueError("no avih")
    usec, max_rate, _, flags, frames, _, streams, _, width, height = struct.unpack_from("<10I", data, at + 8)
    f.update(microseconds_per_frame=usec, frame_rate=round(1_000_000 / usec, 3) if usec else None,
             max_bytes_per_second=max_rate, flags=flags, total_frames=frames, stream_count=streams,
             width=width, height=height, dimensions=f"{width}x{height}")
    handlers = re.findall(rb"strh(?:.{4})(vids|auds|txts)(.{4})", data[:65536], re.S)
    f["stream_types"] = [kind.decode() for kind, _ in handlers]
    f["video_fourcc"] = next((codec.decode("latin-1") for kind, codec in handlers if kind == b"vids"), None)


# --- Disks, archives, packages -----------------------------------------------------------------

VHD_TYPES = {2: "fixed", 3: "dynamic", 4: "differencing"}


def _vhd(data: bytes, f: dict) -> None:
    at = len(data) - 512 if data[-512:-504] == b"conectix" else 0
    (features, version, offset, stamp, app, app_version, host, original, current, geometry, kind,
     checksum) = struct.unpack_from(">IIQI4sI4sQQIII", data, at + 8)
    f.update(footer_offset=at, features=features, file_format_version=f"{version >> 16}.{version & 0xFFFF}",
             data_offset=offset, timestamp_utc=(datetime(2000, 1, 1, tzinfo=timezone.utc)
                                                + timedelta(seconds=stamp)).strftime("%Y-%m-%dT%H:%M:%SZ"),
             creator_application=app.decode("latin-1").strip("\0 "), creator_version=f"{app_version >> 16}.{app_version & 0xFFFF}",
             creator_host_os=host.decode("latin-1").strip("\0 "), original_size=original, current_size=current,
             disk_type=kind, disk_type_name=VHD_TYPES.get(kind, "unknown"), checksum=checksum,
             unique_id=_guid(data[at + 68:at + 84]), saved_state=bool(data[at + 84]))
    cylinders, heads, sectors = geometry >> 16, (geometry >> 8) & 0xFF, geometry & 0xFF
    f["disk_geometry"] = f"{cylinders}/{heads}/{sectors}"


def _vhdx(data: bytes, f: dict) -> None:
    f["creator"] = _utf16(data[8:8 + 512])
    for index, at in enumerate((0x10000, 0x20000), 1):
        if data[at:at + 4] == b"head":
            sequence, = struct.unpack_from("<Q", data, at + 8)
            log_version, version = struct.unpack_from("<HH", data, at + 0x40 + 16 * 3)
            f[f"header{index}_sequence_number"] = sequence
            f.setdefault("version", version)
            f.setdefault("log_version", log_version)


def _cab(data: bytes, f: dict) -> None:
    size, files_at = struct.unpack_from("<I4xI", data, 8)
    minor, major, folders, files, flags, set_id, index = struct.unpack_from("<BBHHHHH", data, 24)
    f.update(cabinet_size=size, version=f"{major}.{minor}", folder_count=folders, file_count=files,
             flags=flags, set_id=set_id, cabinet_index=index)
    names, at = [], files_at
    for _ in range(min(files, 65535)):
        at += 16
        end = data.index(b"\0", at)
        names.append(data[at:end].decode("utf-8" if struct.unpack_from("<H", data, at - 2)[0] & 0x80 else "latin-1"))
        at = end + 1
    f["names"] = names


XZ_CHECKS = {0: "none", 1: "crc32", 4: "crc64", 10: "sha256"}


def _xz(data: bytes, f: dict) -> None:
    check = data[7] & 0x0F
    f.update(stream_flags=data[7], check_type=check, check_name=XZ_CHECKS.get(check, "unknown"))


def _bzip2(data: bytes, f: dict) -> None:
    level = int(chr(data[3]))
    f.update(block_size_level=level, block_size_bytes=level * 100_000)


def _zstd(data: bytes, f: dict) -> None:
    descriptor = data[4]
    single = bool(descriptor & 0x20)
    f.update(frame_header_descriptor=descriptor, single_segment=single, content_checksum=bool(descriptor & 0x04),
             dictionary_id_size=(0, 1, 2, 4)[descriptor & 3])
    size_flag = descriptor >> 6
    at = 5 + (0 if single else 1) + f["dictionary_id_size"]
    width = (1 if single else 0, 2, 4, 8)[size_flag]
    if width:
        value = int.from_bytes(data[at:at + width], "little")
        f["content_size"] = value + 256 if width == 2 else value


def _ar(data: bytes, f: dict) -> None:
    names, at = [], 8
    while at + 60 <= len(data) and len(names) < 4096:
        header = data[at:at + 60]
        name = header[:16].decode("latin-1").strip()
        size = int(header[48:58].decode().strip() or 0)
        names.append(name.rstrip("/"))
        if name.rstrip("/") == "debian-binary":
            f["debian_format_version"] = data[at + 60:at + 60 + size].decode("ascii", "replace").strip()
        at += 60 + size + (size & 1)
    f.update(names=names, member_count=len(names), package="deb" if "debian-binary" in names else "ar")


# Final magic numbers of each CPython release (Lib/importlib/_bootstrap_external.py).
PYC_MAGIC = ((3351, "3.5"), (3379, "3.6"), (3394, "3.7"), (3413, "3.8"), (3425, "3.9"), (3439, "3.10"),
             (3495, "3.11"), (3531, "3.12"), (3571, "3.13"))


def _pyc(data: bytes, f: dict) -> None:
    magic, flags = struct.unpack_from("<H2xI", data, 0)
    version = next((name for number, name in PYC_MAGIC if magic <= number), None)
    if version is None and magic > PYC_MAGIC[-1][0]:
        version = "3.14+"
    f.update(magic_number=magic, magic_hex=data[:4].hex(), python_version=version, flags=flags,
             hash_based=bool(flags & 1), check_source=bool(flags & 2))
    if flags & 1:
        f["source_hash"] = data[8:16].hex()
    else:
        stamp, size = struct.unpack_from("<II", data, 8)
        f.update(source_mtime=stamp, source_size=size,
                 source_mtime_utc=datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))


def _rtf(data: bytes, f: dict) -> None:
    text = data[:65536].decode("latin-1")
    for key in ("ansicpg", "deff", "deflang"):
        match = re.search(rf"\\{key}(-?\d+)", text)
        if match:
            f[key] = int(match[1])
    match = re.search(r"\{\\\*\\generator ([^;}]*)", text)
    if match:
        f["generator"] = match[1].strip()
    for key in ("title", "subject", "author", "operator", "keywords", "comment", "company", "manager"):
        match = re.search(rf"\{{\\{key} ([^}}]*)\}}", text)
        if match:
            f[key] = match[1].strip()
    for key in ("creatim", "revtim", "printim"):
        match = re.search(rf"\{{\\{key}((?:\\[a-z]+\d+)+)\}}", text)
        if match:
            parts = dict(re.findall(r"\\([a-z]+)(\d+)", match[1]))
            f[key] = "{:04d}-{:02d}-{:02d}T{:02d}:{:02d}".format(*(int(parts.get(k, 0)) for k in ("yr", "mo", "dy", "hr", "min")))
    f["version"] = int(re.match(r"\{\\rtf(\d+)", text)[1])


def _crx(data: bytes, f: dict) -> None:
    version = struct.unpack_from("<I", data, 4)[0]
    f["version"] = version
    if version == 2:
        key, signature = struct.unpack_from("<II", data, 8)
        f.update(public_key_length=key, signature_length=signature, zip_offset=16 + key + signature)
    else:
        header = struct.unpack_from("<I", data, 8)[0]
        f.update(header_size=header, zip_offset=12 + header)


# Extensible Storage Engine (SRUM, WebCache, Windows.edb): fields at libesedb's documented offsets.
ESE_STATES = {1: "just_created", 2: "dirty_shutdown", 3: "clean_shutdown", 4: "being_converted", 5: "force_detach"}


def _ese(data: bytes, f: dict) -> None:
    version, kind = struct.unpack_from("<II", data, 8)
    state = struct.unpack_from("<I", data, 52)[0]
    f.update(format_version=f"0x{version:x}", file_type="database" if kind == 0 else "streaming",
             database_state=state, database_state_name=ESE_STATES.get(state, "unknown"),
             format_revision=struct.unpack_from("<I", data, 232)[0], page_size=struct.unpack_from("<I", data, 236)[0])


# --- OLE2 compound documents (.doc/.xls/.ppt/.msg): stream names and SummaryInformation ----------

SUMMARY_PROPERTIES = {2: "title", 3: "subject", 4: "author", 5: "keywords", 6: "comments", 7: "template",
                      8: "last_author", 9: "revision_number", 11: "last_printed_utc", 12: "created_utc",
                      13: "last_saved_utc", 14: "page_count", 15: "word_count", 16: "char_count",
                      18: "application_name", 19: "security"}


def _property_set(stream: bytes) -> dict:
    offset = struct.unpack_from("<I", stream, 44)[0]  # First section (after the header and FMTID).
    _, count = struct.unpack_from("<II", stream, offset)
    out: dict = {}
    codepage = 1252
    entries = [struct.unpack_from("<II", stream, offset + 8 + 8 * index) for index in range(min(count, 256))]
    for pid, at in entries:
        kind = struct.unpack_from("<H", stream, offset + at)[0]
        body = offset + at + 4
        if pid == 1 and kind == 2:
            codepage = struct.unpack_from("<H", stream, body)[0] or 1252
    for pid, at in entries:
        name = SUMMARY_PROPERTIES.get(pid)
        kind = struct.unpack_from("<H", stream, offset + at)[0]
        body = offset + at + 4
        if name is None:
            continue
        if kind == 0x1E:
            length = struct.unpack_from("<I", stream, body)[0]
            raw = stream[body + 4:body + 4 + length].split(b"\0", 1)[0]
            try:
                out[name] = raw.decode("utf-8" if codepage == 65001 else f"cp{codepage}", "replace")
            except LookupError:  # A code page Python has no codec for (cp1200, a damaged field): no value.
                continue
        elif kind == 0x03:
            out[name] = struct.unpack_from("<i", stream, body)[0]
        elif kind == 0x40:
            out[name] = _filetime(struct.unpack_from("<Q", stream, body)[0])
    return out


def _ole(data: bytes, f: dict) -> None:
    from .solvers.metadata import _cfb_streams, _msi_name  # The lane's OLE2 reader (MSI, Day 13).

    streams = _cfb_streams(data)
    if streams is None:
        raise ValueError("CFB directory")
    names = sorted(_msi_name(name).lstrip("\x01\x05") for name in streams)
    f.update(stream_names=names, stream_count=len(names))
    kind = ("word" if "WordDocument" in names else "excel" if "Workbook" in names or "Book" in names
            else "powerpoint" if "PowerPoint Document" in names else "outlook_msg" if any(
                name.startswith("__substg1.0_") for name in names) else "msi" if any(
                name.startswith("!") or name.startswith("_") for name in names) else "ole")
    f["document_type"] = kind
    summary = next((blob for name, blob in streams.items() if name.endswith("SummaryInformation")
                    and "Document" not in name), None)
    if summary:
        f.update(_property_set(summary))


def formats(data: bytes) -> list[tuple[str, dict]]:
    checks = (
        ("evtx", data.startswith(b"ElfFile\0") and len(data) >= 0x80, _evtx),
        ("regf", data.startswith(b"regf") and len(data) >= 0x200, _regf),
        ("prefetch", (data[4:8] == b"SCCA" and len(data) >= 0x100) or (data[:3] == b"MAM" and len(data) >= 8), _prefetch),
        ("plist", data.startswith(b"bplist0") or (data.lstrip()[:5] == b"<?xml" and b"<plist" in data[:1024]), _plist),
        ("webp", data[:4] == b"RIFF" and data[8:12] == b"WEBP" and len(data) >= 25, _webp),
        ("tiff", data[:4] in (b"II*\0", b"MM\0*") and len(data) >= 8, _tiff),
        ("ebml", data.startswith(b"\x1a\x45\xdf\xa3") and len(data) >= 8, _ebml),
        ("avi", data[:4] == b"RIFF" and data[8:12] == b"AVI " and len(data) >= 64, _avi),
        ("vhd", (data.startswith(b"conectix") or data[-512:-504] == b"conectix") and len(data) >= 512, _vhd),
        ("vhdx", data.startswith(b"vhdxfile") and len(data) >= 520, _vhdx),
        ("cab", data.startswith(b"MSCF") and len(data) >= 36, _cab),
        ("xz", data.startswith(b"\xfd7zXZ\0") and len(data) >= 12, _xz),
        ("bzip2", data.startswith(b"BZh") and data[3:4].isdigit() and len(data) >= 10, _bzip2),
        ("zstd", data.startswith(b"\x28\xb5\x2f\xfd") and len(data) >= 6, _zstd),
        ("ar", data.startswith(b"!<arch>\n"), _ar),
        ("pyc", len(data) >= 16 and data[2:4] == b"\r\n" and 3000 <= int.from_bytes(data[:2], "little") < 4000, _pyc),
        ("rtf", data.startswith(b"{\\rtf"), _rtf),
        ("crx", data.startswith(b"Cr24") and len(data) >= 16, _crx),
        ("ese", len(data) >= 240 and data[4:8] == b"\xef\xcd\xab\x89", _ese),
        ("ole", data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") and len(data) >= 512, _ole),
    )
    found = [(label, _guarded(parse, data)) for label, match, parse in checks if match]
    if data.startswith(b"\x04\x22\x4d\x18") and len(data) >= 7:
        descriptor = data[4]
        found.append(("lz4", {"version": descriptor >> 6, "content_checksum": bool(descriptor & 0x04),
                              "content_size_present": bool(descriptor & 0x08),
                              "block_max_size_bytes": {4: 65536, 5: 262144, 6: 1 << 20, 7: 4 << 20}.get((data[5] >> 4) & 7)}))
    return found
