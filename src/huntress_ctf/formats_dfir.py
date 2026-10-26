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
    destlist = next((blob for name, blob in streams.items() if _msi_name(name) == "DestList"), None)
    if destlist:  # An automaticDestinations-ms Jump List: DestList plus one LNK stream per entry.
        from .formats import _guarded as guarded, _lnk

        f["document_type"] = "jump_list"
        try:
            f.update(_destlist(destlist))
        except (struct.error, UnicodeDecodeError, ValueError):
            f["destlist_damaged"] = True
        links = [guarded(_lnk, blob) for name, blob in sorted(streams.items(), key=lambda item: _msi_name(item[0]))
                 if blob[:4] == b"L\0\0\0"]
        f.update(lnk_count=len(links), target_paths=[l["target_path"] for l in links if l.get("target_path")])


# --- Days 26+ candidates: NTFS, USN journal, Recycle Bin, Jump Lists, dumps, tasks, images, certs ---

def _unix(value: int) -> str | None:
    try:
        return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if value else None
    except (OverflowError, OSError, ValueError):
        return None


def _fixups(record: bytes) -> bytes:
    """An NTFS multi-sector record with its update sequence array applied (sector ends restored)."""
    usa_offset, usa_count = struct.unpack_from("<HH", record, 4)
    if not usa_count or usa_offset + 2 * usa_count > len(record):
        return record
    fixed = bytearray(record)
    check = record[usa_offset:usa_offset + 2]
    for index in range(1, usa_count):
        end = index * 512 - 2
        if end + 2 > len(fixed) or fixed[end:end + 2] != check:
            raise ValueError("NTFS fixup mismatch")
        fixed[end:end + 2] = record[usa_offset + 2 * index:usa_offset + 2 * index + 2]
    return bytes(fixed)


FILE_NAME_SPACES = {0: "posix", 1: "win32", 2: "dos", 3: "win32_and_dos"}
ATTRIBUTE_NAMES = {0x10: "$STANDARD_INFORMATION", 0x20: "$ATTRIBUTE_LIST", 0x30: "$FILE_NAME", 0x40: "$OBJECT_ID",
                   0x50: "$SECURITY_DESCRIPTOR", 0x60: "$VOLUME_NAME", 0x70: "$VOLUME_INFORMATION", 0x80: "$DATA",
                   0x90: "$INDEX_ROOT", 0xA0: "$INDEX_ALLOCATION", 0xB0: "$BITMAP", 0xC0: "$REPARSE_POINT",
                   0x100: "$LOGGED_UTILITY_STREAM"}


def _mft(data: bytes, f: dict) -> None:
    size = struct.unpack_from("<I", data, 28)[0] or 1024
    if not 256 <= size <= 65536:
        raise ValueError("MFT record size")
    record = _fixups(data[:size])
    lsn, sequence, links, first, flags, used, allocated, base, next_id = struct.unpack_from("<QHHHHIIQH", record, 8)
    f.update(signature=record[:4].decode("ascii"), logfile_sequence_number=lsn, sequence_number=sequence,
             hard_link_count=links, flags=flags, in_use=bool(flags & 1), is_directory=bool(flags & 2),
             used_size=used, allocated_size=allocated, record_size=size, base_record_number=base & 0xFFFFFFFFFFFF,
             next_attribute_id=next_id)
    if first >= 0x30:
        f["record_number"] = struct.unpack_from("<I", record, 44)[0]
    at, types, names, streams = first, [], [], []
    while at + 16 <= min(used or size, size) and len(types) < 64:
        kind, length = struct.unpack_from("<II", record, at)
        if kind == 0xFFFFFFFF or length < 16:
            break
        resident = record[at + 8] == 0
        name_length, name_offset = record[at + 9], struct.unpack_from("<H", record, at + 10)[0]
        attr_name = record[at + name_offset:at + name_offset + 2 * name_length].decode("utf-16-le", "replace")
        types.append(ATTRIBUTE_NAMES.get(kind, f"0x{kind:x}"))
        body = record[at + struct.unpack_from("<H", record, at + 20)[0]:] if resident else b""
        if kind == 0x10 and resident:
            created, modified, changed, accessed, attributes = struct.unpack_from("<QQQQI", body, 0)
            f.update(si_created=_filetime(created), si_modified=_filetime(modified),
                     si_mft_modified=_filetime(changed), si_accessed=_filetime(accessed), file_attributes=attributes)
        elif kind == 0x30 and resident:
            parent, created, modified, changed, accessed, alloc, real = struct.unpack_from("<QQQQQQQ", body, 0)
            name = body[66:66 + 2 * body[64]].decode("utf-16-le", "replace")
            names.append((body[65] == 2, name, parent, created, modified, changed, accessed, real))
        elif kind == 0x80:
            real = struct.unpack_from("<I", record, at + 16)[0] if resident else struct.unpack_from("<Q", record, at + 48)[0]
            if attr_name:
                streams.append(attr_name)
            else:
                f["data_size"] = real
                f["data_resident"] = resident
        at += length
    f.update(attribute_types=types, alternate_data_streams=streams, has_alternate_data_stream=bool(streams))
    if names:
        names.sort()  # A Win32 name before its DOS 8.3 alias.
        _, name, parent, created, modified, changed, accessed, real = names[0]
        f.update(file_name=name, file_names=[n[1] for n in names], parent_record_number=parent & 0xFFFFFFFFFFFF,
                 parent_sequence_number=parent >> 48, fn_created=_filetime(created), fn_modified=_filetime(modified),
                 fn_mft_modified=_filetime(changed), fn_accessed=_filetime(accessed), fn_real_size=real)
        if f.get("si_created") and f.get("fn_created"):
            f["si_before_fn_created"] = f["si_created"] < f["fn_created"]  # A classic timestomp sign.
    count = len(data) // size
    if count > 1:
        f.update(record_count=count, in_use_record_count=sum(
            1 for i in range(min(count, 1 << 20)) if data[i * size:i * size + 4] == b"FILE" and data[i * size + 22] & 1))


USN_REASONS = ((0x1, "DATA_OVERWRITE"), (0x2, "DATA_EXTEND"), (0x4, "DATA_TRUNCATION"),
               (0x10, "NAMED_DATA_OVERWRITE"), (0x20, "NAMED_DATA_EXTEND"), (0x40, "NAMED_DATA_TRUNCATION"),
               (0x100, "FILE_CREATE"), (0x200, "FILE_DELETE"), (0x400, "EA_CHANGE"), (0x800, "SECURITY_CHANGE"),
               (0x1000, "RENAME_OLD_NAME"), (0x2000, "RENAME_NEW_NAME"), (0x4000, "INDEXABLE_CHANGE"),
               (0x8000, "BASIC_INFO_CHANGE"), (0x10000, "HARD_LINK_CHANGE"), (0x20000, "COMPRESSION_CHANGE"),
               (0x40000, "ENCRYPTION_CHANGE"), (0x80000, "OBJECT_ID_CHANGE"), (0x100000, "REPARSE_POINT_CHANGE"),
               (0x200000, "STREAM_CHANGE"), (0x80000000, "CLOSE"))


_NONZERO = re.compile(rb"[^\0]")


def _usn_start(data: bytes) -> int | None:
    """Offset of the first USN_RECORD_V2/V3 ($J starts with sparse zeros), or None."""
    first = _NONZERO.search(data, 0, 1 << 24)  # No copy of the data, unlike lstrip().
    if first is None:
        return None
    at = first.start() - first.start() % 8
    if at + 60 > len(data):
        return None
    length, major, minor = struct.unpack_from("<IHH", data, at)
    name_offset = struct.unpack_from("<H", data, at + (58 if major == 2 else 74))[0] if major in (2, 3) else 0
    if 60 <= length <= 0x10000 and length % 8 == 0 and minor == 0 and name_offset == (60 if major == 2 else 76):
        return at
    return None


def _usn(data: bytes, f: dict) -> None:
    at = _usn_start(data)
    if at is None:
        raise ValueError("no USN record")
    records, names, reasons, usns, stamps, deleted, created = 0, [], 0, [], [], [], []
    while at + 60 <= len(data) and records < 1_000_000:
        length, major = struct.unpack_from("<IH", data, at)
        if length == 0:  # Zero padding up to the next record.
            nxt = _NONZERO.search(data, at)
            if nxt is None:
                break
            at = nxt.start() - nxt.start() % 8
            continue
        if length < 60 or at + length > len(data) or major not in (2, 3):
            break
        tail = at + (24 if major == 2 else 40)
        usn, stamp, reason = struct.unpack_from("<QQI", data, tail)
        name_length, name_offset = struct.unpack_from("<HH", data, tail + 32)
        name = data[at + name_offset:at + name_offset + name_length].decode("utf-16-le", "replace")
        records += 1
        reasons |= reason
        usns.append(usn)
        stamps.append(stamp)
        if name not in names:
            names.append(name)
        if reason & 0x200 and name not in deleted:
            deleted.append(name)
        if reason & 0x100 and name not in created:
            created.append(name)
        at += length
    f.update(record_count=records, major_version=struct.unpack_from("<H", data, _usn_start(data) + 4)[0],
             first_usn=min(usns) if usns else None, last_usn=max(usns) if usns else None,
             first_timestamp=_filetime(min(stamps)) if stamps else None,
             last_timestamp=_filetime(max(stamps)) if stamps else None,
             file_names=names, file_name_count=len(names), deleted_file_names=deleted, created_file_names=created,
             reasons=[label for bit, label in USN_REASONS if reasons & bit])


def _recycle_i(data: bytes, f: dict) -> None:
    version, size, deleted = struct.unpack_from("<QQQ", data, 0)
    if version == 2:
        count = struct.unpack_from("<I", data, 24)[0]
        path = data[28:28 + 2 * count].decode("utf-16-le", "replace").split("\0", 1)[0]
    else:
        path = _utf16(data[24:24 + 520])
    f.update(version=version, original_size=size, file_size=size, deleted_utc=_filetime(deleted),
             deletion_time=_filetime(deleted), original_path=path, original_name=re.split(r"[\\/]", path)[-1])


def _custom_destinations(data: bytes, f: dict) -> None:
    from .formats import _guarded as guarded, _lnk

    starts = [m.start() for m in re.finditer(re.escape(b"L\0\0\0\x01\x14\x02\0"), data[:16 << 20])][:256]
    links = [guarded(_lnk, data[a:b]) for a, b in zip(starts, starts[1:] + [len(data)])]
    f.update(version=struct.unpack_from("<I", data, 0)[0], lnk_count=len(links),
             target_paths=[l["target_path"] for l in links if l.get("target_path")],
             arguments=[l["arguments"] for l in links if l.get("arguments")])


def _destlist(stream: bytes) -> dict:
    """Jump List DestList: header, then entries (Windows 7 = version 1; 10 = 3/4)."""
    version, count, pinned, _, last_id, _, actions = struct.unpack_from("<IIIfIII", stream, 0)
    out: dict = {"destlist_version": version, "destlist_entry_count": count, "destlist_pinned_count": pinned,
                 "destlist_last_entry_number": last_id, "destlist_action_count": actions}
    path_at = 0x6C if version == 1 else 0x7C
    entries, at = [], 32
    while at + path_at + 2 <= len(stream) and len(entries) < min(count, 4096):
        host = stream[at + 0x48:at + 0x58].split(b"\0", 1)[0]
        number, = struct.unpack_from("<I", stream, at + 0x58)
        access, pin = struct.unpack_from("<Qi", stream, at + 0x60)
        length, = struct.unpack_from("<H", stream, at + path_at)
        path = stream[at + path_at + 2:at + path_at + 2 + 2 * length].decode("utf-16-le")
        if not host.isascii() or not path.isprintable():
            break  # A layout this reader does not know: header fields only.
        entry = {"entry_number": number, "hostname": host.decode(), "path": path, "last_access": _filetime(access),
                 "pinned": pin >= 0}
        if version != 1:
            entry["access_count"] = struct.unpack_from("<I", stream, at + 0x70)[0]
        entries.append(entry)
        at += path_at + 2 + 2 * length + (0 if version == 1 else 4)
    if entries:
        out.update(destlist_entries=entries, destlist_paths=[e["path"] for e in entries],
                   destlist_hostnames=sorted({e["hostname"] for e in entries}),
                   destlist_most_recent_path=max(entries, key=lambda e: e["last_access"] or "")["path"])
    return out


MINIDUMP_STREAMS = {3: "ThreadListStream", 4: "ModuleListStream", 5: "MemoryListStream", 6: "ExceptionStream",
                    7: "SystemInfoStream", 9: "Memory64ListStream", 10: "CommentStreamA", 11: "CommentStreamW",
                    12: "HandleDataStream", 15: "MiscInfoStream", 16: "MemoryInfoListStream",
                    17: "ThreadInfoListStream", 21: "SystemMemoryInfoStream", 22: "ProcessVmCountersStream"}
PROCESSOR_ARCHITECTURES = {0: "x86", 5: "arm", 6: "ia64", 9: "amd64", 12: "arm64", 0xFFFF: "unknown"}


def _minidump(data: bytes, f: dict) -> None:
    version, count, directory, checksum, stamp, flags = struct.unpack_from("<IIIIIQ", data, 4)
    f.update(version=version & 0xFFFF, implementation_version=version >> 16, stream_count=count,
             checksum=checksum, timestamp=_unix(stamp), timestamp_unix=stamp, flags=flags)
    streams = {}
    for index in range(min(count, 512)):
        kind, size, rva = struct.unpack_from("<III", data, directory + 12 * index)
        streams.setdefault(kind, (size, rva))
    f["stream_types"] = [MINIDUMP_STREAMS.get(kind, str(kind)) for kind in streams]

    def text(rva: int) -> str:
        length = struct.unpack_from("<I", data, rva)[0]
        return data[rva + 4:rva + 4 + min(length, 4096)].decode("utf-16-le", "replace")
    if 7 in streams:
        arch, level, revision, cpus, product, major, minor, build, platform, csd = struct.unpack_from(
            "<HHHBBIIIII", data, streams[7][1])
        f.update(processor_architecture=PROCESSOR_ARCHITECTURES.get(arch, str(arch)), number_of_processors=cpus,
                 os_version=f"{major}.{minor}.{build}", os_build=build, product_type=product, platform_id=platform)
    if 4 in streams:
        rva = streams[4][1]
        modules = struct.unpack_from("<I", data, rva)[0]
        names = []
        for index in range(min(modules, 4096)):
            base, size, _, stamp, name_rva = struct.unpack_from("<QIIII", data, rva + 4 + 108 * index)
            names.append(text(name_rva))
        f.update(module_count=modules, module_names=names, main_module=names[0] if names else None,
                 main_module_name=re.split(r"[\\/]", names[0])[-1] if names else None)
    if 3 in streams:
        f["thread_count"] = struct.unpack_from("<I", data, streams[3][1])[0]
    if 15 in streams:
        size, flags1, pid, created = struct.unpack_from("<IIII", data, streams[15][1])
        if flags1 & 1:
            f["process_id"] = pid
        if flags1 & 2:
            f["process_create_time"] = _unix(created)
    if 6 in streams:
        thread, _, code, _, _, address = struct.unpack_from("<IIIIQQ", data, streams[6][1])
        f.update(exception_thread_id=thread, exception_code=f"0x{code:08x}", exception_address=f"0x{address:x}")


_TASK16, _MIT16 = "<Task".encode("utf-16-le"), "mit/task".encode("utf-16-le")


def _scheduled_task(data: bytes, f: dict) -> None:
    import xml.etree.ElementTree as ET

    text = data.decode("utf-16" if data[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig")
    try:  # (an encoding="UTF-16" declaration does not fit a str, so it is dropped first)
        root = ET.fromstring(re.sub(r"<\?xml[^>]*\?>", "", text, count=1))
    except ET.ParseError as exc:  # a SyntaxError, which _guarded does not catch
        raise ValueError("task XML") from exc
    local = lambda node: node.tag.rsplit("}", 1)[-1]
    find = lambda path: next((n for n in root.iter() if local(n) == path), None)
    value = lambda path: (find(path).text or "").strip() if find(path) is not None else None
    triggers = find("Triggers")
    actions = find("Actions")
    execs = [n for n in actions.iter() if local(n) == "Exec"] if actions is not None else []
    f.update(task_version=root.get("version"), author=value("Author"), date=value("Date"), uri=value("URI"),
             description=value("Description"), user_id=value("UserId"), run_level=value("RunLevel"),
             logon_type=value("LogonType"), hidden=value("Hidden"), enabled=value("Enabled"),
             trigger_types=[local(n) for n in triggers] if triggers is not None else [],
             action_count=len(list(actions)) if actions is not None else 0,
             commands=[(e.find("{*}Command").text or "").strip() for e in execs if e.find("{*}Command") is not None],
             arguments=[(e.find("{*}Arguments").text or "").strip() for e in execs if e.find("{*}Arguments") is not None],
             com_class_ids=[(n.text or "").strip() for n in root.iter() if local(n) == "ClassId"])
    f["command"] = f["commands"][0] if f["commands"] else None
    f["command_arguments"] = f["arguments"][0] if f["arguments"] else None


EWF_HEADER_KEYS = {"c": "case_number", "n": "evidence_number", "a": "description", "e": "examiner_name",
                   "t": "notes", "av": "acquisition_software_version", "ov": "os_version",
                   "m": "acquisition_date", "u": "system_date", "p": "password_hash", "md": "model",
                   "sn": "serial_number", "l": "device_label", "pid": "process_identifier"}


def _ewf(data: bytes, f: dict) -> None:
    from .containers import ZIP_ERRORS, decompress

    f.update(segment_number=struct.unpack_from("<H", data, 9)[0])
    at, types, seen = 13, [], set()
    while at + 76 <= len(data) and len(types) < 1024 and at not in seen:
        seen.add(at)
        kind = data[at:at + 16].split(b"\0", 1)[0].decode("ascii")
        following, size = struct.unpack_from("<QQ", data, at + 16)
        types.append(kind)
        body = data[at + 76:at + size] if size >= 76 else b""
        if kind in ("header", "header2") and "case_number" not in f:
            try:
                raw = decompress(body, "zlib", 1 << 20)
            except ZIP_ERRORS as exc:
                raise ValueError("EWF header") from exc
            text = raw.decode("utf-16" if kind == "header2" else "latin-1").replace("\r", "")
            lines = text.split("\n")
            keys = next((i for i, line in enumerate(lines) if line.startswith("c\t") or "\tc\t" in line), None)
            if keys is not None and keys + 1 < len(lines):
                for key, item in zip(lines[keys].split("\t"), lines[keys + 1].split("\t")):
                    f[EWF_HEADER_KEYS.get(key, f"header_{key}")] = item
        elif kind in ("volume", "disk") and len(body) >= 24:
            media, chunks, per_chunk, per_sector, sectors = struct.unpack_from("<B3xIIIQ", body, 0)
            f.update(media_type=media, chunk_count=chunks, sectors_per_chunk=per_chunk,
                     bytes_per_sector=per_sector, sector_count=sectors, media_size_bytes=sectors * per_sector)
        elif kind == "hash" and len(body) >= 16:
            f["md5"] = body[:16].hex()
        elif kind == "digest" and len(body) >= 36:
            f.update(md5=body[:16].hex(), sha1=body[16:36].hex())
        if kind in ("done", "next") or following <= at:
            break
        at = following
    f["section_types"] = types


MBR_TYPES = {0x07: "ntfs_exfat", 0x0B: "fat32_chs", 0x0C: "fat32_lba", 0x0E: "fat16_lba", 0x05: "extended",
             0x0F: "extended_lba", 0x82: "linux_swap", 0x83: "linux", 0x8E: "linux_lvm", 0xEE: "gpt_protective",
             0xEF: "efi_system", 0x27: "windows_recovery"}


def _mbr(data: bytes, f: dict) -> None:
    parts = []
    for index in range(4):
        status, kind, start, sectors = struct.unpack_from("<B3xB3xII", data, 446 + 16 * index)
        if kind:
            parts.append({"index": index + 1, "bootable": status == 0x80, "type": f"0x{kind:02x}",
                          "type_name": MBR_TYPES.get(kind), "start_lba": start, "sector_count": sectors})
    f.update(disk_signature=f"0x{struct.unpack_from('<I', data, 440)[0]:08x}", partition_count=len(parts),
             partitions=parts, partition_types=[p["type"] for p in parts],
             bootable_partition=next((p["index"] for p in parts if p["bootable"]), None),
             first_partition_start_lba=parts[0]["start_lba"] if parts else None)


def _gpt(data: bytes, f: dict) -> None:
    at = 512
    revision, size, _, _, current, backup, first, last = struct.unpack_from("<IIIIQQQQ", data, at + 8)
    disk = _guid(data[at + 56:at + 72])
    entries_lba, count, entry_size = struct.unpack_from("<QII", data, at + 72)
    parts = []
    for index in range(min(count, 256)):
        entry = at - 512 + entries_lba * 512 + index * entry_size
        if entry + 128 > len(data):
            break
        kind = data[entry:entry + 16]
        if kind == bytes(16):
            continue
        start, end = struct.unpack_from("<QQ", data, entry + 32)
        parts.append({"type_guid": _guid(kind), "unique_guid": _guid(data[entry + 16:entry + 32]),
                      "first_lba": start, "last_lba": end, "name": _utf16(data[entry + 56:entry + 128])})
    f.update(revision=f"{revision >> 16}.{revision & 0xFFFF}", header_size=size, disk_guid=disk,
             partition_entry_count=count, partition_count=len(parts), partitions=parts,
             partition_names=[p["name"] for p in parts], partition_type_guids=[p["type_guid"] for p in parts],
             first_usable_lba=first, last_usable_lba=last, backup_lba=backup)


def _ntfs_boot(data: bytes, f: dict) -> None:
    per_sector, per_cluster = struct.unpack_from("<HB", data, 11)
    sectors, mft, mirror, record = struct.unpack_from("<QQQb", data, 40)
    cluster = per_sector * per_cluster
    f.update(oem_id=data[3:11].decode("ascii").strip(), bytes_per_sector=per_sector, sectors_per_cluster=per_cluster,
             cluster_size=cluster, total_sectors=sectors, volume_size_bytes=sectors * per_sector,
             mft_cluster=mft, mft_offset=mft * cluster, mft_mirror_cluster=mirror,
             mft_record_size=2 ** -record if record < 0 else record * cluster,
             volume_serial_number=f"{struct.unpack_from('<Q', data, 72)[0]:016X}")


def _dmg(data: bytes, f: dict) -> None:
    koly = data[-512:]
    version, size, flags, _, data_offset, data_length, rsrc_offset, rsrc_length, segment, segments = \
        struct.unpack_from(">IIIQQQQQII", koly, 4)
    xml_offset, xml_length = struct.unpack_from(">QQ", koly, 0xD8)
    variant, sectors = struct.unpack_from(">IQ", koly, 0x1E8)
    f.update(version=version, header_size=size, flags=flags, data_fork_offset=data_offset,
             data_fork_length=data_length, resource_fork_length=rsrc_length, segment_number=segment,
             segment_count=segments, segment_id=koly[64:80].hex(), xml_offset=xml_offset, xml_length=xml_length,
             image_variant=variant, sector_count=sectors, image_size_bytes=sectors * 512)


DS_STORE_TYPES = {b"long", b"shor", b"bool", b"blob", b"type", b"ustr", b"comp", b"dutc"}


def _ds_store(data: bytes, f: dict) -> None:
    """Record names of a Finder .DS_Store: (length, UTF-16BE name, 4-char code, known type) runs."""
    names, codes = [], set()
    for m in re.finditer(rb"\0\0\0([\x01-\xff])((?:\0[\x20-\x7e]|[\x01-\xff][\0-\xff]){1,255}?)([a-zA-Z]{4})(long|shor|bool|blob|type|ustr|comp|dutc)",
                         data[:16 << 20]):
        if len(m.group(2)) != 2 * m.group(1)[0]:
            continue
        name = m.group(2).decode("utf-16-be", "replace")
        codes.add(m.group(3).decode())
        if name not in names:
            names.append(name)
    f.update(file_names=names, file_name_count=len(names), record_codes=sorted(codes))


# A small DER reader for X.509 certificates (also used for Authenticode signers).

OIDS = {"1.2.840.113549.1.1.1": "rsaEncryption", "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11": "sha256WithRSAEncryption", "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13": "sha512WithRSAEncryption", "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
        "1.2.840.10045.2.1": "ecPublicKey", "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3": "ecdsa-with-SHA384", "1.3.101.112": "Ed25519", "1.2.840.10040.4.1": "dsa"}
NAME_KEYS = {"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
             "1.2.840.113549.1.9.1": "emailAddress", "2.5.4.5": "serialNumber"}


def der(data: bytes, at: int = 0) -> tuple[int, int, int]:
    """(tag, content start, content end) of the DER element at `at`."""
    tag, length = data[at], data[at + 1]
    at += 2
    if length & 0x80:
        count = length & 0x7F
        if not 1 <= count <= 4:
            raise ValueError("DER length")
        length = int.from_bytes(data[at:at + count], "big")
        at += count
    if at + length > len(data):
        raise ValueError("DER element past the data")
    return tag, at, at + length


def der_children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out = []
    while start < end and len(out) < 4096:
        element = der(data, start)
        out.append(element)
        start = element[2]
    return out


def _oid(raw: bytes) -> str:
    parts, value = [], 0
    for byte in raw:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    first = min(parts[0] // 40, 2) if parts else 0
    return ".".join(map(str, [first, parts[0] - 40 * first, *parts[1:]])) if parts else ""


def _der_time(data: bytes, element) -> str:
    tag, a, b = element
    text = data[a:b].decode("ascii").rstrip("Z")
    if tag == 0x17:  # UTCTime YYMMDDHHMMSS
        text = ("19" if int(text[:2]) >= 50 else "20") + text
    return f"{text[:4]}-{text[4:6]}-{text[6:8]}T{text[8:10]}:{text[10:12]}:{text[12:14]}Z"


def _der_name(data: bytes, element) -> dict:
    out: dict = {}
    for _, a, b in der_children(data, element[1], element[2]):            # SET of AttributeTypeAndValue
        for _, c, d in der_children(data, a, b):
            (_, oa, ob), (vtag, va, vb) = der_children(data, c, d)[:2]
            key = NAME_KEYS.get(_oid(data[oa:ob]), _oid(data[oa:ob]))
            out.setdefault(key, data[va:vb].decode("utf-16-be" if vtag == 0x1E else "utf-8", "replace"))
    return out


def certificate(data: bytes, at: int = 0) -> dict:
    import hashlib

    _, start, end = der(data, at)
    blob = data[at:end]
    tbs, algorithm, _ = der_children(data, start, end)[:3]
    fields = der_children(data, tbs[1], tbs[2])
    version = 1
    if fields[0][0] == 0xA0:
        version = data[der(data, fields[0][1])[1]] + 1
        fields = fields[1:]
    serial, _, issuer, validity, subject, key = fields[:6]
    times = der_children(data, validity[1], validity[2])
    key_algorithm = der_children(data, *der_children(data, key[1], key[2])[0][1:])[0]
    sig_oid = der_children(data, algorithm[1], algorithm[2])[0]
    issuer_name, subject_name = _der_name(data, issuer), _der_name(data, subject)
    out = {"version": version, "serial_number": data[serial[1]:serial[2]].lstrip(b"\0").hex() or "00",
           "signature_algorithm": OIDS.get(_oid(data[sig_oid[1]:sig_oid[2]]), _oid(data[sig_oid[1]:sig_oid[2]])),
           "issuer": ", ".join(f"{k}={v}" for k, v in issuer_name.items()), "issuer_cn": issuer_name.get("CN"),
           "subject": ", ".join(f"{k}={v}" for k, v in subject_name.items()), "subject_cn": subject_name.get("CN"),
           "subject_organization": subject_name.get("O"), "issuer_organization": issuer_name.get("O"),
           "not_before": _der_time(data, times[0]), "not_after": _der_time(data, times[1]),
           "public_key_algorithm": OIDS.get(_oid(data[key_algorithm[1]:key_algorithm[2]]),
                                            _oid(data[key_algorithm[1]:key_algorithm[2]])),
           "self_signed": issuer_name == subject_name,
           "sha1_fingerprint": hashlib.sha1(blob).hexdigest(), "sha256_fingerprint": hashlib.sha256(blob).hexdigest()}
    for extra in fields[6:]:
        if extra[0] != 0xA3:
            continue
        for _, a, b in der_children(data, *der_children(data, extra[1], extra[2])[0][1:]):
            parts = der_children(data, a, b)
            if _oid(data[parts[0][1]:parts[0][2]]) == "2.5.29.17":            # subjectAltName
                inner = der(data, parts[-1][1])
                out["subject_alt_names"] = [data[c:d].decode("ascii", "replace")
                                            for tag, c, d in der_children(data, inner[1], inner[2]) if tag in (0x82, 0x81)]
    return out


def _x509(data: bytes, f: dict) -> None:
    import base64

    if data.lstrip()[:11] == b"-----BEGIN ":
        m = re.search(rb"-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----", data)
        if not m:
            raise ValueError("no PEM certificate")
        f["certificate_count"] = data.count(b"-----BEGIN CERTIFICATE-----")
        data = base64.b64decode(b"".join(m.group(1).split()))
    f.update(certificate(data))


# --- Forecast for days 26-31: disk images, mail stores, kernel dumps, Linux journal and logins ----
# Day 23-25 asked about SQLite, EVTX and registry hives; these are the DFIR staples after them
# that no reader above covers (tests/test_forecast.py). Header fields only, from the specs.

_CAMEL_KEY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
VMDK_COMPRESSION = {0: "none", 1: "deflate"}


def _vmdk_descriptor(text: str, f: dict) -> None:
    """`key = "value"` lines (createType -> create_type, ddb.adapterType -> adapter_type) and
    extent lines such as `RW 4192256 SPARSE "disk-s001.vmdk"`."""
    extents = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        extent = re.fullmatch(r'(RW|RDONLY|NOACCESS)\s+(\d+)\s+(\w+)(?:\s+"([^"]*)")?.*', line)
        if extent:
            extents.append({"access": extent[1], "sectors": int(extent[2]), "type": extent[3], "file": extent[4]})
            continue
        key, sep, value = line.partition("=")
        if sep and key.strip():
            name = _CAMEL_KEY.sub("_", key.strip().removeprefix("ddb.").replace(".", "_")).lower()
            f["descriptor_version" if name == "version" else name] = value.strip().strip('"')
    if extents:
        f.update(extents=extents, extent_files=[e["file"] for e in extents if e["file"]],
                 extent_types=[e["type"] for e in extents],
                 descriptor_capacity_sectors=sum(e["sectors"] for e in extents))


def _vmdk(data: bytes, f: dict) -> None:
    """A hosted sparse extent (magic "KDMV") and its embedded descriptor, or a descriptor file."""
    text = data[:1 << 20]
    if data[:4] == b"KDMV":
        (version, flags, capacity, grain, descriptor_at, descriptor_size, entries, redundant, directory,
         overhead) = struct.unpack_from("<IIQQQQIQQQ", data, 4)
        compression, = struct.unpack_from("<H", data, 77)
        f.update(version=version, flags=flags, capacity_sectors=capacity, capacity=capacity * 512,
                 grain_size_sectors=grain, grain_size=grain * 512, descriptor_offset=descriptor_at,
                 descriptor_size=descriptor_size, grain_table_entries=entries,
                 redundant_grain_directory_offset=redundant, grain_directory_offset=directory,
                 overhead_sectors=overhead, unclean_shutdown=bool(data[72]), compress_algorithm=compression,
                 compression=VMDK_COMPRESSION.get(compression, "unknown"))
        text = data[descriptor_at * 512:(descriptor_at + descriptor_size) * 512] if descriptor_at else b""
    _vmdk_descriptor(text.split(b"\0", 1)[0].decode("utf-8", "replace"), f)


QCOW_ENCRYPTION = {0: "none", 1: "aes", 2: "luks"}


def _qcow2(data: bytes, f: dict) -> None:
    """QEMU copy-on-write header (big-endian), version 2 or 3."""
    (version, backing_at, backing_size, cluster_bits, size, crypt, l1_size, l1_at, refcount_at, refcount_clusters,
     snapshots, snapshots_at) = struct.unpack_from(">IQIIQIIQQIIQ", data, 4)
    f.update(version=version, virtual_size=size, cluster_bits=cluster_bits,
             cluster_size=1 << cluster_bits if cluster_bits < 64 else None, crypt_method=crypt,
             encryption=QCOW_ENCRYPTION.get(crypt, "unknown"), l1_size=l1_size, l1_table_offset=l1_at,
             refcount_table_offset=refcount_at, refcount_table_clusters=refcount_clusters,
             snapshot_count=snapshots, snapshots_offset=snapshots_at,
             backing_file=data[backing_at:backing_at + backing_size].decode("utf-8", "replace")
             if backing_at and 0 < backing_size <= 1023 else None)
    if version >= 3 and len(data) >= 104:
        incompatible, compatible, autoclear, refcount_order, header_length = struct.unpack_from(">QQQII", data, 72)
        f.update(incompatible_features=incompatible, compatible_features=compatible, autoclear_features=autoclear,
                 dirty=bool(incompatible & 1), corrupt=bool(incompatible & 2), refcount_order=refcount_order,
                 header_length=header_length)
        if header_length > 104 and len(data) > 104:
            f["compression_type"] = {0: "zlib", 1: "zstd"}.get(data[104], "unknown")


PST_CLIENTS = {b"SM": "pst", b"SO": "ost", b"AB": "pab"}
PST_CRYPT = {0: "none", 1: "permute", 2: "cyclic", 0x10: "edp"}


def _pst(data: bytes, f: dict) -> None:
    """Outlook PST/OST header (MS-PST 2.2.2.6): ANSI (wVer 14/15) or Unicode (23, 36 with 4K pages)."""
    version, client_version, created_on, accessed_on = struct.unpack_from("<HHBB", data, 10)
    unicode = version >= 23
    crypt = data[513 if unicode else 461]
    f.update(file_type=PST_CLIENTS.get(data[8:10], "unknown"), format_version=version,
             format="ansi" if not unicode else "unicode_4k" if version == 36 else "unicode",
             client_version=client_version, platform_create=created_on, platform_access=accessed_on,
             crypt_method=crypt, crypt_method_name=PST_CRYPT.get(crypt, "unknown"),
             file_eof=struct.unpack_from("<Q", data, 184)[0] if unicode else struct.unpack_from("<I", data, 168)[0])


DUMP_MACHINES = {0x14C: "i386", 0x1C4: "arm", 0x8664: "amd64", 0xAA64: "arm64"}


def _kernel_dump(data: bytes, f: dict) -> None:
    """A Windows kernel crash dump (MEMORY.DMP): DUMP_HEADER64 "PAGEDU64" or DUMP_HEADER32 "PAGEDUMP"."""
    wide = data[4:8] == b"DU64"
    major, minor = struct.unpack_from("<II", data, 8)
    if wide:
        table, pfn, modules, processes, machine, processors, code = struct.unpack_from("<QQQQIII", data, 16)
        parameters = [f"0x{value:016x}" for value in struct.unpack_from("<4Q", data, 0x40)]
    else:
        table, pfn, modules, processes, machine, processors, code = struct.unpack_from("<7I", data, 16)
        parameters = [f"0x{value:08x}" for value in struct.unpack_from("<4I", data, 0x2C)]
    f.update(bitness=64 if wide else 32, major_version=major, minor_version=minor, build_number=minor,
             checked_build=major == 0xC, directory_table_base=table, pfn_database=pfn,
             ps_loaded_module_list=modules, ps_active_process_head=processes, machine_type=machine,
             machine_name=DUMP_MACHINES.get(machine, "unknown"), number_processors=processors,
             processor_count=processors, bugcheck_code=code, bugcheck_parameters=parameters)
    if wide and len(data) >= 0xFB0:
        dump_type, = struct.unpack_from("<I", data, 0xF98)
        system_time, = struct.unpack_from("<Q", data, 0xFA8)
        f.update(dump_type=dump_type, system_time_utc=_filetime(system_time))


JOURNAL_STATES = {0: "offline", 1: "online", 2: "archived"}
JOURNAL_INCOMPATIBLE = {1: "compressed_xz", 2: "compressed_lz4", 4: "keyed_hash", 8: "compressed_zstd", 16: "compact"}


def _journal_time(microseconds: int) -> str | None:
    return _unix(microseconds // 1_000_000)


def _journald(data: bytes, f: dict) -> None:
    """A systemd journal file header (journal-def.h); 128-bit ids as 32 hex digits, like journalctl."""
    compatible, incompatible, state = struct.unpack_from("<IIB", data, 8)
    (header_size, arena_size, _, _, _, _, _, objects, entries, tail_seqnum, head_seqnum, _,
     head_realtime, tail_realtime, tail_monotonic) = struct.unpack_from("<15Q", data, 88)
    f.update(compatible_flags=compatible, incompatible_flags=incompatible, sealed=bool(compatible & 1),
             features=[name for bit, name in JOURNAL_INCOMPATIBLE.items() if incompatible & bit],
             state=state, state_name=JOURNAL_STATES.get(state, "unknown"), file_id=data[24:40].hex(),
             machine_id=data[40:56].hex(), boot_id=data[56:72].hex(), seqnum_id=data[72:88].hex(),
             header_size=header_size, arena_size=arena_size, object_count=objects, entry_count=entries,
             head_entry_seqnum=head_seqnum, tail_entry_seqnum=tail_seqnum,
             head_entry_realtime_utc=_journal_time(head_realtime), tail_entry_realtime_utc=_journal_time(tail_realtime),
             tail_entry_monotonic=tail_monotonic)
    if header_size >= 224 and len(data) >= 224:
        f["data_object_count"], f["field_object_count"] = struct.unpack_from("<QQ", data, 208)


UTMP_TYPES = {0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME", 5: "INIT_PROCESS",
              6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS", 9: "ACCOUNTING"}
UTMP_SIZE = 384  # glibc struct utmp on x86-64 (and wtmp, btmp): no magic, so every record is checked.
MAX_UTMP_RECORDS = 100_000


def _utmp_text(field: bytes) -> str:
    text, _, rest = field.partition(b"\0")
    if rest.strip(b"\0") or not all(32 <= c < 127 for c in text):
        raise ValueError("not a utmp string")
    return text.decode("ascii")


def _utmp_record(data: bytes, at: int) -> tuple[int, int, str, str, str, int, bytes]:
    kind, pad, pid = struct.unpack_from("<hHi", data, at)
    if not 0 <= kind <= 9 or pad or pid < 0:
        raise ValueError("not a utmp record")
    line, user, host = (_utmp_text(data[at + start:at + end]) for start, end in ((8, 40), (44, 76), (76, 332)))
    seconds, = struct.unpack_from("<i", data, at + 340)
    return kind, pid, line, user, host, seconds, data[at + 348:at + 364]


def _utmp_ok(data: bytes) -> bool:
    if len(data) < UTMP_SIZE or len(data) % UTMP_SIZE:
        return False
    try:
        return _utmp_record(data, 0)[0] > 0  # A zero-filled file is not a login record.
    except (ValueError, struct.error):
        return False


def _address(raw: bytes) -> str | None:
    import ipaddress

    if not raw.strip(b"\0"):
        return None
    return str(ipaddress.ip_address(raw[:4] if not raw[4:].strip(b"\0") else raw))


def _utmp(data: bytes, f: dict) -> None:
    records = [_utmp_record(data, at) for at in range(0, min(len(data), MAX_UTMP_RECORDS * UTMP_SIZE), UTMP_SIZE)]
    logins = [record for record in records if record[0] == 7]
    times = [record[5] for record in records if record[5] > 0]
    unique = lambda values: list(dict.fromkeys(value for value in values if value))
    f.update(record_count=len(records), record_types=unique(UTMP_TYPES[record[0]] for record in records),
             login_count=len(logins), boot_count=sum(record[0] == 2 for record in records),
             user_names=unique(record[3] for record in logins), hosts=unique(record[4] for record in logins),
             terminals=unique(record[2] for record in logins),
             ip_addresses=unique(_address(record[6]) for record in logins),
             first_time_utc=_unix(min(times)) if times else None, last_time_utc=_unix(max(times)) if times else None,
             last_login_user=logins[-1][3] if logins else None, last_login_host=logins[-1][4] if logins else None)


def formats(data: bytes) -> list[tuple[str, dict]]:
    checks = (
        ("evtx", data.startswith(b"ElfFile\0") and len(data) >= 0x80, _evtx),
        ("regf", data.startswith(b"regf") and len(data) >= 0x200, _regf),
        ("prefetch", (data[4:8] == b"SCCA" and len(data) >= 0x100) or (data[:3] == b"MAM" and len(data) >= 8), _prefetch),
        ("plist", data.startswith(b"bplist0") or (data[:4096].lstrip()[:5] == b"<?xml" and b"<plist" in data[:1024]), _plist),
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
        # Days 26+ candidates.
        ("mft", data[:4] in (b"FILE", b"BAAD") and len(data) >= 0x40, _mft),
        # A record at offset 0 is version 2 or 3; any other start has sparse zeros before it.
        ("usn", len(data) >= 60 and (data[:1] == b"\0" or data[4:8] in (b"\2\0\0\0", b"\3\0\0\0"))
         and _usn_start(data) is not None, _usn),
        ("recycle_bin_i", len(data) >= 28 and data[:8] in (b"\x01" + bytes(7), b"\x02" + bytes(7))
         and (len(data) == 544 or len(data) == 28 + 2 * int.from_bytes(data[24:28], "little")), _recycle_i),
        ("custom_destinations", data[:4] == b"\x02\0\0\0" and data[-4:] == b"\xab\xfb\xbf\xba", _custom_destinations),
        ("minidump", data.startswith(b"MDMP") and len(data) >= 32, _minidump),
        ("scheduled_task", len(data) < 1 << 20 and data[:16].lstrip(b"\xef\xbb\xbf\xff\xfe \t\r\n\0")[:1] == b"<"
         and (data.find(b"<Task", 0, 4096) >= 0 or data.find(_TASK16, 0, 8192) >= 0)
         and (data.find(b"mit/task", 0, 8192) >= 0 or data.find(_MIT16, 0, 16384) >= 0), _scheduled_task),
        ("ewf", data.startswith(b"EVF\x09\x0d\x0a\xff\x00") and len(data) >= 13, _ewf),
        ("ntfs", len(data) >= 512 and data[3:11] == b"NTFS    ", _ntfs_boot),
        ("mbr", len(data) >= 512 and data[510:512] == b"\x55\xaa" and data[3:11] != b"NTFS    "
         and any(data[446 + 16 * i + 4] for i in range(4)), _mbr),
        ("gpt", len(data) >= 1024 and data[512:520] == b"EFI PART", _gpt),
        ("dmg", len(data) >= 512 and data[-512:-508] == b"koly", _dmg),
        ("ds_store", data.startswith(b"\0\0\0\x01Bud1"), _ds_store),
        ("x509", (data[:1] == b"\x30" and data[1:2] in (b"\x82", b"\x81") and data[4:5] == b"\x30")
         or data[:4096].lstrip()[:27] == b"-----BEGIN CERTIFICATE-----", _x509),
        # Forecast for days 26-31.
        ("vmdk", (data[:4] == b"KDMV" and len(data) >= 512)
         or data[:1024].lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"# Disk DescriptorFile"), _vmdk),
        ("qcow2", data[:4] == b"QFI\xfb" and len(data) >= 72, _qcow2),
        ("pst", data[:4] == b"!BDN" and len(data) >= 514, _pst),
        ("kernel_dump", data[:8] in (b"PAGEDU64", b"PAGEDUMP") and len(data) >= 0x100, _kernel_dump),
        ("journald", data[:8] == b"LPKSHHRH" and len(data) >= 208, _journald),
        ("utmp", _utmp_ok(data), _utmp),
    )
    found = [(label, _guarded(parse, data)) for label, match, parse in checks if match]
    if data.startswith(b"\x04\x22\x4d\x18") and len(data) >= 7:
        descriptor = data[4]
        found.append(("lz4", {"version": descriptor >> 6, "content_checksum": bool(descriptor & 0x04),
                              "content_size_present": bool(descriptor & 0x08),
                              "block_max_size_bytes": {4: 65536, 5: 262144, 6: 1 << 20, 7: 4 << 20}.get((data[5] >> 4) & 7)}))
    return found
