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
import hashlib
import plistlib
import re
import struct
import zlib
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


# --- Prefetch (SCCA; Windows 10+ files are MAM: Xpress Huffman compressed) ---------------------

PREFETCH_OFFSETS = {17: (0x78, 0x90), 23: (0x80, 0x98), 26: (0x80, 0xD0), 30: (0x80, 0xD0), 31: (0x80, 0xD0)}
MAX_XPRESS_OUTPUT = 16 * 1024 * 1024


def xpress_huffman(data: bytes, size: int) -> bytes:
    """[MS-XCA] 2.2.4 LZ77+Huffman decompression of `data` to `size` bytes (Windows 10 Prefetch,
    Day 26). Every 64 KiB of output starts with a table of 512 4-bit code lengths; damaged input
    raises ValueError (or IndexError past its end), so a parser reports `damaged`."""
    if not 0 <= size <= MAX_XPRESS_OUTPUT:
        raise ValueError("Xpress Huffman output size out of range")
    data += b"\0" * 4  # The last refill may read past the stream; zeros there decode nothing.
    out = bytearray()
    at = 0
    while len(out) < size:
        if at + 264 > len(data):
            raise ValueError("Xpress Huffman block past the end of the input")
        lengths = [(data[at + i // 2] >> (4 * (i & 1))) & 15 for i in range(512)]
        decode: list[int] = []
        for bit_length in range(1, 16):
            for symbol in range(512):
                if lengths[symbol] == bit_length:
                    decode.extend([symbol] * (1 << (15 - bit_length)))
        if len(decode) != 1 << 15:
            raise ValueError("Xpress Huffman code lengths do not form a complete code")
        at += 256
        bits = (data[at] | data[at + 1] << 8) << 16 | data[at + 2] | data[at + 3] << 8
        at += 4
        extra = 16
        block_end = len(out) + 65536
        while len(out) < block_end and len(out) < size:
            symbol = decode[bits >> 17]
            length = lengths[symbol]
            bits = (bits << length) & 0xFFFFFFFF
            extra -= length
            if extra < 0:
                bits |= (data[at] | data[at + 1] << 8) << -extra
                extra += 16
                at += 2
            if symbol < 256:
                out.append(symbol)
                continue
            symbol -= 256
            match_length, offset_bits = symbol & 15, symbol >> 4
            if match_length == 15:
                match_length = data[at]
                at += 1
                if match_length == 255:
                    match_length = data[at] | data[at + 1] << 8
                    at += 2
                    if match_length == 0:
                        match_length = struct.unpack_from("<I", data, at)[0]
                        at += 4
                    if match_length < 15:
                        raise ValueError("Xpress Huffman match length too short")
                    match_length -= 15
                match_length += 15
            match_length += 3
            offset = ((bits >> (32 - offset_bits)) if offset_bits else 0) + (1 << offset_bits)
            bits = (bits << offset_bits) & 0xFFFFFFFF
            extra -= offset_bits
            if extra < 0:
                bits |= (data[at] | data[at + 1] << 8) << -extra
                extra += 16
                at += 2
            start = len(out) - offset
            if start < 0:
                raise ValueError("Xpress Huffman match before the start of the output")
            for i in range(min(match_length, size - len(out))):
                out.append(out[start + i])
    return bytes(out)


def _prefetch(data: bytes, f: dict) -> None:
    if data[:3] == b"MAM":
        size = struct.unpack_from("<I", data, 4)[0]
        f.update(compressed=True, compression="xpress_huffman" if data[3] & 0x7F == 4 else f"0x{data[3]:02x}",
                 uncompressed_size=size)
        if data[3] & 0x7F != 4:
            return
        data = xpress_huffman(data[12 if data[3] & 0x80 else 8:], size)  # 0x80: a CRC32 follows the size.
        if data[4:8] != b"SCCA":
            raise ValueError("decompressed prefetch is not SCCA")
    else:
        f["compressed"] = False
    # Offset 8 is a constant (0x11 in version 30); the file size is at 12 (Day 26: 15412 there).
    version, size = struct.unpack_from("<I", data, 0)[0], struct.unpack_from("<I", data, 12)[0]
    f.update(version=version, file_size=size, executable_name=_utf16(data[0x10:0x4C]),
             prefetch_hash=struct.unpack_from("<I", data, 0x4C)[0])
    f["prefetch_hash_hex"] = f"{f['prefetch_hash']:08X}"
    if version in PREFETCH_OFFSETS:
        last_run, count = PREFETCH_OFFSETS[version]
        if version >= 30 and struct.unpack_from("<I", data, 0x54)[0] == 0x128:
            count = 0xC8  # The shorter version-30 file information (Day 26: 8 run times, 20 runs at 0xC8, 0 at 0xD0).
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


CAB_COMPRESSION = {0: "none", 1: "mszip", 2: "quantum", 3: "lzx"}
CAB_ATTRIBUTES = ((0x01, "readonly"), (0x02, "hidden"), (0x04, "system"), (0x20, "archive"), (0x40, "exec"))


def _dos_time(date: int, time: int) -> str | None:
    """A FAT/CAB/ZIP date and time word: local time with 2-second steps, no time zone."""
    try:
        return datetime(1980 + (date >> 9), date >> 5 & 15, date & 31, time >> 11, time >> 5 & 63,
                        (time & 31) * 2).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _cab_folder(data: bytes, start: int, blocks: int, kind: int, data_reserve: int) -> bytes:
    """One CAB folder's bytes: its CFDATA blocks, stored, MSZIP (a raw deflate stream per 32 KiB block,
    each primed with the block before) or LZX (the blocks' payloads form one stream)."""
    method, at, payloads, sizes = kind & 0xF, start, [], []
    for _ in range(blocks):
        packed, unpacked = struct.unpack_from("<HH", data, at + 4)
        at += 8 + data_reserve
        if at + packed > len(data):
            raise ValueError("CAB data block past the cabinet")
        payloads.append(data[at:at + packed])
        sizes.append(unpacked)
        at += packed
    if sum(sizes) > MAX_DECOMPRESSED:
        raise ValueError("CAB folder too large")
    if method == 0:
        return b"".join(payloads)
    if method == 1:
        out = bytearray()
        for payload, unpacked in zip(payloads, sizes):
            if payload[:2] != b"CK":
                raise ValueError("MSZIP block without its CK signature")
            inflate = zlib.decompressobj(-15, zdict=bytes(out[-32768:])) if out else zlib.decompressobj(-15)
            block = inflate.decompress(payload[2:], unpacked)
            if len(block) != unpacked:
                raise ValueError("MSZIP block shorter than stated")
            out += block
        return bytes(out)
    if method == 3:
        return lzx(b"".join(payloads), sum(sizes), kind >> 8 & 0x1F)
    raise ValueError(f"CAB compression {CAB_COMPRESSION.get(method, method)} not supported")


def _cab(data: bytes, f: dict) -> None:
    size, files_at = struct.unpack_from("<I4xI", data, 8)
    minor, major, folders, files, flags, set_id, index = struct.unpack_from("<BBHHHHH", data, 24)
    f.update(cabinet_size=size, version=f"{major}.{minor}", folder_count=folders, file_count=files,
             flags=flags, set_id=set_id, cabinet_index=index)
    names, at = [], files_at
    entries = []
    for _ in range(min(files, 65535)):
        length, offset, folder, date, time, attributes = struct.unpack_from("<IIHHHH", data, at)
        at += 16
        end = data.index(b"\0", at)
        names.append(data[at:end].decode("utf-8" if attributes & 0x80 else "latin-1"))
        entries.append((length, offset, folder, date, time, attributes))
        at = end + 1
    f["names"] = names
    f.update(file_sizes=[entry[0] for entry in entries], total_uncompressed=sum(entry[0] for entry in entries),
             modified_times=[_dos_time(entry[3], entry[4]) for entry in entries],
             file_attributes=[[name for bit, name in CAB_ATTRIBUTES if entry[5] & bit] for entry in entries],
             folder_indexes=[entry[2] for entry in entries])
    at, data_reserve = 36, 0
    if flags & 4:  # Reserved areas in the header, each folder entry and each data block.
        header_reserve, folder_reserve, data_reserve = struct.unpack_from("<HBB", data, 36)
        at = 40 + header_reserve
        f.update(header_reserve_size=header_reserve, folder_reserve_size=folder_reserve,
                 data_reserve_size=data_reserve)
    else:
        folder_reserve = 0
    for bit, side in ((1, "previous"), (2, "next")):  # A cabinet set's neighbours.
        if flags & bit:
            for part in ("cabinet", "disk"):
                end = data.index(b"\0", at)
                f[f"{side}_{part}"] = data[at:end].decode("latin-1")
                at = end + 1
    table = []
    for _ in range(min(folders, 4096)):
        table.append(struct.unpack_from("<IHH", data, at))
        at += 8 + folder_reserve
    kinds = [CAB_COMPRESSION.get(kind & 0xF, f"0x{kind & 0xF:x}") for _, _, kind in table]
    f.update(compression_types=kinds, compression=kinds[0] if kinds else "none",
             data_block_count=sum(blocks for _, blocks, _ in table))
    if any(kind & 0xF == 3 for _, _, kind in table):
        f["lzx_window_bits"] = next(kind >> 8 & 0x1F for _, _, kind in table if kind & 0xF == 3)
    hashes: list[str | None] = [None] * len(entries)
    for number, (start, blocks, kind) in enumerate(table):
        try:
            folder = _cab_folder(data, start, blocks, kind, data_reserve)
        except (ValueError, IndexError, struct.error, zlib.error) as exc:
            f.setdefault("folders_unreadable", []).append(f"{number}: {exc}")
            continue
        for i, (length, offset, at_folder, *_rest) in enumerate(entries):
            if at_folder == number and offset + length <= len(folder):
                hashes[i] = hashlib.sha256(folder[offset:offset + length]).hexdigest()
    f["member_sha256"] = hashes


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


# --- Compression real artifacts use (Day 26: Windows 10 Prefetch came MAM-compressed) ------------

MAX_DECOMPRESSED = 64 * 1024 * 1024


def lznt1(data: bytes, size: int | None = None) -> bytes:
    """[MS-XCA] 2.5 LZNT1 (NTFS compression; MAM format 2): chunks of up to 4 KiB, each with a 2-byte
    header (bit 15 compressed, low 12 bits size - 1); flag bytes pick literals or back-references
    whose offset/length split widens as the chunk's output grows."""
    out = bytearray()
    at = 0
    while at + 2 <= len(data) and (size is None or len(out) < size):
        header = struct.unpack_from("<H", data, at)[0]
        if header == 0:
            break
        length = (header & 0xFFF) + 1
        chunk = data[at + 2:at + 2 + length]
        if len(chunk) != length:
            raise ValueError("LZNT1 chunk past the input")
        at += 2 + length
        if not header & 0x8000:
            out += chunk
            continue
        start, i = len(out), 0
        while i < len(chunk):
            flags = chunk[i]
            i += 1
            for bit in range(8):
                if i >= len(chunk):
                    break
                if not flags >> bit & 1:
                    out.append(chunk[i])
                    i += 1
                    continue
                if i + 2 > len(chunk):
                    raise ValueError("LZNT1 token past the chunk")
                token = chunk[i] | chunk[i + 1] << 8
                i += 2
                position, length_bits = len(out) - start - 1, 12
                while position >= 0x10:
                    position >>= 1
                    length_bits -= 1
                count, offset = (token & ((1 << length_bits) - 1)) + 3, (token >> length_bits) + 1
                if offset > len(out) - start:
                    raise ValueError("LZNT1 back-reference before its chunk")
                for _ in range(count):
                    out.append(out[-offset])
        if len(out) > MAX_DECOMPRESSED:
            raise ValueError("LZNT1 output too large")
    return bytes(out if size is None else out[:size])


def xpress(data: bytes, size: int) -> bytes:
    """[MS-XCA] 2.4 plain LZ77 Xpress (MAM format 3, hiberfil.sys, WIM): 32-bit flag words, 16-bit
    matches (offset << 3 | length), lengths extended by shared nibbles, then bytes, words, dwords."""
    if not 0 <= size <= MAX_DECOMPRESSED:
        raise ValueError("Xpress output size out of range")
    out = bytearray()
    at = flags = count = 0
    nibble = None
    while len(out) < size:
        if count == 0:
            flags, count = struct.unpack_from("<I", data, at)[0], 32
            at += 4
        count -= 1
        if not flags >> count & 1:
            out.append(data[at])
            at += 1
            continue
        match = struct.unpack_from("<H", data, at)[0]
        at += 2
        length, offset = match & 7, (match >> 3) + 1
        if length == 7:
            if nibble is None:
                nibble, length = at, data[at] & 15
                at += 1
            else:
                length, nibble = data[nibble] >> 4, None
            if length == 15:
                length = data[at]
                at += 1
                if length == 255:
                    length = struct.unpack_from("<H", data, at)[0]
                    at += 2
                    if length == 0:
                        length = struct.unpack_from("<I", data, at)[0]
                        at += 4
                    if length < 15 + 7:
                        raise ValueError("Xpress match length too short")
                    length -= 15 + 7
                length += 15
            length += 7
        length += 3
        if offset > len(out):
            raise ValueError("Xpress match before the start of the output")
        for _ in range(min(length, size - len(out))):
            out.append(out[-offset])
    return bytes(out)


def lz4_block(data: bytes, size: int) -> bytes:
    """One LZ4 block (Firefox mozLz4): tokens of literal and match lengths, 16-bit offsets."""
    if not 0 <= size <= MAX_DECOMPRESSED:
        raise ValueError("LZ4 output size out of range")
    out = bytearray()
    at = 0
    while at < len(data):
        token = data[at]
        at += 1
        literal = token >> 4
        if literal == 15:
            while True:
                extra = data[at]
                at += 1
                literal += extra
                if extra != 255:
                    break
        out += data[at:at + literal]
        at += literal
        if at >= len(data):
            break  # The last sequence is literals only.
        offset = data[at] | data[at + 1] << 8
        at += 2
        match = (token & 15) + 4
        if token & 15 == 15:
            while True:
                extra = data[at]
                at += 1
                match += extra
                if extra != 255:
                    break
        if not 0 < offset <= len(out) or len(out) + match > size:
            raise ValueError("LZ4 match out of range")
        start = len(out) - offset
        if match <= offset:
            out += out[start:start + match]
        else:
            for i in range(match):
                out.append(out[start + i])
    if len(out) != size:
        raise ValueError("LZ4 output does not match its stated size")
    return bytes(out)


LZX_SLOTS = {15: 30, 16: 32, 17: 34, 18: 36, 19: 38, 20: 42, 21: 50}  # Position slots per window size.
LZX_EXTRA_BITS = tuple(min(max(slot // 2 - 1, 0), 17) for slot in range(51))
LZX_POSITION_BASE = tuple(sum(1 << bits for bits in LZX_EXTRA_BITS[:slot]) for slot in range(51))
LZX_FRAME = 32768
LZX_WIM_E8_SIZE = 12_000_000  # WIM chunks always undo the E8 call translation against this size.


class _LzxBits:
    """LZX's bitstream: 16-bit little-endian words, each read from its high bit."""

    def __init__(self, data: bytes) -> None:
        self.data, self.at, self.buffer, self.count = data, 0, 0, 0

    def need(self, n: int) -> None:
        while self.count < n:
            if self.at > len(self.data) + 8:  # A few words of zero padding, as decoders allow.
                raise ValueError("LZX stream ends early")
            self.buffer = self.buffer << 16 | int.from_bytes(self.data[self.at:self.at + 2].ljust(2, b"\0"), "little")
            self.at += 2
            self.count += 16

    def read(self, n: int) -> int:
        if n == 0:
            return 0
        self.need(n)
        self.count -= n
        value = self.buffer >> self.count
        self.buffer &= (1 << self.count) - 1
        return value

    def symbol(self, tree: tuple[int, list[int]] | None) -> int:
        if tree is None:
            raise ValueError("LZX symbol from an empty Huffman tree")
        width, table = tree
        self.need(width)
        entry = table[self.buffer >> (self.count - width) & ((1 << width) - 1)]
        if entry < 0:
            raise ValueError("LZX: no Huffman code matches")
        self.count -= entry & 31
        self.buffer &= (1 << self.count) - 1
        return entry >> 5

    def align(self, skip_aligned: bool = False) -> None:
        """To the next 16-bit boundary of the input; an uncompressed block also skips a whole
        word when it is already there ("1-16 bits of padding")."""
        consumed = self.at * 8 - self.count
        pad = -consumed % 16 or (16 if skip_aligned else 0)
        self.at, self.buffer, self.count = (consumed + pad) // 8, 0, 0


def _lzx_tree(lengths: list[int]) -> tuple[int, list[int]] | None:
    """A canonical Huffman decode table indexed by the next `width` bits: symbol << 5 | length."""
    used = sorted((length, symbol) for symbol, length in enumerate(lengths) if length)
    if not used:
        return None
    width = used[-1][0]
    table = [-1] * (1 << width)
    code, previous = 0, used[0][0]
    for length, symbol in used:
        code <<= length - previous
        previous = length
        span = 1 << (width - length)
        if (code + 1) * span > len(table):
            raise ValueError("LZX Huffman lengths oversubscribed")
        table[code * span:(code + 1) * span] = [symbol << 5 | length] * span
        code += 1
    return width, table


def _lzx_lengths(bits: _LzxBits, lengths: list[int], first: int, last: int) -> None:
    """Code lengths as deltas from the previous block's, coded with a 20-symbol pretree."""
    pretree = _lzx_tree([bits.read(4) for _ in range(20)])
    x = first
    while x < last:
        z = bits.symbol(pretree)
        if z == 17:
            run, value = bits.read(4) + 4, 0
        elif z == 18:
            run, value = bits.read(5) + 20, 0
        elif z == 19:
            run = bits.read(1) + 4
            value = (lengths[x] - bits.symbol(pretree)) % 17
        else:
            run, value = 1, (lengths[x] - z) % 17
        run = min(run, last - x)
        lengths[x:x + run] = [value] * run
        x += run


def _lzx_e8(out: bytearray, start: int, end: int, file_size: int) -> None:
    """Undo the encoder's x86 CALL translation in one frame: absolute targets back to relative."""
    i = start
    while i < end - 10:
        if out[i] != 0xE8:
            i += 1
            continue
        target = int.from_bytes(out[i + 1:i + 5], "little", signed=True)
        if -i <= target < file_size:
            out[i + 1:i + 5] = ((target - i) if target >= 0 else (target + file_size)).to_bytes(4, "little", signed=True)
        i += 5


def lzx(data: bytes, size: int, window_bits: int = 16, *, wim: bool = False, reset_frames: int = 0) -> bytes:
    """[MS-PATCH] LZX, the LZ77 + Huffman coder of CAB folders (typeCompress 3, window 2^15-2^21),
    WIM chunks and CHM: verbatim, aligned-offset and uncompressed blocks over 32 KiB frames, three
    repeat offsets. CAB streams open with an E8-translation bit (+ 32-bit file size), carry 24-bit
    block sizes and re-align the input after every frame; a WIM chunk (wim=True) has a 1-bit "32 KiB
    block" flag instead and always undoes E8 against 12,000,000. reset_frames restarts the coder
    state every N frames (CHM's reset interval)."""
    if not 0 <= size <= MAX_DECOMPRESSED:
        raise ValueError("LZX output size out of range")
    if window_bits not in LZX_SLOTS:
        raise ValueError(f"LZX window of 2^{window_bits} bytes")
    bits, out = _LzxBits(data), bytearray()
    window, mains = 1 << window_bits, 256 + 8 * LZX_SLOTS[window_bits]
    e8_frames: list[tuple[int, int, int]] = []
    fresh, raw, e8_size = True, False, LZX_WIM_E8_SIZE if wim else 0
    block_end = block_type = 0
    main = aligned = lengths = None
    frame_start, frame_index = 0, 0
    while len(out) < size:
        if fresh:  # Stream start or a CHM reset: empty trees, repeat offsets 1.
            main_lengths, length_lengths, r0, r1, r2 = [0] * mains, [0] * 249, 1, 1, 1
            block_end, fresh = len(out), False
            if not wim:
                e8_size = bits.read(16) << 16 | bits.read(16) if bits.read(1) else 0
        frame_end = min(frame_start + LZX_FRAME, size)
        if len(out) >= block_end:
            block_type = bits.read(3)
            if wim:
                if bits.read(1):
                    block_size = LZX_FRAME
                else:
                    block_size = bits.read(16)
                    if window_bits >= 16:
                        block_size = block_size << 8 | bits.read(8)
            else:
                block_size = bits.read(16) << 8 | bits.read(8)
            block_end += block_size
            if block_end <= len(out):
                raise ValueError("LZX block of zero length")
            if block_type in (1, 2):
                aligned = _lzx_tree([bits.read(3) for _ in range(8)]) if block_type == 2 else None
                _lzx_lengths(bits, main_lengths, 0, 256)
                _lzx_lengths(bits, main_lengths, 256, mains)
                main = _lzx_tree(main_lengths)
                _lzx_lengths(bits, length_lengths, 0, 249)
                lengths = _lzx_tree(length_lengths)
            elif block_type == 3:
                bits.align(skip_aligned=True)
                if bits.at + 12 > len(data):
                    raise ValueError("LZX uncompressed block header past the input")
                r0, r1, r2 = struct.unpack_from("<3I", data, bits.at)
                bits.at += 12
                raw = True
            else:
                raise ValueError(f"LZX block type {block_type}")
        stop = min(block_end, frame_end)
        if raw:
            chunk = data[bits.at:bits.at + stop - len(out)]
            if len(chunk) != stop - len(out):
                raise ValueError("LZX uncompressed block past the input")
            out += chunk
            bits.at += len(chunk)
            if len(out) >= block_end:  # Odd blocks pad to a word; the bitstream starts afresh.
                bits.at += block_size & 1
                raw = False
        while len(out) < stop:
            symbol = bits.symbol(main)
            if symbol < 256:
                out.append(symbol)
                continue
            symbol -= 256
            length, slot = symbol & 7, symbol >> 3
            if length == 7:
                length += bits.symbol(lengths)
            length += 2
            if slot > 2:
                extra = LZX_EXTRA_BITS[slot]
                if block_type == 2 and extra >= 3:
                    offset = LZX_POSITION_BASE[slot] - 2 + (bits.read(extra - 3) << 3) + bits.symbol(aligned)
                else:
                    offset = LZX_POSITION_BASE[slot] - 2 + bits.read(extra)
                r0, r1, r2 = offset, r0, r1
            elif slot == 1:
                offset, r0, r1 = r1, r1, r0
            elif slot == 2:
                offset, r0, r2 = r2, r2, r0
            else:
                offset = r0
            if not 0 < offset <= min(len(out), window):
                raise ValueError("LZX match before the start of the window")
            start = len(out) - offset
            if length <= offset:
                out += out[start:start + length]
            else:
                for i in range(length):
                    out.append(out[start + i])
        if len(out) >= frame_end:  # A frame is complete.
            if e8_size:
                e8_frames.append((frame_start, frame_end, e8_size))
            if not raw and not wim:
                bits.align()
            frame_start, frame_index = frame_end, frame_index + 1
            if reset_frames and frame_index % reset_frames == 0:
                fresh = True
        if len(out) > MAX_DECOMPRESSED:
            raise ValueError("LZX output too large")
    del out[size:]
    for start, end, file_size in e8_frames:  # The window kept the translated bytes matches copy.
        _lzx_e8(out, start, end, file_size)
    return bytes(out)


def _unwrap_mam(data: bytes) -> tuple[bytes, str] | None:
    """A MAM container in LZNT1 (2) or plain Xpress (3) holding a Prefetch file; Xpress Huffman (4),
    the format Windows writes, is the Prefetch reader's own."""
    method = data[3] & 0x7F if data[:3] == b"MAM" and len(data) >= 12 else None
    if method not in (2, 3):
        return None
    size = struct.unpack_from("<I", data, 4)[0]
    body = data[12 if data[3] & 0x80 else 8:]
    try:
        inner = lznt1(body, size) if method == 2 else xpress(body, size)
    except (ValueError, IndexError, struct.error):
        return None
    return (inner, "lznt1" if method == 2 else "xpress") if inner[4:8] == b"SCCA" else None


def _mozlz4(data: bytes, f: dict) -> None:
    import json

    size = struct.unpack_from("<I", data, 8)[0]
    text = lz4_block(data[12:], size)
    f["decompressed_size"] = size
    try:
        document = json.loads(text)
    except ValueError:
        f["json"] = False
        return
    f["json"] = True
    if not isinstance(document, dict):
        return
    f["json_top_level_keys"] = list(document)
    windows = document.get("windows")
    if isinstance(windows, list):  # sessionstore.jsonlz4 / recovery.jsonlz4
        tabs = [tab for window in windows if isinstance(window, dict)
                for tab in window.get("tabs") or [] if isinstance(tab, dict)]
        current = []
        for tab in tabs:
            entries, index = tab.get("entries") or [], tab.get("index")
            index = len(entries) if not isinstance(index, int) else index
            if isinstance(entries, list) and 1 <= index <= len(entries) and isinstance(entries[index - 1], dict):
                current.append(entries[index - 1])
        f.update(window_count=len(windows), tab_count=len(tabs), tab_urls=[entry.get("url") for entry in current],
                 tab_titles=[entry.get("title") for entry in current])
    engines = document.get("engines")
    if isinstance(engines, list):  # search.json.mozlz4
        f["engine_names"] = [engine.get("_name") for engine in engines if isinstance(engine, dict)]
        default = (document.get("metaData") or {}).get("defaultEngineId") if isinstance(document.get("metaData"), dict) else None
        if default:
            f["default_engine_id"] = default


# --- Days 27-31 candidates: thumbcache, hiberfil, WIM, ext, FAT/exFAT, EVT, INDX, $LogFile, PKCS#7 ----

def _thumbcache(data: bytes, f: dict) -> None:
    version, kind = struct.unpack_from("<II", data, 4)
    f.update(format_version=version, cache_type=kind, entry_count=data.count(b"CMMM", 4),
             windows_version={20: "Vista", 21: "7", 26: "8", 28: "8.1", 30: "10", 31: "10", 32: "10"}.get(version))


def _hiberfil(data: bytes, f: dict) -> None:
    f["signature"] = data[:4].decode("ascii")
    f["resumable"] = data[:4] in (b"hibr", b"HIBR")
    if struct.unpack_from("<I", data, 0x18)[0] == 4096:  # PO_MEMORY_IMAGE (64-bit, Windows 8+).
        f.update(length_self=struct.unpack_from("<I", data, 0x0C)[0], page_size=4096,
                 system_time_utc=_filetime(struct.unpack_from("<Q", data, 0x20)[0]))


WIM_COMPRESSION = ((0x20000, "xpress"), (0x40000, "lzx"), (0x80000, "lzms"))


def _wim(data: bytes, f: dict) -> None:
    size, version, flags, chunk = struct.unpack_from("<IIII", data, 8)
    part, total, images = struct.unpack_from("<HHI", data, 40)
    compression = next((name for bit, name in WIM_COMPRESSION if flags & bit), "unknown") if flags & 2 else "none"
    f.update(header_size=size, version=f"0x{version:08x}", flags=flags, compression=compression, chunk_size=chunk,
             guid=_guid(data[24:40]), part_number=part, total_parts=total, image_count=images,
             boot_index=struct.unpack_from("<I", data, 0x78)[0], read_only=bool(flags & 4), spanned=bool(flags & 8))
    length, offset = int.from_bytes(data[0x48:0x4F], "little"), struct.unpack_from("<Q", data, 0x50)[0]
    if 0 < length <= 1 << 20 and offset + length <= len(data):
        xml = data[offset:offset + length].decode("utf-16-le", "replace").lstrip("﻿")
        blocks = re.findall(r"<IMAGE\b[^>]*>(.*?)</IMAGE>", xml, re.S)
        f["image_names"] = [match.group(1) for block in blocks if (match := re.search(r"<NAME>(.*?)</NAME>", block))]
        f["image_descriptions"] = [match.group(1) for block in blocks
                                   if (match := re.search(r"<DESCRIPTION>(.*?)</DESCRIPTION>", block))]
    try:
        _wim_image(data, chunk or LZX_FRAME, compression, f)
    except (ValueError, IndexError, struct.error) as exc:
        f["image_tree_damaged"] = f"{type(exc).__name__}: {exc}"


MAX_WIM_ENTRIES = 50000


def _wim_resource(data: bytes, header: int, chunk: int, compression: str) -> bytes:
    """A resource header (7-byte stored size, flags, offset, original size) -> its bytes."""
    stored, flags = int.from_bytes(data[header:header + 7], "little"), data[header + 7]
    offset, original = struct.unpack_from("<QQ", data, header + 8)
    return _wim_read(data, stored, flags, offset, original, chunk, compression)


def _wim_read(data: bytes, stored: int, flags: int, offset: int, original: int, chunk: int, compression: str) -> bytes:
    """Compressed resources (flag 4) start with a table of chunk offsets (32-bit, or 64-bit past 4 GiB)
    relative to its end; a chunk whose stored size equals its full size is kept raw."""
    if offset + stored > len(data) or original > MAX_DECOMPRESSED:
        raise ValueError("WIM resource past the file or too large")
    if not flags & 4:
        return data[offset:offset + original]
    if flags & 0x10:
        raise ValueError("solid (LZMS) WIM resource")
    count = -(-original // chunk)
    entry = 8 if original > 0xFFFFFFFF else 4
    table = (count - 1) * entry
    starts = [0] + [int.from_bytes(data[offset + i * entry:offset + (i + 1) * entry], "little") for i in range(count - 1)]
    ends, body = starts[1:] + [stored - table], offset + table
    out = bytearray()
    for i, (start, end) in enumerate(zip(starts, ends)):
        want = min(chunk, original - i * chunk)
        piece = data[body + start:body + end]
        if not 0 < len(piece) <= want or body + end > offset + stored:
            raise ValueError("WIM chunk table out of range")
        if len(piece) == want:
            out += piece
        elif compression == "lzx":
            out += lzx(piece, want, max(15, (chunk - 1).bit_length()), wim=True)
        else:
            raise ValueError(f"WIM {compression} chunks not supported")
    return bytes(out)


def _wim_image(data: bytes, chunk: int, compression: str, f: dict) -> None:
    """The first image's metadata resource: security data, then the root directory entry; each
    directory's children follow its subdir offset until a zero length. Entries list their times and
    the SHA-1 of their unnamed stream, which the blob table maps to a size."""
    table = _wim_resource(data, 0x30, chunk, compression)
    sizes, metadata = {}, None
    for at in range(0, len(table) - 49, 50):
        stored, flags = int.from_bytes(table[at:at + 7], "little"), table[at + 7]
        offset, original = struct.unpack_from("<QQ", table, at + 8)
        sizes[table[at + 30:at + 50]] = original
        if flags & 2 and metadata is None:
            metadata = (stored, flags, offset, original)
    if metadata is None:
        return
    meta = _wim_read(data, *metadata, chunk, compression)
    root = max(8, struct.unpack_from("<I", meta, 0)[0] + 7 & ~7)
    paths, names, file_sizes, directories, latest, seen = [], [], [], 0, (0, ""), set()
    stack = [(struct.unpack_from("<Q", meta, root + 16)[0], "", 0)]
    while stack:
        at, parent, depth = stack.pop()
        while 0 < at < len(meta) and len(seen) < MAX_WIM_ENTRIES and at not in seen:
            seen.add(at)
            length = struct.unpack_from("<Q", meta, at)[0]
            if length < 102:  # The end of this directory's list.
                break
            attributes, _, subdir = struct.unpack_from("<IiQ", meta, at + 8)
            written = struct.unpack_from("<Q", meta, at + 56)[0]
            streams, _, name_bytes = struct.unpack_from("<HHH", meta, at + 96)
            name = meta[at + 102:at + 102 + name_bytes].decode("utf-16-le", "replace")
            path = f"{parent}/{name}"
            if attributes & 0x10:
                directories += 1
                if subdir and depth < 64:
                    stack.append((subdir, path, depth + 1))
            else:
                paths.append(path)
                names.append(name)
                file_sizes.append(sizes.get(meta[at + 64:at + 84], 0))
                latest = max(latest, (written, path))
            at += length + 7 & ~7
            for _ in range(streams):  # Named data streams follow the entry, each with its own length.
                at += struct.unpack_from("<Q", meta, at)[0] + 7 & ~7
    # Also under the plain words ("wim.file_names"): `name` is a noise word when fields are scored.
    f.update(image_file_paths=paths, image_file_names=names, image_file_sizes=file_sizes,
             image_file_count=len(paths), image_directory_count=directories,
             image_total_bytes=sum(file_sizes), file_paths=paths, file_names=names, file_count=len(paths),
             directory_count=directories)
    if latest[0]:
        f.update(image_latest_write_utc=_filetime(latest[0]), image_latest_write_path=latest[1])


EXT_OS = {0: "linux", 1: "hurd", 2: "masix", 3: "freebsd", 4: "lites"}


def _ext(data: bytes, f: dict) -> None:
    sb = data[1024:2048]
    inodes, blocks, _, free_blocks, free_inodes, _, log_block = struct.unpack_from("<7I", sb, 0)
    blocks_per_group, _, inodes_per_group, mounted, written = struct.unpack_from("<5I", sb, 32)
    mounts, max_mounts, _, state = struct.unpack_from("<HhHH", sb, 52)
    checked, _, creator, revision = struct.unpack_from("<4I", sb, 64)
    inode_size = struct.unpack_from("<H", sb, 88)[0]
    compat, incompat, ro_compat = struct.unpack_from("<3I", sb, 92)
    if incompat & 0x80:  # 64BIT: the high half of the block counts.
        blocks |= struct.unpack_from("<I", sb, 0x150)[0] << 32
        free_blocks |= struct.unpack_from("<I", sb, 0x158)[0] << 32
    uuid = sb[104:120].hex()
    text = lambda raw: raw.split(b"\0", 1)[0].decode("utf-8", "replace")
    f.update(filesystem_type="ext4" if incompat & 0x2C0 else "ext3" if compat & 4 else "ext2",
             volume_name=text(sb[120:136]), uuid=f"{uuid[:8]}-{uuid[8:12]}-{uuid[12:16]}-{uuid[16:20]}-{uuid[20:]}",
             last_mounted_path=text(sb[136:200]), block_size_bytes=1024 << log_block, block_count=blocks,
             inode_count=inodes, free_block_count=free_blocks, free_inode_count=free_inodes, inode_size=inode_size,
             blocks_per_group=blocks_per_group, inodes_per_group=inodes_per_group, mount_count=mounts,
             max_mount_count=max_mounts, clean=bool(state & 1), has_journal=bool(compat & 4),
             last_mount_utc=_unix(mounted), last_write_utc=_unix(written), last_check_utc=_unix(checked),
             created_utc=_unix(struct.unpack_from("<I", sb, 0x108)[0]), creator_os=EXT_OS.get(creator, str(creator)),
             revision=revision, feature_compat=compat, feature_incompat=incompat, feature_ro_compat=ro_compat)


def _serial(value: int) -> str:
    return f"{value >> 16:04X}-{value & 0xFFFF:04X}"


def _fat(data: bytes, f: dict) -> None:
    sector, per_cluster, reserved, fats, roots, total16, media, per_fat16 = struct.unpack_from("<HBHBHHBH", data, 11)
    fat32 = data[82:87] == b"FAT32"
    serial, label, kind = (67, data[71:82], data[82:90]) if fat32 else (39, data[43:54], data[54:62])
    serial = struct.unpack_from("<I", data, serial)[0]
    f.update(oem_name=data[3:11].decode("ascii", "replace").rstrip(), bytes_per_sector=sector,
             sectors_per_cluster=per_cluster, cluster_size_bytes=sector * per_cluster, reserved_sector_count=reserved,
             fat_count=fats, root_entry_count=roots, total_sectors=total16 or struct.unpack_from("<I", data, 32)[0],
             media_descriptor=f"0x{media:02x}",
             sectors_per_fat=struct.unpack_from("<I", data, 36)[0] if fat32 else per_fat16,
             volume_serial_number=_serial(serial), volume_serial=serial,
             volume_label=label.decode("ascii", "replace").rstrip(), filesystem_type=kind.decode("ascii", "replace").rstrip())
    if fat32:
        f["root_directory_cluster"] = struct.unpack_from("<I", data, 44)[0]


def _exfat(data: bytes, f: dict) -> None:
    partition, length = struct.unpack_from("<QQ", data, 64)
    fat_offset, fat_length, heap, clusters, root, serial = struct.unpack_from("<6I", data, 80)
    sector, per_cluster = 1 << data[108], 1 << data[109]
    f.update(partition_offset=partition, volume_length_sectors=length, fat_offset=fat_offset, fat_length=fat_length,
             cluster_heap_offset=heap, cluster_count=clusters, root_directory_cluster=root,
             volume_serial_number=_serial(serial), volume_serial=serial, filesystem_revision=f"{data[105]}.{data[104]:02d}",
             volume_flags=struct.unpack_from("<H", data, 106)[0], bytes_per_sector=sector,
             sectors_per_cluster=per_cluster, cluster_size_bytes=sector * per_cluster, fat_count=data[110],
             percent_in_use=data[112])
    start = (heap + (root - 2) * per_cluster) * sector
    for at in range(start, min(start + sector * per_cluster, len(data) - 31), 32):
        if data[at] == 0x83:  # Volume label entry: character count, then UTF-16.
            f["volume_label"] = data[at + 2:at + 2 + 2 * min(data[at + 1], 11)].decode("utf-16-le", "replace")
            break
        if data[at] == 0:
            break


def _evt(data: bytes, f: dict) -> None:
    _, _, major, minor, _, _, current, oldest, maximum, flags, _ = struct.unpack_from("<I4s9I", data, 0)
    records = []
    at = data.find(b"LfLe", 0x30)
    while at >= 0 and len(records) < 100000:
        start = at - 4
        length = struct.unpack_from("<I", data, start)[0]
        if length >= 0x38 and start + length <= len(data):
            number, generated, _, event = struct.unpack_from("<4I", data, start + 8)
            names = data[start + 0x38:start + length].decode("utf-16-le", "replace").split("\0")
            records.append((number, generated, event & 0xFFFF, names[0], names[1] if len(names) > 1 else ""))
        at = data.find(b"LfLe", at + 4)
    unique = lambda values: list(dict.fromkeys(value for value in values if value))
    times = [record[1] for record in records if record[1]]
    f.update(format_version=f"{major}.{minor}", oldest_record_number=oldest, next_record_number=current,
             header_record_count=current - oldest if current >= oldest else None, record_count=len(records),
             max_size_bytes=maximum, dirty=bool(flags & 1), wrapped=bool(flags & 2), log_full=bool(flags & 4),
             event_ids=[record[2] for record in records], source_names=unique(record[3] for record in records),
             computer_names=unique(record[4] for record in records),
             first_record_number=records[0][0] if records else None, last_record_number=records[-1][0] if records else None,
             first_time_utc=_unix(min(times)) if times else None, last_time_utc=_unix(max(times)) if times else None)


def _indx(data: bytes, f: dict) -> None:
    page = _fixups(data[:4096])
    start, used, _ = struct.unpack_from("<III", page, 24)
    at, end = 24 + start, min(24 + used, len(page))
    names, entries, created, modified = [], 0, [], []
    while at + 16 <= end:
        length, stream, flags = struct.unpack_from("<HHI", page, at + 8)
        if flags & 2 or length < 16:
            break
        entries += 1
        if stream >= 66:
            entry = page[at + 16:at + 16 + stream]
            if entry[65] != 2:  # The DOS 8.3 twin repeats a long name.
                names.append(entry[66:66 + 2 * entry[64]].decode("utf-16-le", "replace"))
                created.append(_filetime(struct.unpack_from("<Q", entry, 8)[0]))
                modified.append(_filetime(struct.unpack_from("<Q", entry, 16)[0]))
        at += length
    f.update(vcn=struct.unpack_from("<Q", page, 16)[0], entry_count=entries, file_names=names, file_count=len(names),
             created_times_utc=created, modified_times_utc=modified, has_subnodes=bool(page[36] & 1))


def _logfile(data: bytes, f: dict) -> None:
    _, _, chkdsk, system_page, log_page, restart, minor, major = struct.unpack_from("<HHQIIHhh", data, 4)
    if log_page != 4096 or system_page < 4096 or system_page & (system_page - 1):
        raise ValueError("$LogFile restart page sizes")
    page = _fixups(data[:system_page]) if len(data) >= system_page else data
    current, clients, _, _, flags = struct.unpack_from("<QHHHH", page, restart)
    f.update(system_page_size=system_page, log_page_size=log_page, major_version=major, minor_version=minor,
             version=f"{major}.{minor}", chkdsk_lsn=chkdsk, current_lsn=current, log_client_count=clients,
             log_file_size=struct.unpack_from("<Q", page, restart + 24)[0], clean_dismount=bool(flags & 2),
             record_page_count=data.count(b"RCRD"))


PKCS7_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")  # 1.2.840.113549.1.7.2
DIGESTS = {"1.3.14.3.2.26": "sha1", "2.16.840.1.101.3.4.2.1": "sha256", "2.16.840.1.101.3.4.2.2": "sha384",
           "2.16.840.1.101.3.4.2.3": "sha512", "1.2.840.113549.2.5": "md5"}


def _pkcs7_fields(data: bytes, at: int = 0) -> dict:
    """A CMS/PKCS#7 SignedData: its certificates and the signer's (matched by issuer serial)."""
    _, start, end = der(data, at)
    oid, content = der_children(data, start, end)[:2]
    if data[oid[1]:oid[2]] != PKCS7_SIGNED_DATA:
        raise ValueError("not a PKCS#7 SignedData")
    _, start, end = der(data, content[1])
    items = der_children(data, start, end)
    certificates = []
    for tag, inner, stop in items:
        if tag == 0xA0:
            while inner < stop and len(certificates) < 64:
                certificates.append(certificate(data, inner))
                inner = der(data, inner)[2]
    out: dict = {"certificate_count": len(certificates), "certificate_subjects": [c["subject"] for c in certificates],
                 "certificate_subject_cns": [c["subject_cn"] for c in certificates]}
    signers = items[-1]
    if signers[0] == 0x31 and signers[1] < signers[2]:
        info = der_children(data, *der(data, signers[1])[1:])
        sid, digest = info[1], info[2]
        if sid[0] == 0x30:
            serial = der_children(data, sid[1], sid[2])[1]
            wanted = data[serial[1]:serial[2]].lstrip(b"\0").hex() or "00"
            signer = next((c for c in certificates if c["serial_number"] == wanted), None)
            if signer:
                out.update({f"signer_{key}": value for key, value in signer.items()})
        algorithm = der_children(data, digest[1], digest[2])[0]
        out["digest_algorithm"] = DIGESTS.get(_oid(data[algorithm[1]:algorithm[2]]), _oid(data[algorithm[1]:algorithm[2]]))
        for tag, inner, stop in info[3:]:
            if tag != 0xA0:
                continue
            for _, a, b in der_children(data, inner, stop):
                kind, values = der_children(data, a, b)[:2]
                if _oid(data[kind[1]:kind[2]]) == "1.2.840.113549.1.9.5":  # signingTime
                    out["signing_time_utc"] = _der_time(data, der_children(data, values[1], values[2])[0])
    return out


def _pkcs7(data: bytes, f: dict) -> None:
    text = data[:1 << 20].lstrip()
    if text.startswith(b"-----BEGIN PKCS7-----"):
        import base64

        body = text.split(b"-----BEGIN PKCS7-----", 1)[1].split(b"-----END PKCS7-----", 1)[0]
        data = base64.b64decode(b"".join(body.split()))
    f.update(_pkcs7_fields(data))


def _pe_certificate_table(data: bytes) -> tuple[int, int] | None:
    """A PE's IMAGE_DIRECTORY_ENTRY_SECURITY (a file offset, not an RVA), when it has one."""
    if data[:2] != b"MZ" or len(data) < 0x40:
        return None
    lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[lfanew:lfanew + 4] != b"PE\0\0" or lfanew + 0x98 + 40 > len(data):
        return None
    magic = struct.unpack_from("<H", data, lfanew + 24)[0]
    if magic not in (0x10B, 0x20B):
        return None
    offset, size = struct.unpack_from("<II", data, lfanew + 24 + (96 if magic == 0x10B else 112) + 32)
    return (offset, size) if offset and 8 <= size and offset + size <= len(data) else None


def pe_signature(data: bytes) -> dict | None:
    """A signed PE's Authenticode fields (for formats.describe, which reads a PE with pe() alone)."""
    return _guarded(_pe_signature, data) if _pe_certificate_table(data) else None


def _pe_signature(data: bytes, f: dict) -> None:
    offset, size = _pe_certificate_table(data)
    length, revision, kind = struct.unpack_from("<IHH", data, offset)
    f.update(certificate_table_offset=offset, certificate_table_size=size, win_certificate_length=length,
             win_certificate_revision=f"0x{revision:04x}", win_certificate_type=kind, signed=kind == 2)
    if kind == 2:  # WIN_CERT_TYPE_PKCS_SIGNED_DATA: Authenticode.
        f.update(_pkcs7_fields(data, offset + 8))


# --- Registry keys below the root (Days 27+: Amcache, UserAssist, Run, SYSTEM/SOFTWARE/SAM facts) --

MAX_REGISTRY_KEYS = 50000
MAX_REGISTRY_VALUES = 4096  # Per key.


def _cell(data: bytes, offset: int) -> bytes:
    """An allocated hive cell's bytes (offsets count from the first hbin; the size is negative)."""
    at = 0x1000 + offset
    size = struct.unpack_from("<i", data, at)[0]
    if size >= 0 or at - size > len(data):
        raise ValueError("registry cell")
    return data[at + 4:at - size]


def _subkey_offsets(data: bytes, offset: int, depth: int = 0) -> list[int]:
    cell = _cell(data, offset)
    kind, count = cell[:2], struct.unpack_from("<H", cell, 2)[0]
    if kind in (b"lf", b"lh"):
        return [struct.unpack_from("<I", cell, 4 + 8 * i)[0] for i in range(count)]
    if kind == b"li":
        return [struct.unpack_from("<I", cell, 4 + 4 * i)[0] for i in range(count)]
    if kind == b"ri" and depth < 4:
        return [child for i in range(count)
                for child in _subkey_offsets(data, struct.unpack_from("<I", cell, 4 + 4 * i)[0], depth + 1)]
    raise ValueError("registry subkey list")


def _reg_value(kind: int, raw: bytes | None):
    if raw is None:
        return None
    if kind in (1, 2):  # REG_SZ, REG_EXPAND_SZ
        return raw.decode("utf-16-le", "replace").split("\0", 1)[0]
    if kind == 7:  # REG_MULTI_SZ
        return [part for part in raw.decode("utf-16-le", "replace").split("\0") if part]
    if kind == 4 and len(raw) >= 4:
        return struct.unpack_from("<I", raw)[0]
    if kind == 5 and len(raw) >= 4:
        return struct.unpack_from(">I", raw)[0]
    if kind == 11 and len(raw) >= 8:
        return struct.unpack_from("<Q", raw)[0]
    return raw


def _registry_keys(data: bytes) -> list[tuple[str, int, dict]]:
    """Every key below the root, depth first: (path without the root's name, last written FILETIME,
    {value name: (type, decoded data)}). Big-data values (over 16344 bytes) are left out."""
    keys: list[tuple[str, int, dict]] = []
    stack: list[tuple[int, str | None]] = [(struct.unpack_from("<I", data, 0x24)[0], None)]
    seen: set[int] = set()
    while stack and len(keys) < MAX_REGISTRY_KEYS:
        offset, parent = stack.pop()
        if offset in seen:
            continue
        seen.add(offset)
        cell = _cell(data, offset)
        if cell[:2] != b"nk":
            continue
        flags, written = struct.unpack_from("<HQ", cell, 2)
        raw = cell[0x4C:0x4C + struct.unpack_from("<H", cell, 0x48)[0]]
        name = raw.decode("latin-1") if flags & 0x20 else raw.decode("utf-16-le", "replace")
        path = "" if parent is None else f"{parent}\\{name}" if parent else name
        values: dict[str, tuple[int, object]] = {}
        count, listing = struct.unpack_from("<II", cell, 0x24)
        if count:
            offsets = _cell(data, listing)
            for i in range(min(count, len(offsets) // 4, MAX_REGISTRY_VALUES)):
                try:
                    vk = _cell(data, struct.unpack_from("<I", offsets, 4 * i)[0])
                    if vk[:2] != b"vk":
                        continue
                    length, size, where, kind = struct.unpack_from("<HIII", vk, 2)
                    label = vk[0x14:0x14 + length]
                    label = label.decode("latin-1") if struct.unpack_from("<H", vk, 0x10)[0] & 1 else label.decode("utf-16-le", "replace")
                    if size & 0x80000000:
                        blob = struct.pack("<I", where)[:size & 0x7FFFFFFF]
                    else:
                        blob = _cell(data, where)[:size] if size <= 16344 else None
                    values[label] = (kind, _reg_value(kind, blob))
                except (struct.error, ValueError, IndexError):
                    continue
        keys.append((path, written, values))
        if struct.unpack_from("<I", cell, 0x14)[0]:
            try:
                children = _subkey_offsets(data, struct.unpack_from("<I", cell, 0x1C)[0])
            except (struct.error, ValueError, IndexError):
                children = []
            stack.extend((child, path) for child in reversed(children))
    return keys


def _rot13(text: str) -> str:
    return text.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                                        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))


def _regf_tree(data: bytes, f: dict) -> None:
    """The key tree's counts and the classic artifacts of NTUSER, SYSTEM, SOFTWARE, SAM and Amcache."""
    keys = _registry_keys(data)
    by_path = {path.casefold(): values for path, _, values in keys}
    text = lambda value: value if isinstance(value, str) else None
    under = lambda pattern: [(path, values) for path, _, values in keys if re.search(pattern, path, re.I)]
    value = lambda path, name: (by_path.get(path.casefold()) or {}).get(name, (None, None))[1]
    latest = max(keys, key=lambda key: key[1]) if keys else None
    f.update(key_count=len(keys), value_count=sum(len(values) for _, _, values in keys),
             max_key_depth=max((path.count("\\") + 1 for path, _, _ in keys if path), default=0),
             key_paths=[path for path, _, _ in keys if path][:5000],
             last_written_key_path=latest[0] if latest else None,
             last_written_key_utc=_filetime(latest[1]) if latest else None)
    # NTUSER.DAT
    entries, counts, last_run = [], {}, {}
    for _, values in under(r"\\UserAssist\\\{[0-9A-Fa-f-]+\}\\Count$"):
        for name, (_, raw) in values.items():
            program = _rot13(name)
            entries.append(program)
            if isinstance(raw, bytes) and len(raw) >= 68:  # Windows 7+: count at 4, last run at 60.
                counts[program], when = struct.unpack_from("<I", raw, 4)[0], _filetime(struct.unpack_from("<Q", raw, 60)[0])
                if when:
                    last_run[program] = when
    if entries:
        f.update(userassist_entries=entries, userassist_entry_count=len(entries),
                 userassist_run_counts=counts, userassist_last_run=last_run)
    for kind in ("Run", "RunOnce"):
        found = {name: text(raw) for path, values in under(rf"(?:^|\\)Microsoft\\Windows\\CurrentVersion\\{kind}$")
                 for name, (_, raw) in values.items()}
        if found:
            prefix = kind.lower()
            f.update({f"{prefix}_values": found, f"{prefix}_value_names": list(found), f"{prefix}_commands": list(found.values())})
    for field, pattern in (("typed_paths", r"\\Explorer\\TypedPaths$"), ("typed_urls", r"\\Internet Explorer\\TypedURLs$")):
        for _, values in under(pattern):
            ordered = sorted(((name, raw) for name, (_, raw) in values.items() if re.fullmatch(r"url\d+", name, re.I)),
                             key=lambda item: int(item[0][3:]))
            f[field] = [text(raw) for _, raw in ordered]
    for _, values in under(r"\\Explorer\\RunMRU$"):
        order = text(values.get("MRUList", (None, ""))[1]) or ""
        f["run_mru"] = [re.sub(r"\\1$", "", text(values[letter][1]) or "") for letter in order if letter in values]
    for _, values in under(r"\\Explorer\\WordWheelQuery$"):
        f["search_terms"] = [raw.decode("utf-16-le", "replace").split("\0", 1)[0] for name, (_, raw) in values.items()
                             if name != "MRUListEx" and isinstance(raw, bytes)]
    # SYSTEM: the current control set.
    current = value("Select", "Current")
    control = f"ControlSet{current if isinstance(current, int) and 0 < current < 1000 else 1:03d}"
    if by_path.get(control.casefold()) is not None:
        f["current_control_set"] = control
        f["computer_name"] = text(value(f"{control}\\Control\\ComputerName\\ComputerName", "ComputerName"))
        f["time_zone_name"] = text(value(f"{control}\\Control\\TimeZoneInformation", "TimeZoneKeyName")
                                   or value(f"{control}\\Control\\TimeZoneInformation", "StandardName"))
        shutdown = value(f"{control}\\Control\\Windows", "ShutdownTime")
        if isinstance(shutdown, bytes) and len(shutdown) == 8:
            f["last_shutdown_utc"] = _filetime(struct.unpack("<Q", shutdown)[0])
        services = under(rf"^{control}\\Services\\[^\\]+$")
        f.update(service_names=[path.rsplit("\\", 1)[1] for path, _ in services], service_count=len(services),
                 service_image_paths={path.rsplit("\\", 1)[1]: text(values["ImagePath"][1])
                                      for path, values in services if "ImagePath" in values})
        devices = under(rf"^{control}\\Enum\\USBSTOR\\[^\\]+$")
        serials = under(rf"^{control}\\Enum\\USBSTOR\\[^\\]+\\[^\\]+$")
        if devices:
            f.update(usbstor_devices=[path.rsplit("\\", 1)[1] for path, _ in devices],
                     usb_serial_numbers=[re.sub(r"&\d+$", "", path.rsplit("\\", 1)[1]) for path, _ in serials],
                     usb_friendly_names=[text(values["FriendlyName"][1]) for _, values in serials if "FriendlyName" in values])
    mounted = by_path.get("mounteddevices")
    if mounted:
        f["mounted_devices"] = list(mounted)
    # SOFTWARE
    version = "Microsoft\\Windows NT\\CurrentVersion"
    if by_path.get(version.casefold()) is not None:
        for field, name in (("product_name", "ProductName"), ("registered_owner", "RegisteredOwner"),
                            ("registered_organization", "RegisteredOrganization"), ("edition_id", "EditionID"),
                            ("display_version", "DisplayVersion"), ("current_version", "CurrentVersion")):
            f[field] = text(value(version, name))
        f["current_build"] = text(value(version, "CurrentBuild") or value(version, "CurrentBuildNumber"))
        installed = value(version, "InstallDate")
        f["install_date_utc"] = _unix(installed) if isinstance(installed, int) else None
    programs = under(r"^(?:WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$")
    if programs:
        f["installed_programs"] = [text(values["DisplayName"][1]) for _, values in programs if "DisplayName" in values]
    profiles = under(r"^Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\[^\\]+$")
    if profiles:
        f["network_profiles"] = [text(values["ProfileName"][1]) for _, values in profiles if "ProfileName" in values]
    # SAM
    users = under(r"^SAM\\Domains\\Account\\Users\\Names\\[^\\]+$")
    if users:
        f.update(sam_user_names=[path.rsplit("\\", 1)[1] for path, _ in users], sam_user_count=len(users))
    # Amcache.hve: InventoryApplicationFile (Windows 10+) or File\{volume}\<id> (Windows 8).
    files = under(r"^Root\\InventoryApplicationFile\\[^\\]+$")
    old = under(r"^Root\\File\\\{[^}]+\}\\[^\\]+$")
    if files or old:
        pick = lambda values, *names: next((text(values[name][1]) for name in names if name in values), None)
        f.update(amcache_entry_count=len(files) + len(old),
                 amcache_paths=[pick(v, "LowerCaseLongPath") for _, v in files] + [pick(v, "15") for _, v in old],
                 amcache_sha1s=[re.sub(r"^0000", "", pick(v, "FileId", "101") or "") or None for _, v in files + old],
                 amcache_names=[pick(v, "Name") for _, v in files],
                 amcache_publishers=[pick(v, "Publisher") for _, v in files])
    applications = under(r"^Root\\InventoryApplication\\[^\\]+$")
    if applications:
        f["amcache_programs"] = [text(values["Name"][1]) for _, values in applications if "Name" in values]


def formats(data: bytes) -> list[tuple[str, dict]]:
    unwrapped = _unwrap_mam(data)
    if unwrapped:
        data = unwrapped[0]
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
        # Days 27-31: the real shapes of the forecast families (thumbnails, memory, images, NTFS, certs).
        ("thumbcache", data[:4] == b"CMMM" and len(data) >= 24, _thumbcache),
        ("hiberfil", data[:4] in (b"hibr", b"HIBR", b"wake", b"WAKE") and len(data) >= 0x40, _hiberfil),
        ("wim", data.startswith(b"MSWIM\0\0\0") and len(data) >= 0xD0, _wim),
        ("ext", len(data) >= 2048 and data[1080:1082] == b"\x53\xef", _ext),
        ("fat", len(data) >= 512 and data[510:512] == b"\x55\xaa" and data[:1] in (b"\xeb", b"\xe9")
         and (data[54:59] in (b"FAT12", b"FAT16") or data[54:62] == b"FAT     " or data[82:87] == b"FAT32"), _fat),
        ("exfat", len(data) >= 512 and data[3:11] == b"EXFAT   ", _exfat),
        ("evt", len(data) >= 0x30 and data[:8] == b"\x30\0\0\0LfLe", _evt),
        ("indx", data[:4] == b"INDX" and len(data) >= 0x40, _indx),
        ("ntfs_logfile", data[:4] == b"RSTR" and len(data) >= 0x40, _logfile),
        ("mozlz4", data.startswith(b"mozLz40\0") and len(data) >= 12, _mozlz4),
        ("pkcs7", (data[:1] == b"\x30" and PKCS7_SIGNED_DATA in data[:24])
         or data[:4096].lstrip().startswith(b"-----BEGIN PKCS7-----"), _pkcs7),
        ("pe_signature", _pe_certificate_table(data) is not None, _pe_signature),
    )
    found = [(label, _guarded(parse, data)) for label, match, parse in checks if match]
    for label, fields in found:
        if label == "prefetch" and unwrapped:
            fields.update(compressed=True, compression=unwrapped[1])
        if label == "regf" and "damaged" not in fields and data[0x1000:0x1004] == b"hbin":
            tree = _guarded(_regf_tree, data)
            if "damaged" in tree:
                tree["tree_damaged"] = tree.pop("damaged")
            fields.update(tree)
    if data.startswith(b"\x04\x22\x4d\x18") and len(data) >= 7:
        descriptor = data[4]
        found.append(("lz4", {"version": descriptor >> 6, "content_checksum": bool(descriptor & 0x04),
                              "content_size_present": bool(descriptor & 0x08),
                              "block_max_size_bytes": {4: 65536, 5: 262144, 6: 1 << 20, 7: 4 << 20}.get((data[5] >> 4) & 7)}))
    return found
