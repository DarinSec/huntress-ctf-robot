"""LZX, the compression inside CAB folders and WIM resources, from a small encoder written to the
same specification ([MS-PATCH] LZX DELTA, libmspack's CAB framing, wimlib's WIM chunks): verbatim,
aligned-offset and uncompressed blocks, the three repeat offsets, E8 call translation, 32 KiB frames.
The decoder was also checked against real encoders outside the suite: every resource of wimlib's LZX
WIMs (chunks of 32 KiB, 64 KiB and 2 MiB) matched its stored SHA-1, and cabextract (libmspack)
unpacked this encoder's CABs to the same bytes.
"""

import hashlib
import heapq
import random
import struct
import unittest
import zlib

from huntress_ctf import formats_dfir
from huntress_ctf.formats_dfir import formats as dfir_formats
from tests.test_forecast import first_untimed_answer

EXTRA, BASE, FRAME = formats_dfir.LZX_EXTRA_BITS, formats_dfir.LZX_POSITION_BASE, formats_dfir.LZX_FRAME


class Bits:
    """16-bit little-endian words filled from their high bit."""

    def __init__(self):
        self.out, self.acc, self.n = bytearray(), 0, 0

    def put(self, value, count):
        self.acc, self.n = self.acc << count | value, self.n + count
        while self.n >= 16:
            self.n -= 16
            self.out += (self.acc >> self.n).to_bytes(2, "little")
            self.acc &= (1 << self.n) - 1

    def align(self, always=False):
        if self.n or always:
            self.put(0, 16 - self.n if self.n else 16)

    def code(self, codes, symbol):
        self.put(*codes[symbol])


def huffman_lengths(freqs, limit):
    freqs = list(freqs)
    while True:
        used = [symbol for symbol, freq in enumerate(freqs) if freq]
        for symbol in range(len(freqs)):  # A tree needs two leaves.
            if len(used) >= 2:
                break
            if symbol not in used:
                used.append(symbol)
                freqs[symbol] = 1
        lengths = [0] * len(freqs)
        heap = [(freqs[symbol], symbol, [symbol]) for symbol in used]
        heapq.heapify(heap)
        while len(heap) > 1:
            a, b = heapq.heappop(heap), heapq.heappop(heap)
            for symbol in a[2] + b[2]:
                lengths[symbol] += 1
            heapq.heappush(heap, (a[0] + b[0], min(a[1], b[1]), a[2] + b[2]))
        if max(lengths) <= limit:
            return lengths
        freqs = [freq >> 1 | 1 if freq else 0 for freq in freqs]


def canonical(lengths):
    codes, code, previous = {}, 0, 0
    for length, symbol in sorted((length, symbol) for symbol, length in enumerate(lengths) if length):
        code <<= length - previous
        previous = length
        codes[symbol] = (code, length)
        code += 1
    return codes


def write_lengths(bits, lengths, previous, first, last):
    """Deltas against the previous block's lengths, with the zero runs (17, 18) and same-length runs
    (19) of the pretree."""
    tokens, x = [], first
    while x < last:
        run = 1
        while x + run < last and lengths[x + run] == lengths[x]:
            run += 1
        if lengths[x] == 0 and run >= 20:
            run = min(run, 51)
            tokens.append((18, run - 20, 5))
        elif lengths[x] == 0 and run >= 4:
            run = min(run, 19)
            tokens.append((17, run - 4, 4))
        elif run >= 4:
            run = min(run, 5)
            tokens.append((19, run - 4, 1, (previous[x] - lengths[x]) % 17))
        else:
            run = 1
            tokens.append(((previous[x] - lengths[x]) % 17,))
        x += run
    freqs = [0] * 20
    for token in tokens:
        freqs[token[0]] += 1
        if token[0] == 19:
            freqs[token[3]] += 1
    pre = huffman_lengths(freqs, 15)
    for length in pre:
        bits.put(length, 4)
    codes = canonical(pre)
    for token in tokens:
        bits.code(codes, token[0])
        if len(token) > 1:
            bits.put(token[1], token[2])
        if len(token) > 3:
            bits.code(codes, token[3])
    previous[first:last] = lengths[first:last]


def e8_translate(data, start, end, file_size):
    """The encoder's half of E8 translation: relative CALL targets to absolute ones."""
    out, i = bytearray(data), start
    while i < end - 10:
        if out[i] == 0xE8:
            relative = int.from_bytes(out[i + 1:i + 5], "little", signed=True)
            if -i <= relative < file_size:
                absolute = relative + i if relative < file_size - i else relative - file_size
                out[i + 1:i + 5] = absolute.to_bytes(4, "little", signed=True)
            i += 5
        else:
            i += 1
    return bytes(out)


def tokens(data, start, end, window):
    """Greedy LZ77 over data[start:end] (no match crosses `end`): literals and (length, distance)."""
    heads, out, i = {}, [], start
    while i < end:
        best = (0, 0)
        for j in reversed(heads.get(data[i:i + 3], [])[-8:]):
            if i - j > window:
                continue
            length = 0
            while length < 257 and i + length < end and data[j + length] == data[i + length]:
                length += 1
            best = max(best, (length, -(i - j)))
        length, distance = best[0], -best[1]
        step = length if length >= 3 else 1
        out.append((length, distance) if length >= 3 else data[i])
        for k in range(i, i + step):
            heads.setdefault(data[k:k + 3], []).append(k)
        i += step
    return out


class Encoder:
    """One LZX stream. blocks: (type, size) pairs covering the data, type 1 verbatim, 2 aligned,
    3 uncompressed. CAB mode writes the E8 header and re-aligns after each 32 KiB frame; WIM mode
    writes the 1-bit block-size flag and always translates E8 against 12,000,000."""

    def __init__(self, window_bits=16, wim=False, e8_size=0):
        self.window_bits, self.wim = window_bits, wim
        self.e8_size = formats_dfir.LZX_WIM_E8_SIZE if wim else e8_size
        self.mains = 256 + 8 * formats_dfir.LZX_SLOTS[window_bits]
        self.used = set()  # Which coding paths the data exercised, for the tests to require.
        self.frame_ends = []  # Byte offsets of the stream at each frame boundary (CAB data blocks).

    def compress(self, data, blocks):
        size = len(data)
        plain = data
        if self.e8_size:
            for start in range(0, size, FRAME):
                plain = e8_translate(plain, start, min(start + FRAME, size), self.e8_size)
        bits = Bits()
        if not self.wim:
            bits.put(1, 1) if self.e8_size else bits.put(0, 1)
            if self.e8_size:
                bits.put(self.e8_size >> 16, 16)
                bits.put(self.e8_size & 0xFFFF, 16)
        main_prev, length_prev, repeats, pos = [0] * self.mains, [0] * 249, [1, 1, 1], 0
        for kind, block_size in blocks:
            self.used.add(f"block {kind}")
            bits.put(kind, 3)
            if self.wim:
                if block_size == FRAME:
                    bits.put(1, 1)
                else:
                    bits.put(0, 1)
                    bits.put(block_size >> 8 if self.window_bits >= 16 else block_size, 16)
                    if self.window_bits >= 16:
                        bits.put(block_size & 0xFF, 8)
            else:
                bits.put(block_size >> 8, 16)
                bits.put(block_size & 0xFF, 8)
            end = pos + block_size
            if kind == 3:
                bits.align(always=True)
                bits.out += struct.pack("<3I", *repeats)
                data_start = len(bits.out)
                bits.out += plain[pos:end] + bytes(block_size & 1)
                for boundary in range((pos // FRAME + 1) * FRAME, end, FRAME):  # Frames end mid-block.
                    self.frame_ends.append(data_start + boundary - pos)
                if end % FRAME == 0 and end < size:
                    self.frame_ends.append(len(bits.out))
                pos = end
                continue
            ops, start = [], pos
            while start < end:  # No match crosses a frame boundary.
                stop = min(end, (start // FRAME + 1) * FRAME)
                ops += tokens(plain, start, stop, 1 << self.window_bits)
                start = stop
            symbols = self._symbols(ops, repeats, kind)
            main_freq, length_freq, aligned_freq = [0] * self.mains, [0] * 249, [0] * 8
            for main, length, _extra, aligned in symbols:
                main_freq[main] += 1
                if length is not None:
                    length_freq[length] += 1
                if aligned is not None:
                    aligned_freq[aligned] += 1
            main_lengths = huffman_lengths(main_freq, 16)
            length_lengths = huffman_lengths(length_freq, 16) if any(length_freq) else [0] * 249
            if kind == 2:
                aligned_lengths = huffman_lengths(aligned_freq, 7)
                for length in aligned_lengths:
                    bits.put(length, 3)
                aligned_codes = canonical(aligned_lengths)
            write_lengths(bits, main_lengths, main_prev, 0, 256)
            write_lengths(bits, main_lengths, main_prev, 256, self.mains)
            write_lengths(bits, length_lengths, length_prev, 0, 249)
            main_codes, length_codes = canonical(main_lengths), canonical(length_lengths)
            for (main, length, extra, aligned), op in zip(symbols, ops):
                bits.code(main_codes, main)
                if length is not None:
                    bits.code(length_codes, length)
                if extra is not None:
                    bits.put(*extra)
                if aligned is not None:
                    bits.code(aligned_codes, aligned)
                pos += op[0] if isinstance(op, tuple) else 1
                if not self.wim and pos % FRAME == 0 and pos < size:
                    bits.align()
                    self.frame_ends.append(len(bits.out))
        bits.align()
        return bytes(bits.out)

    def _symbols(self, ops, repeats, kind):
        out = []
        for op in ops:
            if not isinstance(op, tuple):
                out.append((op, None, None, None))
                continue
            length, distance = op
            extra = aligned = None
            if distance in repeats:
                slot = repeats.index(distance)
                repeats[0], repeats[slot] = repeats[slot], repeats[0]
                self.used.add(f"repeat R{slot}")
            else:
                formatted = distance + 2
                slot = max(s for s in range(len(BASE)) if BASE[s] <= formatted)
                value, width = formatted - BASE[slot], EXTRA[slot]
                if kind == 2 and width >= 3:
                    extra, aligned = (value >> 3, width - 3), value & 7
                    self.used.add("aligned offset")
                elif width:
                    extra = (value, width)
                repeats[:] = [distance, repeats[0], repeats[1]]
            header = min(length - 2, 7)
            if header == 7:
                self.used.add("length tree")
            out.append((256 + slot * 8 + header, length - 9 if header == 7 else None, extra, aligned))
        return out


def sample(size, seed=7):
    """Text, x86-looking CALLs, fields at repeating distances and incompressible runs."""
    rng, out = random.Random(seed), bytearray()
    words = [b"Huntress", b"forensics", b"metadata", b"cabinet", b"\r\n", b"registry", b"prefetch"]
    while len(out) < size:
        choice = rng.random()
        if choice < 0.35:
            out += b" ".join(rng.choice(words) for _ in range(rng.randint(3, 12)))
        elif choice < 0.55:
            out += b"\xe8" + rng.randint(-5000, 5000).to_bytes(4, "little", signed=True) + b"\x90\x55\x89\xe5"
        elif choice < 0.8:
            record = bytes(rng.randrange(4)) * 2 + rng.choice(words)
            out += (record + struct.pack("<H", rng.randrange(65536))) * rng.randint(2, 6)
        else:
            out += bytes(rng.randrange(256) for _ in range(rng.randint(8, 64)))
    return bytes(out[:size])


def cab(folders, files, reserve=False, plan=None):
    """folders: (method, window_bits) per folder; files: (name, data, folder, date, time, attributes).
    Each folder holds its files back to back in 32 KiB data blocks; plan: LZX blocks (type, size)."""
    contents = [b"".join(data for _, data, folder, *_ in files if folder == index) for index in range(len(folders))]
    blocks = []
    for (method, window), content in zip(folders, contents):
        frames = [content[at:at + FRAME] for at in range(0, len(content), FRAME)] or [b""]
        if method == 0:
            blocks.append([(frame, len(frame)) for frame in frames])
        elif method == 1:
            payloads, previous = [], b""
            for frame in frames:
                deflate = zlib.compressobj(9, zlib.DEFLATED, -15, zdict=previous) if previous else \
                    zlib.compressobj(9, zlib.DEFLATED, -15)
                payloads.append((b"CK" + deflate.compress(frame) + deflate.flush(), len(frame)))
                previous = frame
            blocks.append(payloads)
        else:
            encoder = Encoder(window, e8_size=len(content))
            blocks_plan = plan or [(2, min(len(content), 20000))]
            if not plan and len(content) > 20000:
                blocks_plan += [(3, 1001)] + [(1, len(content) - 21001)]
            stream = encoder.compress(content, blocks_plan)
            cuts = [0] + encoder.frame_ends + [len(stream)]
            blocks.append([(stream[a:b], len(frame)) for a, b, frame in zip(cuts, cuts[1:], frames)])
    header_reserve, folder_reserve, data_reserve = (4, 2, 1) if reserve else (0, 0, 0)
    head = 36 + (4 + header_reserve if reserve else 0)
    files_at = head + len(folders) * (8 + folder_reserve)
    file_table = b"".join(struct.pack("<IIHHHH", len(data), sum(len(d) for _, d, g, *_ in files[:i] if g == folder),
                                      folder, date, time, attributes) + name.encode() + b"\0"
                          for i, (name, data, folder, date, time, attributes) in enumerate(files))
    at = files_at + len(file_table)
    folder_table, data_area = b"", b""
    for (method, window), folder_blocks in zip(folders, blocks):
        kind = method | (window << 8 if method == 3 else 0)
        folder_table += struct.pack("<IHH", at + len(data_area), len(folder_blocks), kind) + bytes(folder_reserve)
        for payload, unpacked in folder_blocks:
            data_area += struct.pack("<IHH", 0, len(payload), unpacked) + bytes(data_reserve) + payload
    total = at + len(data_area)
    header = b"MSCF" + struct.pack("<IIIII", 0, total, 0, files_at, 0) + struct.pack(
        "<BBHHHHH", 3, 1, len(folders), len(files), 4 if reserve else 0, 0x1234, 0)
    if reserve:
        header += struct.pack("<HBB", header_reserve, folder_reserve, data_reserve) + bytes(header_reserve)
    return header + folder_table + file_table + data_area


def filetime(seconds):
    return (seconds + 11644473600) * 10_000_000


def dentry(name, attributes, written, digest=bytes(20)):
    encoded = name.encode("utf-16-le")
    body = struct.pack("<QIiQQQQQQ", 0, attributes, -1, 0, 0, 0, written, written, written) + digest
    body += bytes(12) + struct.pack("<HHH", 0, 0, len(encoded)) + encoded + (b"\0\0" if encoded else b"")
    body = struct.pack("<Q", len(body)) + body[8:]
    return body + bytes(-len(body) % 8)


def wim(tree, name="Evidence image", chunk=FRAME):
    """A one-image LZX WIM. tree: {name: bytes (a file) or dict (a directory)}. File data is stored
    raw; the metadata resource (security data, then the directory entries) is LZX-compressed in
    chunks behind a chunk table, as DISM and wimlib write it."""
    meta, blobs, queue = bytearray(struct.pack("<II", 8, 0)), [], []
    root = len(meta)
    meta += dentry("", 0x10, filetime(1_790_000_000))
    queue.append((root, tree))
    stamp = 1_790_000_000
    while queue:
        parent, children = queue.pop(0)
        struct.pack_into("<Q", meta, parent + 16, len(meta))
        for child, value in children.items():
            stamp += 3600
            if isinstance(value, dict):
                queue.append((len(meta), value))
                meta += dentry(child, 0x10, filetime(stamp))
            else:
                digest = hashlib.sha1(value).digest()
                blobs.append((value, digest))
                meta += dentry(child, 0x20, filetime(stamp), digest)
        meta += bytes(8)
    meta = bytes(meta)
    chunks = []
    for at in range(0, len(meta), chunk):
        piece = meta[at:at + chunk]
        packed = Encoder(15, wim=True).compress(piece, [(2, len(piece))] if len(piece) != FRAME else [(1, FRAME)])
        chunks.append(packed if len(packed) < len(piece) else piece)
    starts, offset = [], 0
    for piece in chunks[:-1]:
        offset += len(piece)
        starts.append(offset)
    resource = b"".join(struct.pack("<I", start) for start in starts) + b"".join(chunks)
    xml = f'﻿<WIM><IMAGE INDEX="1"><NAME>{name}</NAME></IMAGE></WIM>'.encode("utf-16-le")
    body, entries = bytearray(), b""
    for data, digest in blobs:
        entries += len(data).to_bytes(7, "little") + b"\0" + struct.pack("<QQHI", 0xD0 + len(body), len(data), 1, 1) + digest
        body += data
    meta_at = 0xD0 + len(body)
    entries += len(resource).to_bytes(7, "little") + b"\x06" + struct.pack("<QQHI", meta_at, len(meta), 1, 1)
    entries += hashlib.sha1(meta).digest()
    body += resource
    table_at, xml_at = 0xD0 + len(body), 0xD0 + len(body) + len(entries)
    header = bytearray(0xD0)
    header[:8] = b"MSWIM\0\0\0"
    struct.pack_into("<IIII", header, 8, 0xD0, 0x10D00, 2 | 0x40000, chunk)
    struct.pack_into("<HHI", header, 40, 1, 1, 1)
    header[0x30:0x37] = len(entries).to_bytes(7, "little")
    struct.pack_into("<QQ", header, 0x38, table_at, len(entries))
    header[0x48:0x4F] = len(xml).to_bytes(7, "little")
    struct.pack_into("<QQ", header, 0x50, xml_at, len(xml))
    return bytes(header) + bytes(body) + entries + xml


def fields_of(data, label):
    return next(fields for name, fields in dfir_formats(data) if name == label)


FILES = [("readme.txt", b"Read me first.\r\n" * 40, 0, 0x5B5A, 0x6C2F, 0x20),
         ("tool.exe", sample(70000), 1, 0x5B5A, 0x7000, 0x21),
         ("notes/log.txt", sample(5000, seed=3), 2, 0x5B59, 0x0000, 0x22)]


class LzxCodecTests(unittest.TestCase):
    def test_cab_stream_over_three_frames(self):
        data = sample(80000)
        encoder = Encoder(16, e8_size=len(data))
        stream = encoder.compress(data, [(2, 30000), (3, 4097), (1, 45903)])
        self.assertEqual(formats_dfir.lzx(stream, len(data), 16), data)
        self.assertEqual(len(encoder.frame_ends), 2)  # Frame boundaries inside the aligned and verbatim blocks.
        self.assertLessEqual({"block 1", "block 2", "block 3", "repeat R0", "repeat R1", "repeat R2",
                              "aligned offset", "length tree"}, encoder.used)

    def test_window_sizes_and_no_e8(self):
        data = sample(40000, seed=11)
        for window in (15, 17, 21):
            with self.subTest(window=window):
                stream = Encoder(window).compress(data, [(1, 25000), (2, 15000)])
                self.assertEqual(formats_dfir.lzx(stream, len(data), window), data)

    def test_wim_chunk(self):
        data = sample(FRAME, seed=5)
        self.assertEqual(formats_dfir.lzx(Encoder(15, wim=True).compress(data, [(1, FRAME)]), FRAME, 15, wim=True), data)
        short = data[:9001]
        packed = Encoder(15, wim=True).compress(short, [(2, 5000), (3, 4001)])
        self.assertEqual(formats_dfir.lzx(packed, len(short), 15, wim=True), short)

    def test_damaged_streams_raise_value_error(self):
        data = sample(20000)
        stream = Encoder(16).compress(data, [(1, len(data))])
        for broken, window in ((stream[:len(stream) // 3], 16), (b"\xff" * 64, 16), (stream, 14)):
            with self.subTest(size=len(broken), window=window):
                with self.assertRaises(ValueError):
                    formats_dfir.lzx(broken, len(data), window)


class CabTests(unittest.TestCase):
    def test_folders_stored_mszip_and_lzx(self):
        f = fields_of(cab([(0, 0), (1, 0), (3, 16)], FILES), "cab")
        self.assertEqual(f["names"], ["readme.txt", "tool.exe", "notes/log.txt"])
        self.assertEqual((f["compression_types"], f["compression"], f["lzx_window_bits"]), (["none", "mszip", "lzx"], "none", 16))
        self.assertEqual(f["file_sizes"], [640, 70000, 5000])
        self.assertEqual(f["modified_times"], ["2025-10-26 13:33:30", "2025-10-26 14:00:00", "2025-10-25 00:00:00"])
        self.assertEqual(f["file_attributes"], [["archive"], ["readonly", "archive"], ["hidden", "archive"]])
        self.assertEqual(f["member_sha256"], [hashlib.sha256(data).hexdigest() for _, data, *_ in FILES])
        self.assertNotIn("folders_unreadable", f)

    def test_one_lzx_folder_with_reserved_areas(self):
        files = [(name, data, 0, date, time, attributes) for name, data, _, date, time, attributes in FILES]
        plan = [(2, 30000), (3, 4097), (1, 75640 - 34097)]  # The uncompressed block spans a frame boundary.
        f = fields_of(cab([(3, 17)], files, reserve=True, plan=plan), "cab")
        self.assertEqual((f["compression"], f["data_reserve_size"], f["data_block_count"]), ("lzx", 1, 3))
        self.assertEqual(f["member_sha256"], [hashlib.sha256(data).hexdigest() for _, data, *_ in FILES])

    def test_the_first_untimed_answer_is_the_right_field(self):
        data = cab([(0, 0), (1, 0), (3, 16)], FILES)
        for prop, expected in CAB_PROPERTIES:
            with self.subTest(prop=prop):
                self.assertIn(expected, first_untimed_answer(prop, data))

    def test_a_damaged_folder_keeps_the_file_list(self):
        data = bytearray(cab([(0, 0), (3, 16)], [FILES[0], (FILES[1][0], FILES[1][1], 1, *FILES[1][3:])]))
        lzx_start = struct.unpack_from("<I", data, 36 + 8)[0] + 8  # The second folder's first payload.
        data[lzx_start:lzx_start + 32] = b"\xff" * 32
        f = fields_of(bytes(data), "cab")
        self.assertEqual(f["names"], ["readme.txt", "tool.exe"])
        self.assertEqual(f["member_sha256"][0], hashlib.sha256(FILES[0][1]).hexdigest())
        self.assertIsNone(f["member_sha256"][1])
        self.assertIn("folders_unreadable", f)


# Likely property spellings for the new fields -> the value autoprop must send first (untimed).
CAB_PROPERTIES = (("cab.file_names", "readme.txt"), ("cab.member_names", "readme.txt"),
                  ("cab.compression_type", "none"), ("cab.uncompressed_size", "75640"),
                  ("cab.file_timestamps", "2025-10-26 13:33:30"), ("cab.lzx_window_bits", "16"),
                  ("cab.file_sha256", hashlib.sha256(FILES[0][1]).hexdigest()))
WIM_PROPERTIES = (("wim.file_count", "302"), ("wim.image_file_count", "302"), ("wim.directory_count", "6"),
                  ("wim.dir_count", "6"), ("wim.newest_file", "/Windows/System32/config/SAM"),
                  ("wim.compression", "lzx"))


class WimTests(unittest.TestCase):
    TREE = {"Users": {"ilse": {"Desktop": {f"note{i:03}.txt": f"note {i}".encode() for i in range(300)}}},
            "Windows": {"System32": {"config": {"SAM": b"regf" + bytes(60)}}},
            "boot.ini": b"[boot loader]\r\n"}

    def test_image_tree_from_lzx_metadata(self):
        data = wim(self.TREE)
        f = fields_of(data, "wim")
        self.assertEqual((f["compression"], f["image_names"]), ("lzx", ["Evidence image"]))
        self.assertEqual(f["image_file_count"], 302)
        self.assertEqual(f["image_directory_count"], 6)
        self.assertIn("/Windows/System32/config/SAM", f["image_file_paths"])
        self.assertIn("/Users/ilse/Desktop/note299.txt", f["image_file_paths"])
        self.assertEqual(f["image_file_sizes"][f["image_file_paths"].index("/boot.ini")], 15)
        self.assertEqual(f["image_latest_write_path"], "/Windows/System32/config/SAM")  # Written last.
        self.assertNotIn("image_tree_damaged", f)

    def test_the_first_untimed_answer_is_the_right_field(self):
        data = wim(self.TREE)
        for prop, expected in WIM_PROPERTIES:
            with self.subTest(prop=prop):
                self.assertIn(expected, first_untimed_answer(prop, data))
        self.assertIn("note000.txt", first_untimed_answer("wim.file_names", data))
        self.assertNotIn("/", first_untimed_answer("wim.file_names", data))

    def test_a_damaged_metadata_resource_keeps_the_header(self):
        data = bytearray(wim(self.TREE))
        table_at = struct.unpack_from("<Q", data, 0x38)[0]
        meta_at = struct.unpack_from("<Q", data, table_at + 50 * 302 + 8)[0]  # After the 302 files.
        data[meta_at + 8:meta_at + 400] = b"\xa5" * 392
        f = fields_of(bytes(data), "wim")
        self.assertEqual(f["image_names"], ["Evidence image"])
        self.assertIn("image_tree_damaged", f)


if __name__ == "__main__":
    unittest.main()
