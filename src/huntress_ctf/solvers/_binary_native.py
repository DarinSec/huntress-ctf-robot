"""One bounded x86-64 HCFG array-decoder pattern; no general disassembly.

The complete recognized function loads key at record+5, combines length bytes
7/6, and XORs bytes from record+12 into the output. Both loop branches and
runtime call destinations must map correctly. Addresses come from the parsed
ELF and the already CRC/JSON-validated record, never from an answer ID.
"""
import re
import struct

from ._binary_formats import ELF


def array_decoder_reference(image, offset: int) -> int | None:
    if not isinstance(image, ELF) or image.bits != 64 or image.arch != "x86_64" or image.endian != "<" or image.file_type != 2:
        return None
    if offset < 0 or offset + 12 > len(image.data):
        return None
    size = 12 + int.from_bytes(image.data[offset + 6:offset + 8], "little")
    mapped = [s for s in image.sections if s.flags & 2 and s.offset <= offset and offset + size <= s.offset + s.size]
    if len(mapped) != 1:
        return None
    record = mapped[0].address + offset - mapped[0].offset
    addresses = [s for s in image.sections if s.flags & 2 and s.address <= record and record + size <= s.address + s.size]
    if len(addresses) != 1:
        return None
    if not 0 <= record <= 0x7fffffff - 12:
        return None  # This encoding's absolute disp32 is sign-extended in 64-bit mode.
    code = [s for s in image.sections if s.kind == 1 and (s.flags & 6) == 6 and s.size]
    # push saved registers; stack slot; destination in rbx; key in r12b;
    # movabs rax, record; r13d = (record[7] << 8) | record[6].
    prefix = (bytes.fromhex("53 41 54 41 55 41 56 48 8d 64 24 f8 48 89 fb 44 8a 24 25")
              + struct.pack("<I", record + 5) + b"\x48\xb8" + struct.pack("<Q", record)
              + bytes.fromhex("44 0f b6 68 07 41 c1 e5 08 0f b6 40 06 41 09 c5 49 63 f5 48 89 df 31 d2 e8"))
    middle = bytes.fromhex("41 83 ed 01 45 85 ed 7c")
    init = bytes.fromhex("41 be ff ff ff ff 0f 1f 00")
    loop = bytes.fromhex("41 83 c6 01 48 89 df e8")
    xor = (bytes.fromhex("49 63 d6 48 8d 72 01 49 63 d6 8a 8a") + struct.pack("<I", record + 12)
           + bytes.fromhex("44 88 e2 30 ca 88 54 30 ff 45 39 f5 7f"))
    epilogue = bytes.fromhex("48 8d 64 24 08 41 5e 41 5d 41 5c 5b c3")
    pattern = re.compile(re.escape(prefix) + rb"(?P<allocate>.{4})" + re.escape(middle)
                         + rb"(?P<empty>.)" + re.escape(init) + re.escape(loop)
                         + rb"(?P<output>.{4})" + re.escape(xor) + rb"(?P<back>.)" + re.escape(epilogue), re.S)
    for section in code:
        for match in pattern.finditer(image.data, section.offset, section.offset + section.size):
            def va(at):
                return section.address + at - section.offset

            loop_start = match.start("output") - len(loop)
            exit_start = match.end("back")
            empty = match.end("empty") + struct.unpack("b", match["empty"])[0]
            back = match.end("back") + struct.unpack("b", match["back"])[0]
            if empty != exit_start or back != loop_start:
                continue
            valid_calls = True
            for name in ("allocate", "output"):
                destination = va(match.end(name)) + struct.unpack("<i", match[name])[0]
                targets = [s for s in code if s.address <= destination < s.address + s.size]
                if len(targets) != 1 or va(match.start()) <= destination < va(match.end()):
                    valid_calls = False
            # Ambiguous virtual mappings cannot establish instruction evidence.
            sources = [s for s in code if s.address <= va(match.start()) and va(match.end()) <= s.address + s.size]
            if valid_calls and len(sources) == 1:
                return match.start()
    return None
