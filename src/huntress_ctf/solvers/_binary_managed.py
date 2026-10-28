"""Static CLR metadata and Java classfile/manifest readers. Nothing is loaded."""
from io import BytesIO
import zipfile

from ..containers import read_member
from ._binary_formats import PE, ParseError, Reader


def clr_version(image: PE) -> str:
    address, size = image.directory(14)
    if not address or size < 16:
        raise ParseError("No supported CLR header")
    header = image.rva(address, 16)
    metadata, size = image.unpack("II", header + 8)
    root = image.rva(metadata, size)
    if size < 16 or image.take(root, 4) != b"BSJB":
        raise ParseError("Invalid CLR metadata root")
    length, = image.unpack("I", root + 12)
    if length > size - 16:
        raise ParseError("CLR version exceeds metadata")
    return image.take(root + 16, length).rstrip(b"\0").decode("utf-8")


def cli_runtime(image: PE) -> str:
    """CLI header MajorRuntimeVersion.MinorRuntimeVersion (u16 at +4, +6), e.g. "2.5"."""
    address, size = image.directory(14)
    if not address or size < 16:
        raise ParseError("No supported CLR header")
    header = image.rva(address, 16)
    major, minor = image.unpack("HH", header + 4)
    return f"{major}.{minor}"


class JavaClass(Reader):
    def __init__(self, data: bytes):
        super().__init__(data, ">")
        if self.take(0, 4) != b"\xca\xfe\xba\xbe":
            raise ParseError("Invalid classfile magic")
        count, = self.unpack("H", 8)
        if not count:
            raise ParseError("Invalid classfile constant pool")
        self.utf8 = []
        constants, class_names = {}, {}
        offset, index = 10, 1
        widths = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4,
                  12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}
        while index < count:
            tag = self.take(offset, 1)[0]
            offset += 1
            if tag == 1:
                length, = self.unpack("H", offset)
                offset += 2
                raw = self.take(offset, length).replace(b"\xc0\x80", b"\0")
                value = raw.decode("utf-8", "surrogatepass").encode("utf-16-le", "surrogatepass").decode("utf-16-le")
                constants[index] = value
                self.utf8.append((offset, value))
                offset += length
            elif tag in widths:
                self.take(offset, widths[tag])
                if tag == 7:
                    class_names[index], = self.unpack("H", offset)
                offset += widths[tag]
                if tag in (5, 6):
                    index += 1
                    if index >= count:
                        raise ParseError("Invalid two-slot constant")
            else:
                raise ParseError("Unknown classfile constant tag")
            index += 1
        self.access_flags, this_class, _, interfaces = self.unpack("HHHH", offset)
        # Day 28: "resolve its this_class constant-pool name" (CONSTANT_Class -> UTF-8, internal form).
        self.this_class = constants.get(class_names.get(this_class))
        offset += 8
        self.take(offset, interfaces * 2)
        offset += interfaces * 2

        def attributes(at, count):
            for _ in range(count):
                name, length = self.unpack("HI", at)
                if name not in constants:
                    raise ParseError("Attribute lacks UTF-8 name")
                self.take(at + 6, length)
                at += 6 + length
            return at

        def members(at):
            count, = self.unpack("H", at)
            at += 2
            names = []
            for _ in range(count):
                flags, name, descriptor, attrs = self.unpack("HHHH", at)
                if name not in constants or descriptor not in constants:
                    raise ParseError("Invalid classfile member name/descriptor")
                names.append(constants[name])
                at = attributes(at + 8, attrs)
            return at, names
        offset, _ = members(offset)
        offset, self.methods = members(offset)
        count, = self.unpack("H", offset)
        offset = attributes(offset + 2, count)
        if offset != len(data):
            raise ParseError("Unexpected trailing classfile bytes")


class Jar:
    def __init__(self, data: bytes):
        self.archive = zipfile.ZipFile(BytesIO(data))
        self.infos = self.archive.infolist()
        if len(self.infos) > 65536:
            raise ParseError("Too many JAR entries")
        self._main = None
        self._main_name = None

    def read(self, name: str) -> bytes:
        infos = [i for i in self.infos if i.filename == name and not i.is_dir()]
        if len(infos) != 1 or infos[0].file_size > 16 * 1024 * 1024:
            raise ParseError("Missing, ambiguous or oversized JAR member")
        return read_member(self.archive, infos[0])

    @property
    def main(self) -> JavaClass:
        if self._main is None:
            text = self.read("META-INF/MANIFEST.MF").decode("utf-8")
            unfolded = []
            for line in text.splitlines():
                if not line:
                    break  # Only the manifest main section selects the class.
                if line.startswith(" ") and unfolded:
                    unfolded[-1] += line[1:]
                else:
                    unfolded.append(line)
            names = [line.split(":", 1)[1].strip() for line in unfolded if line.casefold().startswith("main-class:")]
            if len(names) != 1 or not names[0] or "/" in names[0] or "\\" in names[0]:
                raise ParseError("No unique manifest Main-Class")
            self._main_name = names[0].replace(".", "/") + ".class"
            self._main = JavaClass(self.read(self._main_name))
        return self._main

    def classes(self):
        """The main class, then every other classfile in central-directory order.

        "Parse every JAR classfile constant pool": day 24's Scala builds keep the HCFG
        constant in the companion object (Day24Corrected000$.class), not the main class.
        """
        yield self.main
        for info in self.infos:
            if info.is_dir() or not info.filename.endswith(".class") or info.filename == self._main_name:
                continue
            if info.file_size > 16 * 1024 * 1024:
                raise ParseError("Oversized JAR classfile")
            try:
                yield JavaClass(read_member(self.archive, info))
            except ParseError:
                continue
