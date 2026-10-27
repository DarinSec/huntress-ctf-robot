"""One bounded, integrity-checked member reader for Binary archive references."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from io import BytesIO
from pathlib import PurePosixPath
import os
import zipfile

from ..containers import LazyMembers, MAX_MEMBERS, ZIP_ERRORS, _external_unzip, passwords_from, unzip_tool
from ._binary_archive import aes_members
from ._binary_formats import ParseError
from .base import instruction_text
from .metadata import Files

MAX_BINARY_MEMBER_BYTES = 128 * 1024 * 1024
MAX_BINARY_ARCHIVE_BYTES = 256 * 1024 * 1024
WARM_WORKERS = max(1, min(4, os.cpu_count() or 1))  # External unzip processes at once.


class BinaryFiles(Files):
    def __init__(self, context):
        # Separate deliveries are already raw assigned bytes. Iterating LazyMembers
        # would eagerly unpack the primary delivery before this reader unpacks it.
        if isinstance(context.members, LazyMembers):
            context = replace(context, members=context.members._extra)
        self.context = context
        super().__init__(context)
        self.passwords = passwords_from(instruction_text(context))
        self.infos = {}
        self.indices = {}
        self.content = {}
        self.decrypted = {}
        self.warmed = {}

    def warm(self, blobs):
        """Unpack several AES deliveries at once with the external tool (a Mastery's ten evidence.zip:
        ~4.8 s one after another on 4 cores, ~1.5 s in parallel); read_index then checks and uses
        them as before. A delivery that fails here is simply unpacked again on first read."""
        todo = []
        for blob in dict.fromkeys(blobs):
            try:
                infos = self.directory(blob)
            except (ParseError, *ZIP_ERRORS):
                continue
            if id(blob) not in self.decrypted and any(x.compress_type == 99 and not x.is_dir() for x in infos):
                todo.append((blob, infos))
        if len(todo) < 2 or unzip_tool() is None:
            return

        def unpack(item):
            blob, infos = item
            return id(blob), _external_unzip(blob, infos, self.passwords, MAX_BINARY_ARCHIVE_BYTES)

        with ThreadPoolExecutor(max_workers=min(len(todo), WARM_WORKERS)) as pool:
            for key, verified in pool.map(unpack, todo):
                if verified:
                    self.warmed[key] = verified

    def directory(self, blob):
        key = id(blob)
        if key not in self.infos:
            with zipfile.ZipFile(BytesIO(blob)) as archive:
                infos = archive.infolist()
            if len(infos) > MAX_MEMBERS:
                raise ParseError("Too many assigned archive entries")
            if sum(x.file_size for x in infos) > MAX_BINARY_ARCHIVE_BYTES or any(x.file_size > MAX_BINARY_MEMBER_BYTES for x in infos):
                raise ParseError("Assigned archive exceeds Binary expansion bound")
            self.infos[key] = (blob, infos)  # Hold source bytes for identity caches.
            self.indices[key] = {id(info): index for index, info in enumerate(infos)}
        return self.infos[key][1]

    def _directory(self, blob):
        key = id(blob)
        if key not in self._directories:
            try:
                by_name = {}
                for info in self.directory(blob):
                    if not info.is_dir():
                        by_name.setdefault(info.filename, []).append(info)
                        by_name.setdefault("\0" + PurePosixPath(info.filename).name, []).append(info)
                self._directories[key] = (blob, by_name)
            except (zipfile.BadZipFile, ValueError, EOFError):
                self._directories[key] = None
        entry = self._directories[key]
        return entry[1] if entry else None

    def member(self, blob, name):
        directory = self._directory(blob)
        if directory is None:
            return None
        chosen = directory.get(name) or directory.get("\0" + name) or []
        if len(chosen) != 1:
            return None
        return self.read_index(blob, self.indices[id(blob)][id(chosen[0])])

    def read_index(self, blob, index):
        infos = self.directory(blob)
        key = (id(blob), index)
        if key in self.content:
            return self.content[key]
        info = infos[index]
        self.content[key] = None  # Failed reads must not repeatedly decrypt either.
        if info.is_dir():
            return None
        if info.compress_type == 99:
            archive_key = id(blob)
            if archive_key not in self.decrypted:
                self.decrypted[archive_key] = {}
                warmed = self.warmed.pop(archive_key, None)
                verified = warmed if warmed is not None else _external_unzip(
                    blob, infos, self.passwords, MAX_BINARY_ARCHIVE_BYTES)
                missing = {i for i, x in enumerate(infos) if x.compress_type == 99 and not x.is_dir()} - verified.keys()
                if missing:
                    verified.update(aes_members(blob, infos, self.passwords, MAX_BINARY_MEMBER_BYTES,
                                                MAX_BINARY_ARCHIVE_BYTES, missing))
                self.decrypted[archive_key] = verified
            data = self.decrypted[archive_key].get(index)
        else:
            data = None
            with zipfile.ZipFile(BytesIO(blob)) as archive:
                for password in (self.passwords if info.flag_bits & 1 else (None,)):
                    try:
                        with archive.open(info, pwd=password.encode() if password else None) as stream:
                            candidate = stream.read(MAX_BINARY_MEMBER_BYTES + 1)
                        if len(candidate) == info.file_size:
                            data = candidate  # ZipExtFile verified CRC at EOF.
                        break
                    except ZIP_ERRORS:
                        continue
        self.content[key] = data
        return data
