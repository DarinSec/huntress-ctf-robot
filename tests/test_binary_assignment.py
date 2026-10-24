"""Public-rule adapters tested with generated data, never event artifacts/answers."""
from dataclasses import replace
import base64
from io import BytesIO
import hashlib
import json
import struct
import unittest
from unittest.mock import patch
import zlib
import zipfile

from huntress_ctf.solvers.binary import BinarySolver
from huntress_ctf.solvers._binary_assignment import AssignedArchive, config_at
from huntress_ctf.solvers._binary_formats import Neko, ParseError, PE
from huntress_ctf.solvers._binary_managed import JavaClass, Jar, clr_version
from tests.test_binary import pe_fixture, elf_fixture, bundle, context


def config_record(values=None):
    payload = json.dumps(values or {"campaign": "synthetic-campaign", "domain": "example.invalid"}, separators=(",", ":")).encode()
    key = 37
    return struct.pack("<4sBBHI", b"HCFG", 1, key, len(payload), zlib.crc32(payload)) + bytes(b ^ key for b in payload)


def archive_context(files, prompts):
    qs = [{"id": name, "question": prompt, "artifact": "evidence.zip"} for name, prompt in prompts]
    ctx = context(bundle(**files), [])
    return replace(ctx, attempt={"questions": qs}, answer_ids=tuple(q["id"] for q in qs))


def java_fixture(name="Fixture", record=b"default"):
    strings = [name, "java/lang/Object", "<init>", "()V", "main", "([Ljava/lang/String;)V"]
    if record:
        strings.append(base64.b64encode(config_record() if record == b"default" else record).decode())
    constants = []
    indices = {}
    for text in strings:
        indices[text] = len(constants) + 1
        raw = text.encode()
        constants.append(b"\x01" + struct.pack(">H", len(raw)) + raw)
    this = len(constants) + 1
    constants.append(b"\x07" + struct.pack(">H", indices[name]))
    parent = len(constants) + 1
    constants.append(b"\x07" + struct.pack(">H", indices['java/lang/Object']))
    header = struct.pack(">IHHH", 0xcafebabe, 0, 52, len(constants) + 1)
    rest = struct.pack(">HHHHHH", 0x21, this, parent, 0, 0, 2)
    for flags, name, descriptor in ((1, '<init>', '()V'), (9, 'main', '([Ljava/lang/String;)V')):
        rest += struct.pack(">HHHH", flags, indices[name], indices[descriptor], 0)
    return header + b"".join(constants) + rest + b"\0\0"


class AssignedBinaryTests(unittest.TestCase):
    def test_managed_metadata_and_compound_format(self):
        data = bytearray(pe_fixture())
        struct.pack_into("<II", data, 0x98 + 112 + 14 * 8, 0x1700, 72)
        struct.pack_into("<IHHII", data, 0x900, 72, 2, 5, 0x1750, 40)
        version = b"v4.0.30319\0"
        struct.pack_into("<4sHHII", data, 0x950, b"BSJB", 1, 1, 0, len(version))
        data[0x960:0x960 + len(version)] = version
        self.assertEqual(clr_version(PE(bytes(data))), version.rstrip(b'\0').decode())
        prefix = "Use all unit-- members in ZIP central-directory order. "
        qs = [("unit_analysis_format", prefix + "Identify its combined executable-container and managed-runtime format classification."),
              ("unit_analysis_version", prefix + "Read the CLR metadata-root version string at BSJB + 16 using its declared length.")]
        got = {c.answer_id:c.answer for c in BinarySolver().solve(archive_context({'unit--managed.dll':bytes(data)},qs))}
        self.assertEqual(got, {'unit_analysis_format':'PE_CLI','unit_analysis_version':'v4.0.30319'})
        struct.pack_into("<I", data, 0x95c, 0xffff)
        self.assertEqual(BinarySolver().solve(archive_context({'unit--managed.dll':bytes(data)},qs)), [])

    def test_neko_bytecode_is_classified_by_magic(self):
        module = b"NEKO" + struct.pack("<iii", 3, 5, 128) + b"\0" * 32
        reader = Neko(module)
        self.assertEqual((reader.globals, reader.fields, reader.code_size), (3, 5, 128))
        prefix = "Use all unit-- members in ZIP central-directory order. "
        prompt = prefix + ("Classify final bytes by magic and parsed container: elf for ELF, pe for "
                           "native PE, pe_cli for PE with a valid CLR/CLI header and metadata root, "
                           "jar for a ZIP/JAR with classfiles, wasm for a valid WebAssembly module, or "
                           "neko_bytecode for NEKO bytecode. Submit exactly one listed lowercase token.")
        got = {c.answer_id: c.answer for c in BinarySolver().solve(
            archive_context({"unit--module.n": module}, [("unit_analysis_format", prompt)]))}
        self.assertEqual(got, {"unit_analysis_format": "neko_bytecode"})
        # A truncated NEKO header is rejected (fail safe), never misclassified.
        with self.assertRaises(ParseError):
            Neko(b"NEKO\x01")

    def test_jar_manifest_classfile_and_hcfg_constant(self):
        blob = BytesIO()
        with zipfile.ZipFile(blob,'w') as archive:
            archive.writestr('empty/',b'',compress_type=zipfile.ZIP_STORED)
            archive.writestr('META-INF/MANIFEST.MF',b'Manifest-Version: 1.0\r\nMain-Class: Fix\r\n ture\r\n\r\n',compress_type=zipfile.ZIP_DEFLATED)
            archive.writestr('Fixture.class',java_fixture(),compress_type=zipfile.ZIP_DEFLATED)
        jar=blob.getvalue()
        self.assertEqual(Jar(jar).main.methods,['<init>','main'])
        prefix='Use all unit-- members in ZIP central-directory order. '
        prompts=[('unit_analysis_format',prefix+'Identify its archive container from the final bytes.'),
                 ('unit_analysis_methods',prefix+'Submit method names in classfile method-table order.'),
                 ('unit_analysis_flags',prefix+'Submit the classfile access_flags unsigned u16 value.'),
                 ('unit_analysis_codecs',prefix+'Submit distinct ZIP compression methods including directory entries.'),
                 ('unit_analysis_campaign',prefix+'Parse the JAR and Main-Class classfile constant pool; Base64-decode each candidate HCFG record. Submit the exact string value of the decoded HCFG JSON object\'s top-level campaign property.')]
        got={c.answer_id:c.answer for c in BinarySolver().solve(archive_context({'unit--java.jar':jar},prompts))}
        self.assertEqual(got,{'unit_analysis_format':'JAR','unit_analysis_methods':'["<init>","main"]','unit_analysis_flags':'33','unit_analysis_codecs':'[0,8]','unit_analysis_campaign':'synthetic-campaign'})
        with self.assertRaises(ValueError): JavaClass(java_fixture()[:-1])

    def test_jar_config_in_companion_class_and_role_pair(self):
        # Day 24: Scala builds keep the HCFG constant in Main$ (not the Main-Class), and the
        # shared config questions name both role members and require equal configs.
        def jar(record):
            blob = BytesIO()
            with zipfile.ZipFile(blob, 'w') as archive:
                archive.writestr('META-INF/MANIFEST.MF', b'Manifest-Version: 1.0\r\nMain-Class: Main\r\n\r\n')
                archive.writestr('Main$.class', java_fixture('Main$', record))
                archive.writestr('Main.class', java_fixture('Main', None))
            return blob.getvalue()
        rule = ('Parse every JAR classfile constant pool; for Base64-alphabet UTF-8 constants of at least 80 characters, '
                'Base64-decode and accept the first CRC32-valid HCFG JSON record. Submit the exact string value of the '
                'decoded HCFG JSON object\'s top-level campaign property, without JSON quotes.')
        prompts = [('u_analysis_config_campaign', 'In evidence.zip, Decode both unit-- role members and require their config objects to be byte-for-byte equal before using the common value. ' + rule),
                   ('u_analysis_corrected_config_campaign', 'In evidence.zip, Use the unique unit-- member whose basename ends corrected.jar. ' + rule)]
        padded = config_record({'campaign': 'synthetic-campaign', 'padding': 'fixture' * 12})
        same = {'unit--sample-vulnerable.jar': jar(padded), 'unit--sample-corrected.jar': jar(padded)}
        got = {c.answer_id: c.answer for c in BinarySolver().solve(archive_context(same, prompts))}
        self.assertEqual(got, {'u_analysis_config_campaign': 'synthetic-campaign', 'u_analysis_corrected_config_campaign': 'synthetic-campaign'})
        other = config_record({'campaign': 'other-campaign', 'padding': 'fixture' * 12})
        differ = {'unit--sample-vulnerable.jar': jar(other), 'unit--sample-corrected.jar': jar(padded)}
        got = {c.answer_id: c.answer for c in BinarySolver().solve(archive_context(differ, prompts))}
        self.assertEqual(got, {'u_analysis_corrected_config_campaign': 'synthetic-campaign'})

    def test_base64_config_records_keep_carrier_offset(self):
        original=pe_fixture()
        record=config_record({'campaign':'synthetic-campaign','domain':'example.invalid','padding':'fixture'*12})
        data=original+b'\0'+base64.b64encode(record)+b'\0'
        prefix='Use all unit-- members in ZIP central-directory order. Test every non-overlapping Latin-1 run by Base64-decoding it. '
        prompts=[('unit_analysis_domain',prefix+'Submit the exact string value of the decoded HCFG JSON object\'s top-level domain property.'),
                 ('unit_analysis_offset',prefix+'Submit the base-10 byte offset of the winning encoded carrier for base64. HCFG header bytes are validated.')]
        got={c.answer_id:c.answer for c in BinarySolver().solve(archive_context({'unit--native.exe':data},prompts))}
        self.assertEqual(got,{'unit_analysis_domain':'example.invalid','unit_analysis_offset':str(len(original)+1)})

    def test_public_group_and_directory_order_choose_bytes(self):
        data = pe_fixture()
        prompts = [
            ("unit_artifact_sha256_2", "Use all unit-- members in ZIP central-directory order. Compute SHA-256 over the exact bytes of member 2."),
            ("unit_analysis_machine", "For the requested delivered binary, report the processor architecture identified by its executable header."),
        ]
        ctx = archive_context({"unit--z.txt": b"support", "unit--binary.exe": data}, prompts)
        got = {c.answer_id: c.answer for c in BinarySolver().solve(ctx)}
        self.assertEqual(got, {"unit_artifact_sha256_2": hashlib.sha256(data).hexdigest()})

    def test_generic_question_uses_only_its_siblings_public_selector(self):
        prompts = [
            ("u_artifact_sha256_1", "Use all sample-- members in ZIP central-directory order. Compute SHA-256 over the exact bytes of member 1."),
            ("u_analysis_machine", "For the requested delivered binary, report the processor architecture identified by its executable header."),
        ]
        ctx = archive_context({"sample--native.exe": pe_fixture(32), "other--native.exe": pe_fixture(64)}, prompts)
        got = {c.answer_id: c.answer for c in BinarySolver().solve(ctx)}
        self.assertEqual(got["u_analysis_machine"], "x86")

    def test_hcfg_fields_require_section_bounds_crc_and_json(self):
        data = bytearray(pe_fixture())
        section = 0x98 + 0xf0
        data[section:section + 8] = b".hcfg\0\0\0"
        record = config_record()
        data[0x200:0x200 + len(record)] = record
        public = "Use all unit-- members in ZIP central-directory order. Parse the native section table and use the HCFG record starting at byte 0 of the section named exactly .hcfg. "
        prompts = [
            ("unit_analysis_campaign", public + "Submit the exact string value of the decoded HCFG JSON object's top-level campaign property."),
            ("unit_analysis_key", public + "Render header byte 5 as 0x plus exactly two lowercase hexadecimal digits."),
            ("unit_analysis_version", public + "Submit unsigned HCFG byte 4 as a base-10 integer."),
        ]
        got = {c.answer_id: c.answer for c in BinarySolver().solve(archive_context({"unit--native.exe": bytes(data)}, prompts))}
        self.assertEqual(got, {"unit_analysis_campaign": "synthetic-campaign", "unit_analysis_key": "0x25", "unit_analysis_version": "1"})
        data[0x208] ^= 1
        self.assertEqual(BinarySolver().solve(archive_context({"unit--native.exe": bytes(data)}, prompts)), [])
        self.assertIsNone(config_at(b"HCFG" + b"\0" * 20, 0))

    def test_a_storage_no_rule_knows_is_discovered_when_unique(self):
        # A new day words its carrier in a way no rule matches: every carrier is searched and
        # only one CRC/JSON-valid record is accepted. Offsets/storage labels are not claimed.
        public = "Use all unit-- members in ZIP central-directory order. Locate the ZZ24 vault described in the lesson. "
        prompts = [("unit_analysis_campaign", public + "Submit the exact string value of the decoded HCFG JSON object's top-level campaign property."),
                   ("unit_analysis_version", public + "Submit unsigned HCFG byte 4 as a base-10 integer."),
                   ("unit_analysis_offset", public + "Submit the base-10 byte offset of the winning encoded carrier for base64. HCFG header bytes are validated.")]
        record = config_record()
        carriers = {
            "zlib": pe_fixture() + b"ZZ24" + zlib.compress(record),
            "xor": pe_fixture() + bytes(b ^ 0x5A for b in record),
            "utf16": pe_fixture() + base64.b64encode(config_record({"campaign": "synthetic-campaign", "pad": "x" * 80})).decode().encode("utf-16-le"),
            "nested zip": bundle(**{"inner.bin": record}),
        }
        for name, data in carriers.items():
            got = {c.answer_id: c.answer for c in BinarySolver().solve(archive_context({"unit--native.exe": data}, prompts))}
            self.assertEqual(got, {"unit_analysis_campaign": "synthetic-campaign", "unit_analysis_version": "1"}, name)
        two = pe_fixture() + record + zlib.compress(config_record({"campaign": "other", "domain": "x.invalid"}))
        self.assertEqual(BinarySolver().solve(archive_context({"unit--native.exe": two}, prompts)), [])

    def test_first_valid_literal_discards_bad_record(self):
        data = pe_fixture() + b"HCFG" + b"\xff" * 12 + config_record()
        prompt = "Use all unit-- members in ZIP central-directory order. Scan the specified member for literal HCFG magic and accept the first record whose bounds, CRC32, and decoded JSON validate. Submit the exact string value of the decoded HCFG JSON object's top-level domain property."
        got = BinarySolver().solve(archive_context({"unit--native.exe": data}, [("unit_analysis_domain", prompt)]))
        self.assertEqual([c.answer for c in got], ["example.invalid"])

    def test_static_elf_symbols_and_constant_return_are_exact(self):
        data = bytearray(elf_fixture())
        struct.pack_into("<I", data, 0x400 + 3 * 64 + 4, 2)  # SHT_SYMTAB.
        strings = b"\0recover_code\0"
        data[0x180:0x180 + len(strings)] = strings
        data[0x200 + 24:0x200 + 72] = b"\0" * 48
        struct.pack_into("<IBBHQQ", data, 0x200 + 48, 1, 0x12, 0, 1, 0x401000, 6)
        data[0x100:0x106] = b"\xb8\x2a\0\0\0\xc3"
        prefix = "Use all unit-- members in ZIP central-directory order. "
        prompts = [
            ("unit_analysis_symbols", prefix + "Submit every nonempty SHT_SYMTAB symbol name in symbol-table entry order as a JSON string array; preserve duplicates."),
            ("unit_analysis_immediate", prefix + "Look for a FUNC symbol named recover_code. Otherwise decode that symbol's exact bytes as mov eax, imm32 followed by ret and submit the immediate."),
            ("unit_analysis_disassembly", prefix + "Find the recover_code FUNC symbol and disassemble its bytes. Submit instructions as JSON."),
        ]
        got = {c.answer_id: c.answer for c in BinarySolver().solve(archive_context({"unit--native.elf": bytes(data)}, prompts))}
        self.assertEqual(got, {"unit_analysis_symbols": '["recover_code"]', "unit_analysis_immediate": "42", "unit_analysis_disassembly": '["mov eax, 0x2a","ret"]'})
        data[0x105] = 0x90
        got = {c.answer_id: c.answer for c in BinarySolver().solve(archive_context({"unit--native.elf": bytes(data)}, prompts))}
        self.assertEqual(list(got), ["unit_analysis_symbols"])

    def test_coff_long_names_keep_section_prefixes_and_skip_auxiliary(self):
        data = bytearray(pe_fixture())
        names = [b".rdata$_ZTI_SyntheticType", b"_ZN_SyntheticType_score"]
        strings = b"\0".join(names) + b"\0"
        table = len(data)
        struct.pack_into("<II", data, 0x8c, table, 3)
        for offset, auxiliary in ((4, 1), (4 + len(names[0]) + 1, 0)):
            data.extend(struct.pack("<8sIhHBB", b"\0" * 4 + struct.pack("<I", offset), 0, 1, 0, 3, auxiliary))
            if auxiliary:
                data.extend(b"\0" * 18)
        data.extend(struct.pack("<I", 4 + len(strings)) + strings)
        self.assertEqual([s.name for s in PE(bytes(data)).static_symbols], [x.decode() for x in names])
        prompt = "Use all unit-- members in ZIP central-directory order. Submit the first exact remaining name matching /ZTI.*SyntheticType/."
        got = BinarySolver().solve(archive_context({"unit--native.exe": bytes(data)}, [("unit_analysis_symbol", prompt)]))
        self.assertEqual([c.answer for c in got], [names[0].decode()])

    def test_conflicting_sibling_prefixes_are_not_guessed(self):
        ctx = archive_context({"a--x.exe": pe_fixture(), "b--x.exe": pe_fixture(32)}, [
            ("u_artifact_sha256_1", "Use all a-- members in ZIP central-directory order. Compute SHA-256 over the exact bytes of member 1."),
            ("u_analysis_machine", "Use all b-- members. What is the architecture?"),
        ])
        ctx=replace(ctx,attempt={**ctx.attempt,'artifacts':[{'filename':'evidence.zip'}]})
        self.assertEqual(BinarySolver().solve(ctx), [])

    def test_an_encoded_record_is_found_past_a_megabyte_of_lookalike_runs(self):
        # A record is read from byte 0 of its carrier and starts with b"HCFG", so a
        # candidate must begin with "48434647" (hex) or "SENG" (both Base64 alphabets).
        # Binary members are full of runs that only look like hex or Base64, and day 23's
        # Single Solve spent 369 ms decoding them in four scans, so they are now rejected
        # on those bytes. This pins the result of that shortcut, not its speed: with and
        # without it the record is found and noise alone answers nothing.
        import base64 as b64
        record = config_record({"campaign": "synthetic-campaign-0001", "domain": "example.invalid",
                                "url": "https://example.invalid/stage/one"})
        noise = (b"0123456789abcdefABCDEF" * 40 + b"\0") * 400  # Long hex/Base64-looking runs.
        archive = AssignedArchive.__new__(AssignedArchive)
        for codec, carrier in (("hex", record.hex().encode()), ("base64", b64.b64encode(record)),
                               ("base64url", b64.urlsafe_b64encode(record))):
            archive.records, archive.digests = {}, {}
            found = archive.encoded_config(noise + b"\0" + carrier + b"\0" + noise, codec, False)
            self.assertIsNotNone(found, codec)
            self.assertEqual(found.values["campaign"], "synthetic-campaign-0001", codec)
            archive.records = {}
            self.assertIsNone(archive.encoded_config(noise, codec, False), codec)  # Noise alone.
