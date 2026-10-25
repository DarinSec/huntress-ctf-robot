"""Synthetic fixture for the Script Analysis adapter: an embedded HUNTRESS_ANALYSIS descriptor.

The specimen carries a base64-encoded key=value descriptor, exactly the shape the real
Script-analysis samples use. No archive extraction (members passed directly).
"""

import base64
import unittest
from pathlib import Path

from huntress_ctf.containers import Member
from huntress_ctf.solvers.base import SolveContext
from huntress_ctf.solvers.script import ScriptSolver

DESCRIPTOR = (
    "v=3|language=php|role=stager|verdict=suspicious|attack=T1105|adapter=runtime_loader|"
    "host_profile=standalone|obfuscation_profile=base64|stage_profile=two_stage_download_execute|"
    "next_language=jscript|stage_count=2|steps=acquire_remote,dispatch_process|"
    "campaign_id=TEST-abc123|url=https://test-abc123.example.invalid/stage|file_path=/tmp/x.stage"
)


def specimen(campaign: str = "TEST-abc123") -> bytes:
    blob = base64.b64encode(DESCRIPTOR.replace("TEST-abc123", campaign).encode()).decode()
    return (f"<?php\n// HUNTRESS_ANALYSIS_V1:B64-{blob}\ndeclare(strict_types=1);\n").encode()


def context(member_name, questions):
    return SolveContext(
        challenge_id="script-analysis-day-21-x",
        challenge={"lane": "script-analysis", "questions": questions},
        attempt={"attempt_id": "test"},
        artifact=b"",
        artifact_path=Path("unused"),
        answer_ids=tuple(q["id"] for q in questions),
        members=(Member(member_name, specimen()),),
    )


class ScriptSolverTest(unittest.TestCase):
    def test_descriptor_fields(self):
        name = "polyglot-php-stager.php"
        art = f"evidence.zip -> {name}"
        questions = [
            {"id": "polyglot-php-stager-campaign", "question": "campaign?", "artifact": art,
             "answer_format": {"kind": "exact_text"}},
            {"id": "polyglot-php-stager-url", "question": "url?", "artifact": art,
             "answer_format": {"kind": "exact_text"}},
            {"id": "polyglot-php-stager-role", "question": "role?", "artifact": art,
             "answer_format": {"kind": "enum"}},
        ]
        got = {c.answer_id: c.answer for c in ScriptSolver().solve(context(name, questions))}
        self.assertEqual(got["polyglot-php-stager-campaign"], "TEST-abc123")
        self.assertEqual(got["polyglot-php-stager-url"], "https://test-abc123.example.invalid/stage")
        self.assertEqual(got["polyglot-php-stager-role"], "stager")

    def test_mastery_sets_in_one_bundle_keep_their_own_specimens(self):
        # The bundle's inner evidence zips are already unpacked: "evidence-02.zip/<name>".
        # Five sets share specimen names, so a base name alone would mix them up.
        name = "polyglot-php-stager.php"
        questions = [
            {"id": f"set{n}.polyglot-php-stager-campaign", "question": "campaign?",
             "artifact": f"evidence-0{n}.zip -> {name}", "answer_format": {"kind": "exact_text"}}
            for n in (1, 2)
        ]
        members = tuple(
            Member(f"bundle/evidence-0{n}.zip/specimens/{name}", specimen(f"TEST-set{n}")) for n in (1, 2)
        )
        ctx = context(name, questions)
        ctx = SolveContext(ctx.challenge_id, ctx.challenge, ctx.attempt, ctx.artifact,
                           ctx.artifact_path, ctx.answer_ids, members=members)
        got = {c.answer_id: c.answer for c in ScriptSolver().solve(ctx)}
        self.assertEqual(got, {"set1.polyglot-php-stager-campaign": "TEST-set1",
                               "set2.polyglot-php-stager-campaign": "TEST-set2"})

    def test_day23_layered_header_and_derived_fields(self):
        # LYR lists its layers in encoder order (b64, then rev, then hex); decoding undoes them last-to-first.
        layered = base64.b64encode(DESCRIPTOR.encode())[::-1].hex()
        name = "5f33a0.php"
        art = f"evidence.zip -> {name}"
        fields = ("campaign", "campaign-token", "url-host", "path-leaf", "steps", "obfuscation")
        questions = [{"id": f"polyglot-php-5f33a0-{f}", "question": "?", "artifact": art,
                      "answer_format": {"kind": "exact_text"}} for f in fields]
        ctx = context(name, questions)
        member = Member(name, f"<?php // HUNTRESS_ANALYSIS_V1:LYR-b64_rev_hex-{layered}\n".encode())
        ctx = SolveContext(ctx.challenge_id, ctx.challenge, ctx.attempt, ctx.artifact,
                           ctx.artifact_path, ctx.answer_ids, members=(member,))
        got = {c.answer_id.rsplit("5f33a0-", 1)[1]: c.answer for c in ScriptSolver().solve(ctx)}
        self.assertEqual(got["campaign"], "TEST-abc123")
        self.assertEqual(got["campaign-token"], "abc123")
        self.assertEqual(got["url-host"], "test-abc123.example.invalid")
        self.assertEqual(got["path-leaf"], "x.stage")
        self.assertEqual(got["obfuscation"], "base64")

    def test_layers_no_day_has_used_yet(self):
        import zlib
        from huntress_ctf.analysis import scriptrules
        packed = base64.b64encode(zlib.compress(DESCRIPTOR.encode())).decode()
        record = scriptrules.analysis_header(f"# HUNTRESS_ANALYSIS_V1:LYR-zlib_b64-{packed}\n")
        self.assertEqual((record["campaign_id"], record["_lyr"]), ("TEST-abc123", "zlib_b64"))
        # An unknown layer name is not guessed at: the header yields nothing rather than a wrong record.
        self.assertIsNone(scriptrules.analysis_header(f"# HUNTRESS_ANALYSIS_V1:LYR-mystery_b64-{packed}\n"))


RECORD = b"v=1|steps=acquire_remote,write_file|campaign_id=CAMP-ab12cd|url=https://stage.example.invalid/x"


def _cbc_encrypt(key, iv, plain):
    from huntress_ctf import ciphers
    pad = 16 - len(plain) % 16
    plain, keys, out, prior = plain + bytes([pad]) * pad, ciphers.expand_key(key), b"", iv
    for i in range(0, len(plain), 16):
        prior = ciphers.encrypt_block(keys, bytes(a ^ b for a, b in zip(plain[i:i + 16], prior)))
        out += prior
    return out


class AnticipatedScriptTest(unittest.TestCase):
    """Days 26+: RC4/AES with the key the script carries, obfuscators, layers and families no day used."""

    def test_rc4_and_aes_records_with_the_scripts_own_key(self):
        from huntress_ctf import ciphers
        from huntress_ctf.analysis import scripts
        key, iv = b"Sup3rS3cretKey!!", bytes(range(16))
        cases = {
            "rc4": '$key = "rc4-loader-key"\n$blob = "%s"\n' % base64.b64encode(ciphers.rc4(b"rc4-loader-key", RECORD)).decode(),
            "aes_cbc": 'KEY = b"%s"\ndata = "%s"\n' % (key.decode(), base64.b64encode(iv + _cbc_encrypt(key, iv, RECORD)).decode()),
            "aes_ctr": 'secret_key = "%s"\nnonce = "%s"\nmaterial = "%s"\n' % (
                base64.b64encode(key).decode(), iv.hex(), base64.b64encode(ciphers.ctr(key, iv, RECORD)).decode()),
        }
        for name, text in cases.items():
            found = scripts.recover(text)
            self.assertEqual((found["plaintext"].encode(), found["chain"].split("|")[1]), (RECORD, name))
        # A declared AES codec may name its key array anything.
        declared = 'CODEC = "base64|aes_cbc"\n$k = [byte[]](%s)\n$v = [byte[]](%s)\nMATERIAL = "%s"\n' % (
            ",".join(map(str, key)), ",".join(map(str, iv)), base64.b64encode(_cbc_encrypt(key, iv, RECORD)).decode())
        self.assertEqual(scripts.recover(declared)["plaintext"].encode(), RECORD)

    def test_wrong_key_and_xor_days_unchanged(self):
        from huntress_ctf import ciphers
        from huntress_ctf.analysis import scripts
        wrong = '$key = "not-the-key"\n$blob = "%s"\n' % base64.b64encode(ciphers.rc4(b"rc4-loader-key", RECORD)).decode()
        self.assertIsNone(scripts.recover(wrong))
        xor = 'MATERIAL = "%s"\nCODEC = "hex_pairs|xor_5a"\n' % bytes(b ^ 0x5A for b in RECORD).hex()
        self.assertEqual(scripts.recover(xor)["chain"], "hex_pairs|single_byte_xor|5a")
        self.assertEqual(scripts.harvest_secrets('private_key = "abcd1234"')[0], (b"abcd1234", None))

    def test_deobfuscators(self):
        from huntress_ctf.analysis.deobfuscate import deobfuscate, unpack_packer
        self.assertIn('"Hi"', deobfuscate("var a = String.fromCharCode(72, 0x69);"))
        self.assertIn('"Hi"', deobfuscate("$a = [char]72+[char]105"))
        self.assertIn('"Hi"', deobfuscate("$a = -join [char[]](72,105)"))
        self.assertIn('"Hi"', deobfuscate('a = Chr(72) & Chr(105)'))
        self.assertIn('"Hi"', deobfuscate("a = bytes([72, 105]).decode()"))
        self.assertIn("'ab'", deobfuscate('$a = ("{1}{0}" -f \'b\',\'a\')'))
        self.assertIn("IEX", deobfuscate("I`E`X $x"))
        self.assertIn("echo ell", deobfuscate("set v=hello\necho %v:~1,3%\n"))
        packed = "eval(function(p,a,c,k,e,d){}('0 1=\\'2\\';',3,3,'var|x|hidden'.split('|'),0,{}))"
        self.assertEqual(unpack_packer(packed), "var x='hidden';")
        encoded = base64.b64encode("Write-Host secret".encode("utf-16-le")).decode()
        self.assertIn("Write-Host secret", deobfuscate(f"powershell -enc {encoded}"))
        self.assertEqual(deobfuscate("plain text"), "plain text")

    def test_obfuscated_header_and_unknown_family_answer(self):
        # A family no day used yet (lua), whose HUNTRESS header is built with string.char codes.
        header = f"HUNTRESS_ANALYSIS_V1:B64-{base64.b64encode(DESCRIPTOR.encode()).decode()}"
        name = "5f33a0.js"
        text = f"var h = String.fromCharCode({','.join(str(ord(c)) for c in header)});\n"
        art = f"evidence.zip -> {name}"
        questions = [{"id": f"lua-5f33a0-{f}", "question": "?", "artifact": art,
                      "answer_format": {"kind": "exact_text"}} for f in ("campaign", "campaign-token", "url")]
        ctx = context(name, questions)
        ctx = SolveContext(ctx.challenge_id, ctx.challenge, ctx.attempt, ctx.artifact,
                           ctx.artifact_path, ctx.answer_ids, members=(Member(name, text.encode()),))
        got = {c.answer_id.rsplit("5f33a0-", 1)[1]: c.answer for c in ScriptSolver().solve(ctx)}
        self.assertEqual(got, {"campaign": "TEST-abc123", "campaign-token": "abc123",
                               "url": "https://test-abc123.example.invalid/stage"})

    def test_more_layers(self):
        import bz2
        from huntress_ctf.analysis import scriptrules
        packed = base64.b64encode(bz2.compress(DESCRIPTOR.encode())).decode()
        self.assertEqual(scriptrules.analysis_header(f"# HUNTRESS_ANALYSIS_V1:LYR-bz2_b64-{packed}\n")["campaign_id"], "TEST-abc123")
        xored = base64.b64encode(bytes(b ^ 0x3C for b in DESCRIPTOR.encode())).decode()
        self.assertEqual(scriptrules.analysis_header(f"# HUNTRESS_ANALYSIS_V1:LYR-xor3c_b64-{xored}\n")["campaign_id"], "TEST-abc123")
        broken = base64.b64encode(b"\xfd7zXZ\x00broken").decode()  # lzma.LZMAError: no data, no crash
        self.assertIsNone(scriptrules.analysis_header(f"# HUNTRESS_ANALYSIS_V1:LYR-xz_b64-{broken}\n"))


if __name__ == "__main__":
    unittest.main()
