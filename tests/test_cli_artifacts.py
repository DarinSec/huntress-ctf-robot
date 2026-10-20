from contextlib import redirect_stdout, redirect_stderr
from io import BytesIO, StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

from huntress_ctf.artifacts import artifact_kind, artifact_summary, save_artifact
from huntress_ctf.cli import main
from huntress_ctf.client import GameMasterError


class CliTests(unittest.TestCase):
    def setUp(self):
        # A developer's real .env must never leak into tests.
        patcher = patch("huntress_ctf.cli.load_env")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_triage_is_offline_and_reports_members(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.zip"
            path.write_bytes(zipped("notes.txt"))
            with patch("huntress_ctf.cli.GameMasterClient") as client:
                with redirect_stdout(StringIO()) as stdout:
                    self.assertEqual(main(["triage", str(path)]), 0)
                client.assert_not_called()
        self.assertIn("Unpacked members", stdout.getvalue())
        self.assertIn("notes.txt", stdout.getvalue())

    def test_triage_time_reports_solver_costs_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            path.write_bytes(b"aGVsbG8=")
            with patch("huntress_ctf.cli.GameMasterClient") as client:
                with redirect_stdout(StringIO()) as stdout:
                    code = main(["triage", str(path), "--time", "--question", "Decode the Base64 text."])
                client.assert_not_called()
        self.assertEqual(code, 0)
        for expected in ("median_ms", "unpack", "base64-answer", "would_submit", "hello"):
            self.assertIn(expected, stdout.getvalue())

    def test_help_works_without_client_or_credentials(self):
        with patch("huntress_ctf.cli.GameMasterClient") as client:
            with redirect_stdout(StringIO()), self.assertRaises(SystemExit) as result:
                main(["--help"])
            self.assertEqual(result.exception.code, 0)
            client.assert_not_called()

    def test_invalid_timeouts_and_days_are_usage_errors(self):
        for argv in (["--timeout", "nan", "list"], ["--timeout", "0", "list"],
                     ["list", "--day", "32"]):
            with self.subTest(argv=argv), redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit) as result:
                    main(argv)
                self.assertEqual(result.exception.code, 2)

    def test_client_configuration_error_is_clean(self):
        with patch("huntress_ctf.cli.GameMasterClient", side_effect=GameMasterError("bad URL")):
            with redirect_stderr(StringIO()) as stderr:
                self.assertEqual(main(["list"]), 1)
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_manual_submission_exit_codes_and_redaction(self):
        for result, code in (
            ({"result": "CORRECT"}, 0), ({"result": "accepted", "remaining": 1}, 3),
            ({"result": "incorrect"}, 4), ({"result": "expired"}, 5),
            ({"result": "CORRECT", "status": "pending"}, 7),
            ({"result": "CORRECT", "status": "PENDING"}, 7),
            ({"result": "incorrect", "status": "completed"}, 1),
            ({"result": "CORRECT", "remaining": 1}, 1),
            ({"result": "unknown"}, 1),
        ):
            with self.subTest(result=result):
                client = Mock(token="secret-token")
                client.submit.return_value = {**result, "debug": "secret-token", "token": "hidden"}
                with patch("huntress_ctf.cli.GameMasterClient", return_value=client):
                    with redirect_stdout(StringIO()) as stdout, redirect_stderr(StringIO()):
                        self.assertEqual(main(["submit", "c", "a", "value"]), code)
                    self.assertNotIn("secret-token", stdout.getvalue())
                    self.assertNotIn('"hidden"', stdout.getvalue())


class ArtifactTests(unittest.TestCase):
    def test_variant_files_are_preserved_and_reserved_ids_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            first, digest = save_artifact(b"one", "../CON", Path(directory))
            second, _ = save_artifact(b"two", "../CON", Path(directory))
            same, _ = save_artifact(b"one", "../CON", Path(directory))
            self.assertEqual(first, same)
            self.assertNotEqual(first, second)
            self.assertEqual(first.parent, Path(directory).resolve())
            self.assertIn(digest, first.name)
            self.assertEqual(first.read_bytes(), b"one")

    def test_explicit_output_requires_force_to_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.bin"
            save_artifact(b"first", "c", output=path)
            with self.assertRaises(GameMasterError):
                save_artifact(b"second", "c", output=path)
            self.assertEqual(path.read_bytes(), b"first")
            save_artifact(b"second", "c", output=path, overwrite=True)
            self.assertEqual(path.read_bytes(), b"second")

    def test_terminal_escape_characters_are_not_rendered(self):
        preview = "\n".join(artifact_summary(b"\x1b[31mhidden\x07"))
        self.assertNotIn("\x1b", preview)
        self.assertNotIn("\x07", preview)


def zipped(*names, encrypted=False):
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in names:
            archive.writestr(name, b"x")
    data = bytearray(buffer.getvalue())
    if encrypted:
        # zipfile cannot write encrypted entries; set the flag in both headers instead.
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            data[data.index(signature) + offset] |= 0x1
    return bytes(data)


class TriageTests(unittest.TestCase):
    def test_kind_and_lane_hint_from_structure(self):
        for artifact, expected in (
            (b"MZ\x90\x00\x03" + b"\x00" * 60, "PE executable"),
            (b"\x7fELF\x02\x01\x01" + b"\x00" * 9, "ELF executable"),
            (b"%PDF-1.7\n", "PDF document"),
            (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", "PNG image"),
            (b"\xff\xd8\xff\xe1\x00\x10Exif", "JPEG image"),
            (zipped("AndroidManifest.xml", "classes.dex", "resources.arsc"), "Mobile Android"),
            (zipped("[Content_Types].xml", "docProps/core.xml", "word/document.xml"), "Office Open XML"),
            (zipped("notes.txt"), "ZIP archive"),
            (zipped("sample.ps1", encrypted=True), "encrypted entries"),
            (b"$s = 'x'\npowershell -EncodedCommand SQBFAFgA", "Script Analysis"),
            (b"Just a note about encrypted files.", "UTF-8 text"),
            (b"\x00\x01\x02\xfe", "unrecognized binary data"),
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, artifact_kind(artifact))

    def test_binary_summary_includes_utf16_strings(self):
        artifact = b"\x00\xfe" + "http://wide.example/x".encode("utf-16-le") + b"\xff\x00plain-ascii\x00"
        summary = "\n".join(artifact_summary(artifact))
        self.assertIn("http://wide.example/x", summary)
        self.assertIn("plain-ascii", summary)
        self.assertIn("Kind: unrecognized binary data", summary)


if __name__ == "__main__":
    unittest.main()
