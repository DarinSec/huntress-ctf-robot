from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from huntress_ctf.artifacts import artifact_summary, save_artifact
from huntress_ctf.cli import main
from huntress_ctf.client import GameMasterError


class CliTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
