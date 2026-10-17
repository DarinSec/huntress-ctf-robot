import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from huntress_ctf.config import load_env


class LoadEnvTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / ".env"

    def test_reads_allowed_keys_with_bom_and_quotes(self):
        self.path.write_bytes(
            "﻿HUNTRESS_GM_TOKEN='synthetic-token'\n# comment\nOTHER=ignored\n"
            "export HUNTRESS_GM_URL=https://example.invalid\n".encode("utf-8")
        )
        with patch.dict(os.environ, {"HUNTRESS_GM_TOKEN": "", "HUNTRESS_GM_URL": ""}, clear=False):
            os.environ.pop("OTHER", None)
            self.assertEqual(load_env((self.path,)), self.path)
            self.assertEqual(os.environ["HUNTRESS_GM_TOKEN"], "synthetic-token")
            self.assertEqual(os.environ["HUNTRESS_GM_URL"], "https://example.invalid")
            self.assertNotIn("OTHER", os.environ)

    def test_real_environment_wins_and_missing_file_is_fine(self):
        self.path.write_text("HUNTRESS_GM_TOKEN=from-file\n", encoding="utf-8")
        with patch.dict(os.environ, {"HUNTRESS_GM_TOKEN": "from-shell"}):
            load_env((self.path,))
            self.assertEqual(os.environ["HUNTRESS_GM_TOKEN"], "from-shell")
        self.assertIsNone(load_env((Path(self.directory.name) / "missing.env",)))


if __name__ == "__main__":
    unittest.main()
