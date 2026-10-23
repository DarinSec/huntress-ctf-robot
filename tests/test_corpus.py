"""The replay corpus: record a scored assignment, replay it, and flag only real regressions."""

from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from huntress_ctf import corpus
from huntress_ctf.containers import Member


def evidence(roster=b"name,role\nana,lead\n"):
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("roster.csv", roster)
    return buffer.getvalue()


def assignment():
    questions = [{"id": "roster-size-bytes", "question": "Inspect `roster.csv`. What is its exact size in bytes?",
                  "artifact": "evidence.zip -> roster.csv", "answer_format": {"kind": "integer"}},
                 {"id": "roster-md5", "question": "Inspect `roster.csv`. What is its MD5 digest?",
                  "artifact": "evidence.zip -> roster.csv", "answer_format": {"kind": "pattern"}}]
    challenge = {"id": "metadata-forensics-day-30-x/time_trial", "lane": "metadata-forensics"}
    attempt = {"attempt_id": "a1", "answer_ids": [q["id"] for q in questions], "questions": questions,
               "artifacts": [{"filename": "evidence.zip"}]}
    return challenge, attempt


class CorpusTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def test_record_replay_and_regression(self):
        challenge, attempt = assignment()
        data = evidence()
        accepted = {"roster-size-bytes": "19"}
        entry = corpus.record(challenge["id"], challenge, attempt, data, (), accepted, root=self.root)
        self.assertEqual(corpus.entries(self.root), [entry])
        first = corpus.replay(entry)
        self.assertEqual((first["answered"], first["equal"], first["regressions"]), (2, 1, []))
        # A later solver change that loses an accepted answer is a regression; a new attempt id adds an entry.
        with patch("huntress_ctf.solvers.metadata._FACTS", []):
            second = corpus.replay(entry)
        self.assertEqual(second["regressions"], ["roster-md5", "roster-size-bytes"])

    def test_limits_and_merging(self):
        challenge, attempt = assignment()
        entry = corpus.record(challenge["id"], challenge, attempt, evidence(), (), {"roster-md5": "x"}, root=self.root)
        corpus.record(challenge["id"], challenge, attempt, evidence(), (), {"roster-size-bytes": "19"}, root=self.root)
        self.assertEqual(json.loads((entry / "accepted.json").read_text()), {"roster-md5": "x", "roster-size-bytes": "19"})
        for attempt_id in ("a2", "a3"):
            corpus.record(challenge["id"], challenge, {**attempt, "attempt_id": attempt_id}, evidence(), (), {"q": "1"}, root=self.root)
        self.assertEqual(len(corpus.entries(self.root)), corpus.MAX_ENTRIES_PER_ROUTE)
        self.assertIsNone(corpus.record("x", {}, attempt, b"", (), {}, root=self.root))  # Nothing accepted.

    def test_deliveries_keep_their_names_and_order(self):
        challenge, attempt = assignment()
        deliveries = (Member("delivery 1: one.apk", b"1"), Member("delivery 2: two.apk", b"2"))
        entry = corpus.record("mobile-android-day-30-x/mastery", challenge, attempt, b"1", deliveries, {"q": "a"}, root=self.root)
        self.assertEqual(sorted(path.name for path in (entry / "deliveries").iterdir()), ["1-one.apk", "2-two.apk"])


if __name__ == "__main__":
    unittest.main()
