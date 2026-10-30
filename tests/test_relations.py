"""relation.* properties of a cluster ZIP: Day 30 "Seeing Double" and the relations its prompt names.

Generated data only, never event artifacts or answers. The cluster mirrors what Day 30 shipped:
artifacts/<id> members, exact copies, one-byte forgeries (text, a PNG's final-block bit, a nested
ZIP changed without its CRC), nested ZIPs, and a delivery manifest with claims.
"""
from io import BytesIO
import json
from pathlib import Path
import struct
import unittest
import zipfile
import zlib

from huntress_ctf import relations
from huntress_ctf.solvers.base import SolveContext
from huntress_ctf.solvers.metadata import MetadataSolver, property_parser


def zipped(members):
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, data in members:
            archive.writestr(zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0)), data)
    return buffer.getvalue()


def chunk(kind, body):
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def png(text=None, final=True):
    pixels = zlib.compress(b"\x00\xff\x00\x00" * 2, 0)  # Stored block: byte 2 holds the final-block bit.
    header = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 2, 8, 2, 0, 0, 0))
    meta = chunk(b"tEXt", b"Comment\0" + text) if text else b""
    image = b"\x89PNG\r\n\x1a\n" + header + meta + chunk(b"IDAT", pixels) + chunk(b"IEND", b"")
    if not final:  # Day 30's forgery: the final-block bit cleared, chunk CRC left as it was (one byte).
        at = image.index(b"IDAT") + 6
        image = image[:at] + bytes([image[at] & 0xFE]) + image[at + 1:]
    return image


NOTE = b"# kelp a1b2c3\n$ErrorActionPreference = 'Stop'\n"
INNER = zipped([("willow.txt", NOTE)])
BROKEN = INNER.replace(b"Stop", b"Stoq", 1)  # Content changed, CRC not: the ZIP no longer reads.
CLUSTER = [
    ("artifacts/anchor-01", NOTE), ("artifacts/birch-02", NOTE), ("artifacts/cobalt-03", NOTE.replace(b"Pref", b"Prez")),
    ("artifacts/delta-04", b'{"a":1,"b":[2,3]}\n'), ("artifacts/ember-05", b'{ "b": [2, 3], "a": 1 }\r\n'),
    ("artifacts/fern-06", png()), ("artifacts/gale-07", png(b"exported")), ("artifacts/hazel-08", png()),
    ("artifacts/iris-09", png(final=False)),
    ("artifacts/jade-10", INNER), ("artifacts/kiln-11", INNER), ("artifacts/lark-12", BROKEN),
    ("artifacts/moss-13", zipped([("note.txt", NOTE)])),
]


def read(prop, members=CLUSTER):
    return property_parser(prop)(zipped(members))


class RelationTests(unittest.TestCase):
    def test_exact_groups_name_ids_and_sort(self):
        self.assertEqual(read("relation.identical_sha256_groups"),
                         '[["anchor-01","birch-02"],["fern-06","hazel-08"],["jade-10","kiln-11"]]')
        self.assertEqual(read("relation.identical_sha256_group_count"), "3")

    def test_semantic_identity_reads_content_not_storage(self):
        answer = read("relation.semantic_identity_groups")
        # JSON key order and CRLF, a PNG's tEXt chunk and the ZIP holding the same note all collapse;
        # the PNG whose zlib stream never ends (iris-09) is a forgery, not the same image.
        # A nested ZIP counts by its names and contents: moss-13 holds the note as note.txt, not willow.txt.
        self.assertEqual(answer, '[["anchor-01","birch-02"],["delta-04","ember-05"],["fern-06","gale-07","hazel-08"],'
                                 '["jade-10","kiln-11"]]')
        self.assertIn('[["anchor-01","birch-02"],["delta-04","ember-05"],["fern-06","gale-07","hazel-08","iris-09"],'
                      '["jade-10","kiln-11"]]', answer.alternatives)  # Lenient inflate.
        self.assertIn('[["delta-04","ember-05"],["fern-06","gale-07","hazel-08"]]',
                      answer.alternatives)  # Only groups that are no exact copies.

    def test_containment_by_artifact_then_by_name(self):
        # A nested file that is byte for byte another artifact names that artifact (by name as the alternative).
        pairs = read("relation.containment_pairs")
        self.assertEqual(pairs, '[["jade-10","anchor-01"],["jade-10","birch-02"],["kiln-11","anchor-01"],'
                                '["kiln-11","birch-02"],["moss-13","anchor-01"],["moss-13","birch-02"]]')
        self.assertEqual(pairs.alternatives, ('[["jade-10","willow.txt"],["kiln-11","willow.txt"],["moss-13","note.txt"]]',))
        # Day 30's shape: each nested ZIP holds its own text, so the nested file's name is the other end.
        own = [("artifacts/jade-10", zipped([("willow.txt", b"delta quiet nectar c711\n")])),
               ("artifacts/kiln-11", zipped([("willow.txt", b"delta quiet nectar c711\n")])),
               ("artifacts/moss-13", zipped([("garnet.txt", b"saffron archived tundra 382f\n")])), ("artifacts/note-14", NOTE)]
        self.assertEqual(read("relation.containment_pairs", own),
                         '[["jade-10","willow.txt"],["kiln-11","willow.txt"],["moss-13","garnet.txt"]]')
        self.assertEqual(read("relation.contained_artifacts", own), '["garnet.txt","willow.txt"]')
        self.assertEqual(read("relation.container_ids", own), '["jade-10","kiln-11","moss-13"]')
        self.assertEqual(read("relation.containment_pairs", [("artifacts/note-14", NOTE)]), "[]")

    def test_fabricated_cluster_is_the_one_byte_forgeries(self):
        self.assertEqual(read("relation.fabricated_cluster"), '["cobalt-03","iris-09","lark-12"]')
        self.assertEqual(read("relation.near_duplicate_pairs"),
                         '[["cobalt-03","anchor-01"],["iris-09","fern-06"],["lark-12","jade-10"]]')
        groups = read("relation.fabricated_cluster_groups")
        self.assertEqual(groups, '[["cobalt-03"],["iris-09"],["lark-12"]]')
        self.assertIn('[["anchor-01","birch-02","cobalt-03"],["fern-06","hazel-08","iris-09"],["jade-10","kiln-11","lark-12"]]',
                      groups.alternatives)

    def test_claimed_provenance_needs_a_manifest(self):
        self.assertIsNone(read("relation.claimed_provenance_mismatches"))
        manifest = {"schema": "huntress.artifact_delivery_manifest.v1", "artifacts": [
            {"id": "alpha-01", "path": "artifacts/alpha-01.txt", "sha256": "00" * 32, "producer_id": "text_template"},
            {"id": "alpha-02", "path": "artifacts/alpha-02.txt", "producer_id": "duplicate_ref"},
            {"id": "bravo-01", "path": "artifacts/bravo-01.txt", "producer_id": "duplicate_ref", "size_bytes": 4},
        ]}
        members = [("delivery-manifest.json", json.dumps(manifest).encode()), ("artifacts/alpha-01.txt", b"same"),
                   ("artifacts/alpha-02.txt", b"same"), ("artifacts/bravo-01.txt", b"lone")]
        answer = read("relation.claimed_provenance_mismatches", members)
        self.assertEqual(answer, '["alpha-01","bravo-01"]')  # A false sha256; a "copy" with no twin.
        self.assertEqual(answer.alternatives, ('["alpha-01"]',))  # sha256 claims only.

    def test_damaged_members_and_unknown_names_answer_nothing(self):
        self.assertIsNone(property_parser("relation.weather_report"))
        self.assertIsNone(relations.relation_property("disk.partition_count"))
        self.assertIsNone(property_parser("relation.fabricated_cluster")(b"not a zip"))
        self.assertEqual(read("relation.fabricated_cluster", [("artifacts/a", b"x"), ("artifacts/b", b"y")]), '["a","b"]')

    def test_the_solver_passes_the_readings_on_as_alternatives(self):
        question = {"id": "d31-cluster-001-relation-semantic-identity-groups", "artifact": "evidence.zip -> cluster-001.zip",
                    "question": "Determine relation.semantic_identity_groups for cluster-001.zip.",
                    "answer_format": {"kind": "json", "syntax": "compact valid JSON array with exact values and order"}}
        context = SolveContext("metadata-forensics-day-31-x/time_trial", {"lane": "metadata-forensics"},
                               {"answer_ids": [question["id"]], "questions": [question]},
                               zipped([("cluster-001.zip", zipped(CLUSTER))]), Path("x"), (question["id"],))
        [candidate] = MetadataSolver().solve(context)
        self.assertIs(type(candidate.answer), str)
        self.assertEqual(candidate.answer, read("relation.semantic_identity_groups"))
        self.assertEqual(candidate.alternatives[:2], read("relation.semantic_identity_groups").alternatives)


if __name__ == "__main__":
    unittest.main()
