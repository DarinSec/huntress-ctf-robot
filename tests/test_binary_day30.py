"""Day 30 Binary: the HGRF campaign graph hidden in each d30-- Neko member.

Generated data only, never event artifacts or answers. The wording is the issued question's.
"""
from dataclasses import replace
import json
import struct
import unittest
import zlib

from huntress_ctf.solvers.binary import BinarySolver
from tests.test_binary_assignment import archive_context

LAYOUT = ("Locate the unique CRC32-valid HGRF record by scanning backward from the end of the Neko member. Its byte-4 "
          "version, byte-5 XOR key, little-endian length and CRC32 fields, XOR decoding, and UTF-8 JSON payload use the "
          "same 12-byte layout as HCFG. ")
LOADER = ("In evidence.zip, Use loader.n's decoded HGRF graph.config object after confirming all three canonical campaign "
          "graphs match when this_role is omitted. " + LAYOUT)
CAPSULE = "In evidence.zip, Use the unique unit-- member whose basename ends config.n. " + LAYOUT


def graph_record(values, key=0xF1):
    payload = json.dumps(values, separators=(",", ":")).encode()
    return struct.pack("<4sBBHI", b"HGRF", 1, key, len(payload), zlib.crc32(payload)) + bytes(b ^ key for b in payload)


def neko(role, config):
    graph = {"schema": "synthetic.campaign_graph.v1", "nodes": ["loader", "library", "config"], "config": config,
             "this_role": role}
    broken = bytearray(graph_record({"config": {"campaign": "decoy"}}))
    broken[8] ^= 1  # A later HGRF magic with a bad CRC32: the backward scan must skip it.
    return b"NEKO" + struct.pack("<iii", 1, 1, 1) + b"\0" * 64 + graph_record(graph) + bytes(broken) + b"\0" * 16


def members(config, config_member=None):
    return {"unit--sample-loader.n": neko("loader", config), "unit--sample-library.n": neko("library", config),
            "unit--sample-config.n": neko("config", config_member or config)}


def solve(files, prompts, timed=False):
    context = archive_context(files, prompts)
    if timed:
        context = replace(context, attempt={**context.attempt, "run_for_time": True, "deadline": "2099-01-01T00:00:00.000Z"})
    return {c.answer_id: c.answer for c in BinarySolver().solve(context)}


class Day30BinaryTests(unittest.TestCase):
    PROMPTS = [("unit_analysis_config_campaign", LOADER + "Submit the exact JSON string at loader.n decoded HGRF JSON "
                "property graph.config.campaign, without JSON quotes."),
               ("unit_analysis_config_capsule_graph_config_url", CAPSULE + "Submit the exact JSON string at config.n "
                "decoded HGRF JSON property graph.config.url, without JSON quotes.")]

    def test_graph_config_fields_untimed_and_timed(self):
        files = members({"campaign": "SYN-001", "url": "https://synthetic.invalid/stage"})
        expected = {"unit_analysis_config_campaign": "SYN-001",
                    "unit_analysis_config_capsule_graph_config_url": "https://synthetic.invalid/stage"}
        self.assertEqual(solve(files, self.PROMPTS), expected)
        self.assertEqual(solve(files, self.PROMPTS, timed=True), expected)

    def test_graphs_that_differ_beyond_this_role_answer_only_the_named_member(self):
        files = members({"campaign": "SYN-001", "url": "https://a.invalid/"}, {"campaign": "SYN-002", "url": "https://b.invalid/"})
        self.assertEqual(solve(files, self.PROMPTS, timed=True),
                         {"unit_analysis_config_capsule_graph_config_url": "https://b.invalid/"})


if __name__ == "__main__":
    unittest.main()
