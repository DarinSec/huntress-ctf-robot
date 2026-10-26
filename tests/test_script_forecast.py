"""Script Analysis forecast for days 27-31, the way tests/test_forecast.py does it for Metadata.

The course names its next languages itself: every polyglot descriptor carries a `next_language`,
and on day 24 those included elixir and erlang, which became day 25's .exs and day 26's .escript
specimens. The fourteen named since and not yet shipped (days 24-26 descriptors) get specimens here
in the course's polyglot shape: the descriptor as a `HUNTRESS_ANALYSIS_V1:LYR-<layers>-<payload>`
comment in the language's own comment syntax (block comments too, with and without spaces), the
same payload in a body constant, an inert stub, and question IDs `setN.polyglot-<language>-<hex>-
<field>`. All 13 polyglot questions must come back with the descriptor's values. Layers stay within
the vocabulary days 23-26 used (b64, b32, hex, rev, frag), stacked as the course stacks them.

Some languages have no bracketed arrays (fish, makefile), so a SPLIT payload there is a list of
quoted words with no closing bracket.
"""

import base64
import hashlib
import unittest
from pathlib import Path

from huntress_ctf.containers import Member
from huntress_ctf.solvers.base import SolveContext
from huntress_ctf.solvers.script import ScriptSolver

# language, extension, comment line ({h}: the header), body ({p}: the payload).
FORECAST = (
    ("awk", "awk", "# {h}", 'BEGIN {{ descriptor = "{p}"; exit 0 }}'),
    ("beanshell", "bsh", "// {h}", 'String descriptor = "{p}";\nvoid inertRequest() {{ return; }}'),
    ("dockerfile", "dockerfile", "# {h}", 'FROM scratch\nENV HUNTRESS_DESCRIPTOR="{p}"\nLABEL purpose="inert analysis"'),
    ("fish", "fish", "# {h}", 'set -l descriptor "{p}"\nfunction inert_request; echo none; end'),
    ("kotlin", "kts", "/*{h}*/", 'val descriptor = "{p}"\nfun inertRequest(): String = "none"'),
    ("makefile", "mk", "# {h}", "DESCRIPTOR := {p}\n.PHONY: analyze\nanalyze:\n\t@:"),
    ("nim", "nims", "#[ {h} ]#", 'const descriptor = "{p}"\nproc inertRequest(): string = "none"'),
    ("rust", "rs", "//! {h}", 'const DESCRIPTOR: &str = "{p}";\nfn main() {{}}'),
    ("sed", "sed", "# {h}", "1i\\\n{p}\nd"),
    ("swift", "swift", "/// {h}", 'let descriptor = "{p}"\nfunc inertRequest() -> String {{ "none" }}'),
    ("tcl", "tcl", "# {h}", 'set descriptor "{p}"\nproc inert_request {{}} {{ return none }}'),
    ("terraform_hcl", "tf", "/* {h} */", 'locals {{\n  descriptor = "{p}"\n}}'),
    ("xslt", "xslt", '<?xml version="1.0"?>\n<!--{h}-->',
     '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">\n'
     '  <xsl:variable name="descriptor" select="\'{p}\'"/>\n</xsl:stylesheet>'),
    ("zsh", "zsh", "# {h}", 'typeset descriptor="{p}"\ninert_request() {{ print none }}'),
)

# Real day 26 role, attack, steps, stage profile, adapter, host profile, verdict combinations.
PROFILES = (
    ("launcher", "T1059", "read_file,enumerate_targets,decode_embedded,write_file,transmit_remote,dispatch_memory",
     "slate_ladder", "process_builder", "php_webshell", "suspicious"),
    ("staged_chain", "T1059", "read_file,decode_embedded,write_file,dispatch_memory", "umber_ladder",
     "operation_graph", "standalone", "suspicious"),
    ("uploader", "T1041", "enumerate_targets,locate_local,acquire_remote,decode_configuration,write_file,"
     "transmit_remote,dispatch_memory", "teal_spindle", "http_client", "php_webshell", "suspicious"),
    ("downloader", "T1105", "decode_embedded,transmit_remote,dispatch_memory", "ruby_weave", "http_client",
     "php_webshell", "suspicious"),
    ("dropper", "T1140", "profile_host,enumerate_targets,decode_embedded,read_file,transmit_remote,dispatch_memory",
     "onyx_braid", "file_writer", "php_webshell", "suspicious"),
    ("benign_utility", "none", "profile_host,acquire_remote,transmit_remote,dispatch_language", "cobalt_pivot",
     "local_parser", "standalone", "benign"),
    ("persistence_descriptor", "T1053", "read_file,enumerate_targets,acquire_remote,decode_configuration,write_file,"
     "dispatch_language", "ruby_lattice", "schedule_builder", "hta_jscript", "suspicious"),
)
LAYERS = ("b64_frag_b64", "hex_b32_rev", "b32_hex_rev", "hex_rev_frag", "b64_b32_rev", "b32_frag_rev",
          "hex_hex_b64", "b64_b64_b64", "hex_b64", "b32_rev_b64")
FIELDS = ("role", "attack", "steps", "stage-count", "stage-profile", "obfuscation", "next-language", "campaign",
          "url", "file-path", "url-host", "path-leaf", "campaign-token")


def layered(spec, plain):
    """Encode in the order the spec lists (decoding undoes them last to first)."""
    data = plain
    for layer in spec.split("_"):
        if layer == "b64":
            data = base64.b64encode(data)
        elif layer == "b32":
            data = base64.b32encode(data)
        elif layer == "hex":
            data = data.hex().encode()
        elif layer == "rev":
            data = data[::-1]
        elif layer == "frag":
            data = b".".join(data[at:at + 32] for at in range(0, len(data), 32))
    return data.decode()


def descriptor(language, index):
    role, attack, steps, profile, adapter, host, verdict = PROFILES[index % len(PROFILES)]
    token = hashlib.sha256(language.encode()).hexdigest()
    host_name = language.replace("_", "-")
    spec = LAYERS[index % len(LAYERS)]
    values = {"v": "3", "language": language, "role": role, "verdict": verdict, "attack": attack,
              "adapter": adapter, "host_profile": host, "obfuscation_profile": spec, "stage_profile": profile,
              "next_language": FORECAST[(index + 1) % len(FORECAST)][0], "stage_count": str(len(steps.split(","))),
              "steps": steps, "campaign_id": f"{language.upper()}-{token[:8]}",
              "url": f"https://{host_name}-{token[:10]}.example.invalid/stage",
              "file_path": f"/tmp/huntress-{language}/.{token[:16]}.stage"}
    return spec, values


def expected(values):
    return {"role": values["role"], "attack": values["attack"], "steps": values["steps"].replace(",", ">"),
            "stage-count": values["stage_count"], "stage-profile": values["stage_profile"],
            "obfuscation": values["obfuscation_profile"], "next-language": values["next_language"],
            "campaign": values["campaign_id"], "url": values["url"], "file-path": values["file_path"],
            "url-host": values["url"].split("/")[2], "path-leaf": values["file_path"].rsplit("/", 1)[1],
            "campaign-token": values["campaign_id"].split("-", 1)[1]}


def specimen(index, split=None):
    """(language, file name, text, expected answers); split: "brackets" or "words" spreads the payload
    over a SPLIT string array instead of the one-line header."""
    language, extension, comment, body = FORECAST[index]
    spec, values = descriptor(language, index)
    payload = layered(spec, "|".join(f"{k}={v}" for k, v in values.items()).encode())
    if split:
        text = "LYR-" + spec + "-" + payload
        pieces = " ".join(f'"{text[at:at + 48]}"' for at in range(0, len(text), 48))
        array = f"[{pieces.replace(' ', ', ')}]" if split == "brackets" else pieces
        source = f"{comment.format(h='HUNTRESS_ANALYSIS_V1:SPLIT')}\nparts = {array}\n{body.format(p='inert')}\n"
    else:
        source = f"{comment.format(h=f'HUNTRESS_ANALYSIS_V1:LYR-{spec}-{payload}')}\n{body.format(p=payload)}\n"
    digest = hashlib.sha256(f"{language}{split}".encode()).hexdigest()[:6]
    return language, f"{digest}.{extension}", source, expected(values)


def solve(specimens):
    questions, members = [], []
    for language, name, source, _ in specimens:
        members.append(Member(f"bundle/evidence-01.zip/{name}", source.encode()))
        stem = name.split(".")[0]
        questions += [{"id": f"set1.polyglot-{language}-{stem}-{field}", "question": f"{field} of {name}?",
                       "artifact": f"evidence-01.zip -> {name}", "answer_format": {"kind": "exact_text"}}
                      for field in FIELDS]
    context = SolveContext("script-analysis-day-27-x/mastery", {"lane": "script-analysis", "questions": questions},
                           {"attempt_id": "forecast"}, b"", Path("unused"), tuple(q["id"] for q in questions),
                           members=tuple(members))
    return {candidate.answer_id: candidate.answer for candidate in ScriptSolver().solve(context)}


class ScriptForecastTests(unittest.TestCase):
    def check(self, specimens):
        got = solve(specimens)
        for language, name, _, answers in specimens:
            stem = name.split(".")[0]
            for field, value in answers.items():
                with self.subTest(language=language, field=field):
                    self.assertEqual(got.get(f"set1.polyglot-{language}-{stem}-{field}"), value)

    def test_every_forecast_language_answers_all_polyglot_questions(self):
        self.check([specimen(index) for index in range(len(FORECAST))])

    def test_split_payloads_with_and_without_brackets(self):
        by_name = {language: index for index, (language, *_rest) in enumerate(FORECAST)}
        self.check([specimen(by_name["kotlin"], "brackets"), specimen(by_name["tcl"], "brackets"),
                    specimen(by_name["fish"], "words"), specimen(by_name["makefile"], "words")])


if __name__ == "__main__":
    unittest.main()
