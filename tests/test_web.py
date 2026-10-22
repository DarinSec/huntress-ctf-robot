"""The Web lane plumbing: a scoped HTTP client and the fastpath target path.

No real target is touched: a local http.server on 127.0.0.1 stands in, and a demo handler
reads a flag from it. Handlers themselves are not tested here (they are their own modules).
"""

from contextlib import redirect_stdout
from copy import deepcopy
from io import StringIO
from pathlib import Path
import re
import tempfile
import threading
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, HTTPServer

from huntress_ctf.autopilot import COMPLETE, UNRESOLVED
from huntress_ctf.fastpath import run_fast
from huntress_ctf.solvers import AnswerCandidate
from huntress_ctf.solvers.web import (
    HostNotAllowed, ScopedHttp, TargetContext, scoped_http, target_urls,
)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/secret":
            body = b"<html>flag{demo-12345} is here</html>"
            self.send_response(200)
        else:
            body = b"nothing here"
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # Keep the test output clean.
        pass


class LocalServer:
    def __enter__(self):
        self.server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


class DemoFlagSolver:
    name = "web-demo"

    def solve(self, context: TargetContext):
        response = context.http.get(context.url.rstrip("/") + "/secret")
        match = re.search(r"flag\{[^}]+\}", response.text)
        if not match:
            return []
        return [AnswerCandidate(context.answer_ids[0], match.group(0), self.name, "read from the target")]


class ScopedHttpTests(unittest.TestCase):
    def test_target_urls_from_strings_and_dicts(self):
        self.assertEqual(target_urls(["http://a.test"]), ["http://a.test"])
        self.assertEqual(target_urls([{"url": "http://b.test"}, {"href": "http://c.test"}]),
                         ["http://b.test", "http://c.test"])
        self.assertEqual(target_urls([{"unrelated": "x"}]), [])

    def test_only_listed_hosts_are_reachable(self):
        with LocalServer() as server:
            http = scoped_http([{"url": server.url}])
            self.assertEqual(http.get(server.url + "/secret").status, 200)
            self.assertIn("flag{demo-12345}", http.get(server.url + "/secret").text)
            self.assertEqual(http.get(server.url + "/other").status, 404)
            with self.assertRaises(HostNotAllowed):
                http.get("http://127.0.0.1:1/off-target")  # A port not in the allowlist.
            with self.assertRaises(HostNotAllowed):
                http.get("http://attacker.example/")
            with self.assertRaises(HostNotAllowed):
                http.get("file:///etc/passwd")

    def test_empty_targets_allow_nothing(self):
        self.assertFalse(ScopedHttp(frozenset()).allows("http://anything.test"))


class WebClient:
    token = None

    def __init__(self, stdout, target_url, answer_id="flag", result=None):
        self.stdout = stdout
        self.answer_id = answer_id
        self.assignment = {
            "answer_ids": [answer_id], "attempt_id": "w", "mode": "single_solve",
            "targets": [{"url": target_url}], "instructions": "Read the flag from the target.",
        }
        self.result = result if result is not None else {"result": "CORRECT"}
        self.calls = []
        self.status_response = None

    def list_challenges(self, day=None, lane=None):
        return {"challenges": [{"id": "web-exploitation-day-01-x", "lane": "web-exploitation",
                                "curriculum_day": 1}]}

    def status(self, challenge_id):
        self.calls.append("status")
        if self.status_response is not None:
            return deepcopy(self.status_response)
        return {**deepcopy(self.assignment), "state": "active"}

    def start(self, challenge_id, timed=False):
        self.calls.append(("start", timed))
        return deepcopy(self.assignment)

    def retry(self, challenge_id, timed=False):
        self.calls.append(("retry", timed))
        return deepcopy(self.assignment)

    def artifact(self, challenge_id):
        raise AssertionError("A web route has no artifact to download")

    def submit_many(self, challenge_id, answers):
        self.calls.append(("submit_many", dict(answers)))
        return deepcopy(self.result)


class WebFastPathTests(unittest.TestCase):
    def run_fast(self, client, **kwargs):
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(StringIO()):
            root = Path(directory)
            return run_fast(client, "web-exploitation-day-01-x", artifact_dir=root,
                            work_dir=root / "work", hints_path=root / "h.json",
                            ntp=lambda: None, **kwargs)

    def test_a_handler_flag_is_submitted(self):
        with LocalServer() as server:
            client = WebClient(StringIO(), server.url)
            with mock.patch("huntress_ctf.solvers.web.WEB_SOLVERS", (DemoFlagSolver(),)):
                code = self.run_fast(client)
        self.assertEqual(code, COMPLETE)
        self.assertIn(("submit_many", {"flag": "flag{demo-12345}"}), client.calls)

    def test_no_handler_leaves_the_attempt_untouched(self):
        with LocalServer() as server:
            client = WebClient(StringIO(), server.url)
            with mock.patch("huntress_ctf.solvers.web.WEB_SOLVERS", ()):
                code = self.run_fast(client)
        self.assertEqual(code, UNRESOLVED)
        self.assertFalse([c for c in client.calls if isinstance(c, tuple) and c[0] == "submit_many"])


if __name__ == "__main__":
    unittest.main()
