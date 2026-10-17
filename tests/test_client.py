from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from huntress_ctf.client import GameMasterClient, GameMasterError, PROXY_BASE_URL


def reply(body=b'{"ok":true}', kind="application/json", attachment=False, status=200):
    headers = Message()
    headers["Content-Type"] = kind
    if attachment:
        headers["Content-Disposition"] = "attachment"
    return status, headers, body


def sent(client):
    method, target, body, headers, _limit = client._send.call_args.args
    return method, target, body, headers


class ClientTests(unittest.TestCase):
    def setUp(self):
        # Preserve the runtime's SSL configuration while isolating client settings.
        self.env = patch.dict("os.environ", {
            "HUNTRESS_GM_URL": "https://2026.huntress.ctf.games/",
            "HUNTRESS_GM_TOKEN": "",
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        self.client = GameMasterClient(token="private-test-token")
        self.client._send = Mock(return_value=reply())

    def test_direct_get_has_root_query_and_auth(self):
        self.client.list_challenges(day=1, lane="warm ups")
        method, target, body, headers = sent(self.client)
        self.assertEqual(method, "GET")
        self.assertEqual(urlsplit(target).path, "/")
        self.assertEqual(parse_qs(urlsplit(target).query),
                         {"op": ["list"], "day": ["1"], "lane": ["warm ups"]})
        self.assertEqual(headers["Authorization"], "Bearer private-test-token")
        self.assertNotIn("Content-Type", headers)
        self.assertIsNone(body)

    def test_proxy_exact_path_never_inherits_bearer(self):
        with patch.dict("os.environ", {"HUNTRESS_GM_TOKEN": "private-test-token"}):
            client = GameMasterClient(base_url=PROXY_BASE_URL + "/")
        client._send = Mock(return_value=reply())
        client.list_challenges()
        _method, target, _body, headers = sent(client)
        self.assertEqual(target, "/huntress-ctf-proxy?op=list")
        self.assertNotIn("Authorization", headers)

    def test_timed_start_and_retry_request_bodies(self):
        for method, expected in (
            (lambda: self.client.start("x"), {"challenge": "x"}),
            (lambda: self.client.start("x", timed=True),
             {"op": "start", "challenge": "x", "run_for_time": True}),
            (lambda: self.client.retry("x", timed=True),
             {"op": "retry", "challenge": "x", "run_for_time": True}),
            (lambda: self.client.submit("x", "a", "answer"),
             {"challenge": "x", "answers": {"a": "answer"}}),
            (lambda: self.client.submit_many("x", {"a": "one", "b": "two"}),
             {"challenge": "x", "answers": {"a": "one", "b": "two"}}),
        ):
            with self.subTest(expected=expected):
                self.client._send.return_value = reply()
                method()
                verb, _target, body, headers = sent(self.client)
                self.assertEqual(verb, "POST")
                self.assertEqual(json.loads(body), expected)
                self.assertEqual(headers["Content-Type"], "application/json")

    def test_submit_many_rejects_bad_answers_before_network(self):
        for answers in ({}, {"a": 1}, {"": "x"}, ["a"]):
            with self.subTest(answers=answers), self.assertRaises(GameMasterError):
                self.client.submit_many("x", answers)
        self.client._send.assert_not_called()

    def test_configuration_rejected_before_network(self):
        for url in ("file:///tmp/file", "https://u:p@example.com", "https://x/?q=1",
                    "https://x/#f", "https://x:bad", "https://x/\n", ""):
            with self.subTest(url=url), self.assertRaises(GameMasterError):
                GameMasterClient(base_url=url, token="")
        for timeout in (0, -1, float("nan"), float("inf"), True, "30"):
            with self.subTest(timeout=timeout), self.assertRaises(GameMasterError):
                GameMasterClient(token="", timeout=timeout)
        with self.assertRaises(GameMasterError):
            GameMasterClient(base_url=PROXY_BASE_URL, token="secret")
        for token in (0, False, "bad\x00token", "bad token", "☃"):
            with self.subTest(token=token), self.assertRaises(GameMasterError):
                GameMasterClient(token=token)

    def test_missing_token_fails_without_network(self):
        self.client.token = None
        for call in (self.client.list_challenges, self.client.warm):
            with self.assertRaises(GameMasterError):
                call()
        self.client._send.assert_not_called()

    def test_bad_json_and_error_envelopes_are_not_success(self):
        for body in (b"", b"oops", b"null", b'"OK"', b'{"error":"denied"}'):
            with self.subTest(body=body), self.assertRaises(GameMasterError):
                self.client._send.return_value = reply(body)
                self.client.status("x")

    def test_artifacts_can_be_json_but_not_error_pages(self):
        body = b'{"answers":{"a":"value"}}'
        self.client._send.return_value = reply(body)
        self.assertEqual(self.client.artifact("x"), body)
        for response in (reply(b"<html>login</html>", "text/html"),
                         reply(b'{"error":"unavailable"}')):
            self.client._send.return_value = response
            with self.assertRaises(GameMasterError):
                self.client.artifact("x")
        self.client._send.return_value = reply(b"<html>puzzle</html>", "text/html", True)
        self.assertEqual(self.client.artifact("x"), b"<html>puzzle</html>")

    def test_limits_and_uncertain_posts_are_not_retried(self):
        with patch("huntress_ctf.client.MAX_ARTIFACT_BYTES", 4):
            self.client._send.return_value = reply(b"12345", "application/octet-stream")
            with self.assertRaises(GameMasterError):
                self.client.artifact("x")
        self.client._send.reset_mock()
        self.client._served = 3  # Even on a reused connection, a POST is sent once.
        self.client._send.side_effect = OSError("private-test-token")
        with self.assertRaises(GameMasterError) as raised:
            self.client.submit("x", "a", "value")
        self.assertNotIn("private-test-token", str(raised.exception))
        self.assertEqual(self.client._send.call_count, 1)

    def test_stale_kept_alive_get_is_repeated_once(self):
        self.client._served = 1
        self.client._send.side_effect = [ConnectionResetError(), reply()]
        self.assertEqual(self.client.status("x"), {"ok": True})
        self.assertEqual(self.client._send.call_count, 2)
        self.client._send.reset_mock()
        self.client._served = 1
        self.client._send.side_effect = [ConnectionResetError(), ConnectionResetError()]
        with self.assertRaises(GameMasterError):
            self.client.status("x")
        self.assertEqual(self.client._send.call_count, 2)

    def test_http_error_and_redirect_do_not_leak_credentials(self):
        self.client._send.return_value = reply(b"private-test-token", status=401)
        with self.assertRaisesRegex(GameMasterError, "HTTP 401") as raised:
            self.client.list_challenges()
        self.assertNotIn("private-test-token", str(raised.exception))
        self.client._send.reset_mock()
        self.client._send.return_value = reply(b"", status=302)
        with self.assertRaisesRegex(GameMasterError, "redirected"):
            self.client.submit("x", "a", "value")
        self.assertEqual(self.client._send.call_count, 1)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.server.connections += 1

    def _respond(self):
        self.server.requests.append((self.command, self.path))
        body = json.dumps({"state": "active", "n": len(self.server.requests)}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        if self.server.drop_after_response:
            # Close without announcing it, like an idle keep-alive timeout.
            self.close_connection = True

    def do_GET(self):
        self._respond()

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        self._respond()


class KeepAliveTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.connections = 0
        self.server.requests = []
        self.server.drop_after_response = False
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        with patch.dict("os.environ", {"HUNTRESS_GM_TOKEN": "", "NO_PROXY": "*"}):
            self.client = GameMasterClient(
                base_url=f"http://127.0.0.1:{self.server.server_port}/", token="", timeout=5,
            )
        self.addCleanup(self.client.close)

    def test_requests_share_one_connection(self):
        with patch.dict("os.environ", {"NO_PROXY": "*"}):
            self.client.warm()
            self.client.status("x")
            self.client.artifact("x")
            self.client.submit_many("x", {"a": "one", "b": "two"})
        self.assertEqual(self.server.connections, 1)
        self.assertEqual([method for method, _ in self.server.requests], ["GET", "GET", "POST"])

    def test_dropped_connection_repeats_get_but_never_post(self):
        self.server.drop_after_response = True
        with patch.dict("os.environ", {"NO_PROXY": "*"}):
            self.client.status("x")
            self.client.status("x")  # Stale connection: repeated once on a new one.
            self.assertEqual(len(self.server.requests), 2)
            with self.assertRaises(GameMasterError):
                self.client.submit("x", "a", "value")
        self.assertEqual([method for method, _ in self.server.requests], ["GET", "GET"])


if __name__ == "__main__":
    unittest.main()
