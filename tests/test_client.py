from email.message import Message
from io import BytesIO
import json
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request

from huntress_ctf.client import GameMasterClient, GameMasterError, PROXY_BASE_URL, _NoRedirect


class Response(BytesIO):
    def __init__(self, body=b'{"ok":true}', kind="application/json", attachment=False):
        super().__init__(body)
        self.headers = Message()
        self.headers["Content-Type"] = kind
        if attachment:
            self.headers["Content-Disposition"] = "attachment"


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
        self.client._opener = Mock()
        self.client._opener.open.return_value = Response()

    def test_direct_get_has_root_query_and_auth(self):
        self.client.list_challenges(day=1, lane="warm ups")
        request = self.client._opener.open.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(urlsplit(request.full_url).path, "/")
        self.assertEqual(parse_qs(urlsplit(request.full_url).query),
                         {"op": ["list"], "day": ["1"], "lane": ["warm ups"]})
        self.assertEqual(request.get_header("Authorization"), "Bearer private-test-token")
        self.assertIsNone(request.get_header("Content-type"))

    def test_proxy_exact_path_never_inherits_bearer(self):
        with patch.dict("os.environ", {"HUNTRESS_GM_TOKEN": "private-test-token"}):
            client = GameMasterClient(base_url=PROXY_BASE_URL + "/")
        client._opener = Mock()
        client._opener.open.return_value = Response()
        client.list_challenges()
        request = client._opener.open.call_args.args[0]
        self.assertEqual(request.full_url, PROXY_BASE_URL + "?op=list")
        self.assertIsNone(request.get_header("Authorization"))

    def test_timed_start_and_retry_request_bodies(self):
        for method, expected in (
            (lambda: self.client.start("x"), {"challenge": "x"}),
            (lambda: self.client.start("x", timed=True),
             {"op": "start", "challenge": "x", "run_for_time": True}),
            (lambda: self.client.retry("x", timed=True),
             {"op": "retry", "challenge": "x", "run_for_time": True}),
            (lambda: self.client.submit("x", "a", "answer"),
             {"challenge": "x", "answers": {"a": "answer"}}),
        ):
            with self.subTest(expected=expected):
                self.client._opener.open.return_value = Response()
                method()
                request = self.client._opener.open.call_args.args[0]
                self.assertEqual(request.get_method(), "POST")
                self.assertEqual(json.loads(request.data), expected)
                self.assertEqual(request.get_header("Content-type"), "application/json")

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
        for token in (0, False, "bad\x00token", "bad token", "\u2603"):
            with self.subTest(token=token), self.assertRaises(GameMasterError):
                GameMasterClient(token=token)

    def test_missing_token_fails_without_network(self):
        self.client.token = None
        with self.assertRaises(GameMasterError):
            self.client.list_challenges()
        self.client._opener.open.assert_not_called()

    def test_bad_json_and_error_envelopes_are_not_success(self):
        for body in (b"", b"oops", b"null", b'"OK"', b'{"error":"denied"}'):
            with self.subTest(body=body), self.assertRaises(GameMasterError):
                self.client._opener.open.return_value = Response(body)
                self.client.status("x")

    def test_artifacts_can_be_json_but_not_error_pages(self):
        body = b'{"answers":{"a":"value"}}'
        self.client._opener.open.return_value = Response(body)
        self.assertEqual(self.client.artifact("x"), body)
        for response in (Response(b"<html>login</html>", "text/html"),
                         Response(b'{"error":"unavailable"}')):
            self.client._opener.open.return_value = response
            with self.assertRaises(GameMasterError):
                self.client.artifact("x")
        self.client._opener.open.return_value = Response(b"<html>puzzle</html>", "text/html", True)
        self.assertEqual(self.client.artifact("x"), b"<html>puzzle</html>")

    def test_limits_and_uncertain_posts_are_not_retried(self):
        with patch("huntress_ctf.client.MAX_ARTIFACT_BYTES", 4):
            self.client._opener.open.return_value = Response(b"12345", "application/octet-stream")
            with self.assertRaises(GameMasterError):
                self.client.artifact("x")
        self.client._opener.open.reset_mock()
        self.client._opener.open.side_effect = URLError("private-test-token")
        with self.assertRaises(GameMasterError) as raised:
            self.client.submit("x", "a", "value")
        self.assertNotIn("private-test-token", str(raised.exception))
        self.assertEqual(self.client._opener.open.call_count, 1)

    def test_http_error_and_redirect_do_not_leak_credentials(self):
        self.client._opener.open.side_effect = HTTPError(
            "https://example.com", 401, "private-test-token", {}, BytesIO(b"secret")
        )
        with self.assertRaisesRegex(GameMasterError, "HTTP 401"):
            self.client.list_challenges()
        with self.assertRaises(GameMasterError):
            _NoRedirect().redirect_request(
                Request("https://example.com", headers={"Authorization": "Bearer secret"}),
                None, 302, "Found", {}, "https://other.example/path",
            )


if __name__ == "__main__":
    unittest.main()
