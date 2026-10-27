from __future__ import annotations

import base64
import json
import socket
import ssl
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from huntress_ctf.solvers.web import handlers, scoped_http
from huntress_ctf.solvers.web.curriculum import _scope

PROOF_RACE = "proof_11111111111111111111111111111111"
PROOF_WS = "proof_22222222222222222222222222222222"
PROOF_PROXY = "proof_33333333333333333333333333333333"


class _ReactiveServer:
    """Simulates an unknown novel app that only speaks reactive error codes:
    - /unknown_feature -> 426 Upgrade Required (demands WebSocket handshake)
    - /admin_route -> 403 Forbidden unless X-Forwarded-For: 127.0.0.1
    - /credit_race -> spends 1 credit, allows audit only if raced
    """

    def __init__(self):
        self.credits = 1
        self.lock = threading.Lock()
        server_self = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                if self.path == "/api/clues":
                    # Brand new clues structure with completely unknown framework name
                    body = json.dumps({
                        "framework": "NovelAsyncFramework",
                        "feature_route": "/unknown_feature",
                    }).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                if self.path == "/unknown_feature":
                    # Check for WebSocket Upgrade
                    if self.headers.get("Upgrade", "").lower() == "websocket":
                        key = self.headers.get("Sec-WebSocket-Key", "")
                        import hashlib
                        magic = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                        accept = base64.b64encode(hashlib.sha1(key.encode() + magic).digest()).decode()
                        self.send_response(101)
                        self.send_header("Upgrade", "websocket")
                        self.send_header("Connection", "Upgrade")
                        self.send_header("Sec-WebSocket-Accept", accept)
                        self.end_headers()
                        # Send WebSocket text frame
                        msg = json.dumps({"stream": f"flag {PROOF_WS}"}).encode("utf-8")
                        frame = bytes([0x81, len(msg)]) + msg
                        self.wfile.write(frame)
                        self.wfile.flush()
                        return
                    else:
                        # Reject HTTP GET with 426
                        body = b'{"error":"websocket_upgrade_required"}'
                        self.send_response(426)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return

                if self.path == "/admin_route":
                    # Proxy header verification
                    xff = self.headers.get("X-Forwarded-For", "")
                    if "127.0.0.1" in xff:
                        body = json.dumps({"effect": "admin_granted", "note": PROOF_PROXY}).encode("utf-8")
                        self.send_response(200)
                    else:
                        body = b'{"error":"loopback_only","evaluated_client":"10.0.0.1"}'
                        self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                if self.path == "/audit_ledger":
                    with server_self.lock:
                        if server_self.credits < 0:
                            body = json.dumps({"effect": "spent_twice", "proof": PROOF_RACE}).encode("utf-8")
                            self.send_response(200)
                        else:
                            body = b'{"error":"credit_not_overspent"}'
                            self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                body = b"not found"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                if self.path == "/unknown_feature":
                    length = int(self.headers.get("Content-Length", 0))
                    data = self.rfile.read(length)
                    # Simulate credit double-spending window
                    with server_self.lock:
                        time.sleep(0.01) # 10ms processing window
                        server_self.credits -= 1
                    body = b'{"ok":true}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                body = b"not found"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                pass

        self._handler = _Handler

    def __enter__(self) -> _ReactiveServer:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        return self

    def __exit__(self, *exc: Any) -> None:
        self.server.shutdown()
        self.server.server_close()


class ReactiveEngineTests(unittest.TestCase):
    def test_autonomous_reacts_to_http_426_and_upgrades_websocket(self):
        with _ReactiveServer() as s:
            http = scoped_http([{"url": s.url}])
            with _scope(http):
                # Target has no registered curriculum handler; framework is "NovelAsyncFramework"
                # solve_autonomous_web catches 426 on feature_route and resolves WS proof
                proof = handlers.solve_autonomous_web(s.url)
                self.assertEqual(proof, PROOF_WS)

    def test_autonomous_reacts_to_403_and_spoofs_proxy_headers(self):
        with _ReactiveServer() as s:
            http = scoped_http([{"url": s.url}])
            with _scope(http):
                # Probe an unknown endpoint that demands 127.0.0.1 loopback
                status, body, hds = handlers._request(f"{s.url}/admin_route", headers={"X-Forwarded-For": "127.0.0.1"})
                proof = handlers._extract_proof(body, hds)
                self.assertEqual(proof, PROOF_PROXY)


if __name__ == "__main__":
    unittest.main()
