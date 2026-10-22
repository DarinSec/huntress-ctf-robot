"""The curriculum adapter, its scope guard, and its keep-alive connection reuse.

No real target is touched: local http.server instances on 127.0.0.1 stand in for the Game
Master's assigned target (and for an off-scope host the handler must never reach). The
synthetic Day-1 server mirrors the backup-exposure flow the ported handler walks
(robots.txt -> directory index -> .bak), so the adapter runs Parsa's real `detect_and_solve`
end to end, scoped, without the network leaving the test process. The server counts both
requests and TCP connections, so a test can prove one kept-alive socket serves the whole
sequence.
"""

from __future__ import annotations

import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from huntress_ctf.solvers.web import HostNotAllowed, TargetContext, scoped_http
from huntress_ctf.solvers.web import WEB_SOLVERS
from huntress_ctf.solvers.web import handlers
from huntress_ctf.solvers.web.curriculum import CurriculumWebSolver, _ScopedTransport

PROOF = "proof_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"  # proof_<32 hex>, the shape handlers return


class _RoutedServer:
    """A tiny configurable http.server. `routes[path] = (status, headers, body)`; a
    redirect route carries a `Location` header and an empty body. `hits` records every path
    served and `connections` every TCP connection accepted, so a test can assert both the
    off-scope host was never contacted and the request sequence reused one socket. `http11`
    turns on keep-alive (as a live framework would); HTTP/1.0 is the no-reuse baseline.
    """

    def __init__(self, routes: dict[str, tuple[int, dict[str, str], bytes]], *, http11: bool = False):
        self.routes = routes
        self.hits: list[str] = []
        self.connections = 0
        server_self = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1" if http11 else "HTTP/1.0"

            def setup(self) -> None:  # one handler instance per TCP connection
                super().setup()
                server_self.connections += 1

            def do_GET(self) -> None:  # noqa: N802
                server_self.hits.append(self.path)
                status, headers, body = server_self.routes.get(self.path, (404, {}, b"not found"))
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:  # keep test output clean
                pass

        self._handler = _Handler

    def __enter__(self) -> "_RoutedServer":
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        return self

    def __exit__(self, *exc: Any) -> None:
        self.server.shutdown()
        self.server.server_close()


def _day1_routes() -> dict[str, tuple[int, dict[str, str], bytes]]:
    return {
        "/robots.txt": (200, {}, b"User-agent: *\nDisallow: /backups/\n"),
        "/backups/": (200, {}, b'<html><a href="app.bak">app.bak</a></html>'),
        "/backups/app.bak": (200, {}, f"archived note: {PROOF}".encode()),
    }


def _context(server_url: str, *, curriculum_day: Any = 1,
             answer_ids: tuple[str, ...] = ("flag",)) -> TargetContext:
    targets = ({"url": server_url},)
    return TargetContext(
        challenge_id="web-exploitation-day-01-x",
        challenge={"curriculum_day": curriculum_day},
        attempt={},
        answer_ids=answer_ids,
        targets=targets,
        http=scoped_http(targets),
    )


class AdapterTests(unittest.TestCase):
    def test_discovery_registers_the_curriculum_solver(self):
        self.assertTrue(any(isinstance(s, CurriculumWebSolver) for s in WEB_SOLVERS))

    def test_day1_proof_is_recovered_and_wrapped(self):
        with _RoutedServer(_day1_routes()) as server:
            candidates = CurriculumWebSolver().solve(_context(server.url))
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].answer, PROOF)
        self.assertEqual(candidates[0].answer_id, "flag")
        self.assertEqual(candidates[0].solver, "web-curriculum")

    def test_one_candidate_per_answer_id(self):
        with _RoutedServer(_day1_routes()) as server:
            candidates = CurriculumWebSolver().solve(_context(server.url, answer_ids=("a", "b")))
        self.assertEqual({c.answer_id for c in candidates}, {"a", "b"})
        self.assertTrue(all(c.answer == PROOF for c in candidates))

    def test_no_proof_yields_no_candidate(self):
        routes = _day1_routes()
        routes["/backups/app.bak"] = (200, {}, b"archived note: (redacted)")
        with _RoutedServer(routes) as server:
            candidates = CurriculumWebSolver().solve(_context(server.url))
        self.assertEqual(candidates, [])

    def test_a_handler_exception_never_escapes(self):
        # robots.txt missing -> solve_backup_exposure raises WebHandlerError; detect's
        # fingerprint then finds nothing -> the adapter swallows it and reports nothing.
        with _RoutedServer({"/": (200, {}, b"<html>unknown app</html>")}) as server:
            candidates = CurriculumWebSolver().solve(_context(server.url))
        self.assertEqual(candidates, [])

    def test_non_proof_shaped_return_is_rejected(self):
        routes = _day1_routes()
        routes["/backups/app.bak"] = (200, {}, b"archived note: not-a-proof-token")
        with _RoutedServer(routes) as server:
            candidates = CurriculumWebSolver().solve(_context(server.url))
        self.assertEqual(candidates, [])

    def test_curriculum_day_falls_back_to_the_challenge_id(self):
        # Metadata omits curriculum_day; the day-01 ID still dispatches straight to the
        # day-1 handler (robots.txt first), never fingerprinting "/" on the clock.
        with _RoutedServer(_day1_routes(), http11=True) as server:
            context = _context(server.url, curriculum_day=None)
            self.assertEqual(context.curriculum_day, 1)
            candidates = CurriculumWebSolver().solve(context)
        self.assertEqual(candidates[0].answer, PROOF)
        self.assertNotIn("/", server.hits)
        self.assertEqual(server.hits[0], "/robots.txt")

    def test_curriculum_day_id_fallback_leaves_later_days_to_fingerprint(self):
        # A day > 10 is no known handler, so the property reports it but detect_and_solve
        # still fingerprints (unchanged behaviour); confirm the property, not a regression.
        context = TargetContext(
            challenge_id="web-exploitation-day-19-x/mastery", challenge={}, attempt={},
            answer_ids=("flag",), targets=(), http=scoped_http(()),
        )
        self.assertEqual(context.curriculum_day, 19)


class ScopeGuardTests(unittest.TestCase):
    def test_shim_rejects_an_off_scope_host(self):
        with _RoutedServer(_day1_routes()) as server:
            transport = _ScopedTransport(scoped_http([{"url": server.url}]))
            try:
                status, body, _ = transport.request(server.url + "/robots.txt")  # in scope
                self.assertEqual(status, 200)
                self.assertIn("Disallow", body)
                with self.assertRaises(HostNotAllowed):
                    transport.request("http://attacker.example/")
                with self.assertRaises(HostNotAllowed):
                    transport.request("http://127.0.0.1:1/off-port")  # host ok, port not listed
            finally:
                transport.close()

    def test_shim_follows_an_in_scope_redirect(self):
        routes = {
            "/go": (302, {"Location": "/dest"}, b""),
            "/dest": (200, {}, f"here: {PROOF}".encode()),
        }
        with _RoutedServer(routes, http11=True) as server:
            transport = _ScopedTransport(scoped_http([{"url": server.url}]))
            try:
                status, body, _ = transport.request(server.url + "/go")
                self.assertEqual(status, 200)
                self.assertIn(PROOF, body)
            finally:
                transport.close()

    def test_a_redirect_off_scope_is_not_followed(self):
        with _RoutedServer({"/leak": (200, {}, f"leaked: {PROOF}".encode())}) as off_scope:
            routes = _day1_routes()
            # The .bak now 302s to an out-of-scope host; the scoped shim must not chase it.
            routes["/backups/app.bak"] = (302, {"Location": off_scope.url + "/leak"}, b"")
            with _RoutedServer(routes) as target:
                candidates = CurriculumWebSolver().solve(_context(target.url))
            self.assertEqual(candidates, [])
            self.assertEqual(off_scope.hits, [])  # the off-scope host was never contacted

    def test_scope_patch_is_restored_after_the_run(self):
        from huntress_ctf.solvers.web import handlers

        original = handlers._request
        with _RoutedServer(_day1_routes()) as server:
            CurriculumWebSolver().solve(_context(server.url))
        self.assertIs(handlers._request, original)


class KeepAliveTests(unittest.TestCase):
    def test_keep_alive_reuses_one_connection(self):
        # A keep-alive target (like the live frameworks): the 3-request Day-1 flow rides a
        # single socket -- one TCP handshake on the clock, not three.
        with _RoutedServer(_day1_routes(), http11=True) as server:
            candidates = CurriculumWebSolver().solve(_context(server.url))
        self.assertEqual(candidates[0].answer, PROOF)
        self.assertEqual(len(server.hits), 3)
        self.assertEqual(server.connections, 1)

    def test_without_keep_alive_each_request_opens_its_own_connection(self):
        # The no-reuse baseline (HTTP/1.0): correctness holds, at one handshake per request.
        with _RoutedServer(_day1_routes(), http11=False) as server:
            candidates = CurriculumWebSolver().solve(_context(server.url))
        self.assertEqual(candidates[0].answer, PROOF)
        self.assertEqual(len(server.hits), 3)
        self.assertEqual(server.connections, 3)


class _XssServer:
    """Stands in for the Day-7 stored-XSS target: GET /api/clues, POST the feedback route
    (init then payload), and GET the receipt view, which shows the proof only once the
    out-of-band moderator has "visited" -- i.e. after `proof_after_polls` view GETs.
    """

    def __init__(self, *, proof_after_polls: int = 0):
        self.proof_after_polls = proof_after_polls
        self.view_gets = 0
        server_self = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _send(self, status: int, body: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/api/clues":
                    self._send(200, json.dumps({
                        "feature_route": "/feedback",
                        "moderator_data_route": "/internal/secret",
                        "receipt_route_template": "/api/receipt/{id}",
                    }).encode())
                elif self.path == "/feedback/1":
                    server_self.view_gets += 1
                    if server_self.view_gets > server_self.proof_after_polls:
                        self._send(200, f"receipt: {PROOF}".encode())
                    else:
                        self._send(200, b"pending")
                else:
                    self._send(404, b"not found")

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                self._send(200, json.dumps({"id": 0}).encode())  # actual_id = 0 + 1 = 1

            def log_message(self, *args: Any) -> None:
                pass

        self._handler = _Handler

    def __enter__(self) -> "_XssServer":
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        return self

    def __exit__(self, *exc: Any) -> None:
        self.server.shutdown()
        self.server.server_close()


class StoredXssPollTests(unittest.TestCase):
    def test_receipt_already_present_returns_without_sleeping(self):
        # Check-first: the proof is there on the first view GET, so the handler returns at
        # once -- no leading sleep, well under the old 1.5 s-per-attempt interval.
        with _XssServer(proof_after_polls=0) as server:
            started = time.monotonic()
            proof = handlers.solve_stored_xss(server.url)
            elapsed = time.monotonic() - started
        self.assertEqual(proof, PROOF)
        self.assertLess(elapsed, 1.0)

    def test_poll_stops_at_the_wall_budget(self):
        # The moderator never posts a receipt: the handler gives up at the budget rather
        # than running the full attempt count, so a slow bot cannot blow the race deadline.
        with _XssServer(proof_after_polls=10_000) as server:
            started = time.monotonic()
            with self.assertRaises(handlers.WebHandlerError):
                handlers.solve_stored_xss(server.url, poll_attempts=10_000,
                                          poll_interval=0.02, poll_budget_s=0.3)
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 2.0)


if __name__ == "__main__":
    unittest.main()
