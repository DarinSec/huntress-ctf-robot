"""Per-target budgets for the web prober (ROBUSTNESS.md workstream 2).

The autonomous prober, the deep-form crawl, and the try-every-handler fallback can fire many
requests at one target. Each caps at DEFAULT_TIMEOUT, but hundreds in a row would blow the
race deadline. A `Budget` bounds a whole target: at most N requests inside a wall-clock
window. No real target is touched -- a local "maze" server on 127.0.0.1 answers every path
with links and a form and never a proof, so the prober churns until the budget stops it.
"""

from __future__ import annotations

import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from huntress_ctf.solvers.web import Budget, BudgetExhausted, TargetContext, scoped_http
from huntress_ctf.solvers.web.curriculum import CurriculumWebSolver

_MAZE_PAGE = (
    b"<html><body>Unknown Application"
    + b"".join(b'<a href="/node/%d">n%d</a>' % (i, i) for i in range(8))
    + b'<form action="/submit" method="POST"><input name="q"><textarea name="body"></textarea></form>'
    + b"</body></html>"
)


class _MazeServer:
    """Answers every GET and POST with the same linky, form-bearing page and never a proof,
    so the prober keeps finding more to try. `count` records every request served.
    """

    def __init__(self) -> None:
        self.count = 0
        self._lock = threading.Lock()
        server_self = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _serve(self) -> None:
                with server_self._lock:
                    server_self.count += 1
                body = b"{}" if self.path == "/api/clues" else _MAZE_PAGE
                self.send_response(404 if self.path == "/api/clues" else 200)
                self.send_header("Content-Type", "application/json" if self.path == "/api/clues" else "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                self._serve()

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                self._serve()

            def log_message(self, *args: Any) -> None:
                pass

        self._handler = _Handler

    def __enter__(self) -> "_MazeServer":
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        return self

    def __exit__(self, *exc: Any) -> None:
        self.server.shutdown()
        self.server.server_close()


def _context(url: str, budget: Budget) -> TargetContext:
    targets = ({"url": url},)
    return TargetContext(
        challenge_id="web-exploitation-day-19-maze",  # > 10: no direct handler, so it probes.
        challenge={}, attempt={}, answer_ids=("flag",), targets=targets,
        http=scoped_http(targets, budget=budget),
    )


class BudgetTests(unittest.TestCase):
    def test_the_request_count_is_capped(self):
        budget = Budget(max_requests=3, wall_s=100.0)
        self.assertTrue(all(budget.charge() > 0 for _ in range(3)))
        with self.assertRaises(BudgetExhausted):
            budget.charge()

    def test_the_wall_clock_is_capped(self):
        budget = Budget(max_requests=1000, wall_s=0.0)
        with self.assertRaises(BudgetExhausted):
            budget.charge()  # Nothing left the moment the clock starts.

    def test_reset_begins_a_fresh_allowance(self):
        budget = Budget(max_requests=1, wall_s=100.0)
        remaining = budget.charge()
        # (now + wall_s) - now can round a hair ABOVE wall_s when the sum crosses a binade
        # boundary: with a 100 s budget a monotonic clock in [412, 512) rounds up ~21% of the
        # time (0% outside such a band). A freshly booted Homebase sits in those low bands, so
        # without this tick the deploy's test gate fails on the VM's uptime, not on a defect.
        self.assertTrue(0 < remaining <= 100.0 + 1e-9)
        with self.assertRaises(BudgetExhausted):
            budget.charge()
        budget.reset()
        self.assertTrue(budget.charge() > 0)  # Charges again after the reset.

    def test_budget_exhausted_is_not_an_ordinary_exception(self):
        # The ported handlers wrap requests in `except Exception`; the stop signal must slip
        # past that, so it is a BaseException and not caught by handler code.
        self.assertTrue(issubclass(BudgetExhausted, BaseException))
        self.assertFalse(issubclass(BudgetExhausted, Exception))


class MazeTests(unittest.TestCase):
    def test_the_prober_stops_at_its_budget_and_reports_nothing(self):
        budget = Budget(max_requests=12, wall_s=30.0)
        with _MazeServer() as maze:
            began = time.monotonic()
            candidates = CurriculumWebSolver().solve(_context(maze.url, budget))
            elapsed = time.monotonic() - began
        self.assertEqual(candidates, [])  # No proof anywhere: never a guess.
        self.assertLessEqual(maze.count, 12)  # The cap is a hard ceiling on requests served.
        self.assertGreaterEqual(maze.count, 10)  # It really churned up to the budget.
        self.assertLess(elapsed, 30.0)  # Well under the race deadline.

    def test_the_time_budget_stops_the_prober(self):
        budget = Budget(max_requests=100000, wall_s=0.0)  # No time at all.
        with _MazeServer() as maze:
            candidates = CurriculumWebSolver().solve(_context(maze.url, budget))
        self.assertEqual(candidates, [])
        self.assertEqual(maze.count, 0)  # The first charge trips before any request is sent.


if __name__ == "__main__":
    unittest.main()
