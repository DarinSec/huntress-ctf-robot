"""Per-solver watchdog and the race's overall solve deadline (ROBUSTNESS.md, workstream 1).

`try/except` catches a crash, not a hang: a parser that loops on a never-seen file used to
freeze the whole sweep or race, and on the clock a crash in one solver ended the race. Every
solver now runs under a wall-clock budget. One that overruns is abandoned, one that raises is
reported, and the other solvers' answers still go out.

- fork (Linux, the playing Homebase): each solver runs in its own forked child, up to one per
  core at once. The child shares the context copy-on-write, so nothing is pickled in; only its
  candidates come back. An overrun is killed. Day 25 Binary TT (12 solvers, 35.7 MB): 1277 ms
  this way against 1213 ms in-process. Warm-up stays in the parent, before the clock, so every
  child inherits warm imports and regex caches.
- No fork (Windows): each solver runs in a daemon thread instead. An overrun is abandoned (a
  thread cannot be killed) but the run goes on.
- Forking a multi-threaded process (daily runs families in threads) copies every lock as it is
  at that instant; a lock another thread held then is held forever in the child. CPython resets
  the import and logging locks after fork, and the child gets fresh stdout/stderr on /dev/null
  (solver prints there were lost anyway), so the remaining risk is small, and its worst case is
  this module's normal one: that child times out and only its own answers are lost. Python's
  "multi-threaded, use of fork()" DeprecationWarning is filtered for that reason.
- HUNTRESS_WATCHDOG=off: the old in-process loop, still crash-isolated, for debugging.
  HUNTRESS_SOLVER_BUDGET=<seconds> overrides the per-solver budget.
- Memory (ROBUSTNESS.md workstream 4): a forked solver may grow SOLVER_MEMORY_MB past its size
  at the fork (HUNTRESS_SOLVER_MEMORY_MB; 0 = no ceiling). One that reaches it gets MemoryError,
  reported as crashed, and the robot goes on. Each child also offers itself to the OOM killer
  first (oom_score_adj 1000), so when the machine as a whole runs out, a solver dies, not the
  robot. Thread and off modes have no per-solver ceiling (a limit there is process-wide).

On the clock, `race_deadline()` turns the attempt's deadline into one overall cap: no solver
runs past it minus SUBMIT_MARGIN_S, so the race always reaches submit-or-fail in time.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import multiprocessing
from multiprocessing.connection import wait
import os
import sys
import threading
import time
from typing import Any, Callable, Sequence
import warnings

warnings.filterwarnings("ignore", message=r"This process \(pid=\d+\) is multi-threaded, use of fork\(\)",
                        category=DeprecationWarning)

# Untimed per-solver budget. The slowest real solve so far is ~25 s (Day 22 Binary Mastery,
# 1584 .NET questions), so 90 s never cuts a working solver and still ends a hang.
SOLVER_BUDGET_S = 90.0
# On the clock: stop solving this long before the server deadline, so the submit lands in time.
SUBMIT_MARGIN_S = 3.0
# A solver always gets at least this long, even when the deadline is close.
MIN_BUDGET_S = 0.5
# A deadline further away than this is not a race deadline (a skewed or odd field).
MAX_DEADLINE_AHEAD_S = 24 * 3600
# A forked solver's memory ceiling above its size at the fork. A real solve adds far less (Day 25
# Binary Mastery: ~900 MB for all 12 solvers together, in one process), so this only stops a
# runaway: a forged size or a bomb some path still reads whole.
SOLVER_MEMORY_MB = 4096


@dataclass(frozen=True)
class Outcome:
    """What happened to one solver: ok, timeout, crashed or skipped (the deadline came first)."""

    solver: str
    status: str
    seconds: float
    detail: str = ""

    def note(self) -> str:
        return f"watchdog: {self.solver} {self.status} after {self.seconds:.1f} s" + (
            f" ({self.detail})" if self.detail else "")

    def report(self, stage: str) -> dict[str, Any]:
        """This outcome for the sweep summary's safe-mode block; `stage` is warm-up or race."""
        return {"stage": stage, "solver": self.solver, "status": self.status,
                "seconds": round(self.seconds, 1), "detail": self.detail}


def solver_name(solver: Any) -> str:
    return getattr(solver, "name", None) or type(solver).__name__


def default_budget() -> float:
    try:
        return max(MIN_BUDGET_S, float(os.environ.get("HUNTRESS_SOLVER_BUDGET", SOLVER_BUDGET_S)))
    except ValueError:
        return SOLVER_BUDGET_S


def memory_headroom() -> int:
    """Bytes a forked solver may grow past its size at the fork; 0 means no ceiling."""
    try:
        return max(0, int(os.environ.get("HUNTRESS_SOLVER_MEMORY_MB", SOLVER_MEMORY_MB))) << 20
    except ValueError:
        return SOLVER_MEMORY_MB << 20


def cap_memory(headroom: int) -> None:
    """In a forked child: be the OOM killer's first choice, and grow at most `headroom` bytes.

    RLIMIT_AS counts address space, which the child inherits from the parent at the fork, so
    the limit is the current size plus the headroom. Best effort: no /proc or resource module
    (Windows, macOS) leaves the budget's timeout as the only bound.
    """
    try:
        with open("/proc/self/oom_score_adj", "w", encoding="ascii") as score:
            score.write("1000")
    except OSError:
        pass
    if headroom <= 0:
        return
    try:
        import resource
        with open("/proc/self/status", encoding="ascii") as status:
            size = next(int(line.split()[1]) * 1024 for line in status if line.startswith("VmSize:"))
        _, hard = resource.getrlimit(resource.RLIMIT_AS)
        limit = size + headroom if hard == resource.RLIM_INFINITY else min(size + headroom, hard)
        resource.setrlimit(resource.RLIMIT_AS, (limit, hard))
    except (ImportError, OSError, ValueError, StopIteration):
        pass


def race_deadline(deadline: str | None, now: Callable[[], float] = time.time) -> float | None:
    """The attempt's ISO deadline as a time.monotonic() cap, SUBMIT_MARGIN_S early; None when
    there is no usable deadline. A deadline already past (clock skew) is no reason to stay
    silent: the server decides, so the plain per-solver budget applies."""
    if not deadline:
        return None
    try:
        ends = datetime.fromisoformat(str(deadline).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None
    left = ends - now() - SUBMIT_MARGIN_S
    if not 0 < left < MAX_DEADLINE_AHEAD_S:
        return None
    return time.monotonic() + left


def run_solvers(
    solvers: Sequence[Any], context: Any, *, budget: float | None = None, deadline: float | None = None,
    mode: str | None = None, parallel: int | None = None, memory: int | None = None,
) -> tuple[list[Any], list[Outcome]]:
    """Every solver's candidates (in solver order) and one Outcome per solver.

    `budget` caps each solver (default SOLVER_BUDGET_S); `deadline` (time.monotonic()) caps
    them all. `mode` is "fork", "thread" or "off" (default: HUNTRESS_WATCHDOG, else fork where
    the platform has it). `memory` is a forked solver's ceiling in bytes (memory_headroom()).
    """
    budget = default_budget() if budget is None else budget
    memory = memory_headroom() if memory is None else memory
    mode = mode or os.environ.get("HUNTRESS_WATCHDOG") or (
        "fork" if "fork" in multiprocessing.get_all_start_methods() else "thread")
    if mode == "off":
        return _in_process(solvers, context)
    if mode == "fork":
        return _forked(solvers, context, budget, deadline, parallel or os.cpu_count() or 1, memory)
    return _threaded(solvers, context, budget, deadline)


def _cap(began: float, budget: float, deadline: float | None) -> float:
    """When a solver started at `began` must be done."""
    ends = began + budget
    if deadline is not None:
        ends = min(ends, max(deadline, began + MIN_BUDGET_S))
    return ends


def _in_process(solvers: Sequence[Any], context: Any) -> tuple[list[Any], list[Outcome]]:
    candidates: list[Any] = []
    outcomes = []
    for solver in solvers:
        began = time.monotonic()
        try:
            candidates.extend(solver.solve(context))
            outcomes.append(Outcome(solver_name(solver), "ok", time.monotonic() - began))
        except Exception as exc:  # A crash is a finding, not the end of the run.
            outcomes.append(Outcome(solver_name(solver), "crashed", time.monotonic() - began,
                                    f"{type(exc).__name__}: {exc}"))
    return candidates, outcomes


def _child(solver: Any, context: Any, conn: Any, memory: int = 0) -> None:
    # Never touch the inherited streams: another thread may have held their lock at the fork.
    sys.stdout = sys.stderr = open(os.devnull, "w")
    cap_memory(memory)
    try:
        result: tuple[str, Any] = ("ok", list(solver.solve(context)))
    except MemoryError:
        result = ("crashed", f"MemoryError: past the {memory >> 20} MB memory ceiling")
    except BaseException as exc:  # noqa: BLE001 - everything goes back to the parent as a report
        result = ("crashed", f"{type(exc).__name__}: {exc}")
    try:
        conn.send(result)
    except Exception as exc:  # An unpicklable candidate is a crash too.
        conn.send(("crashed", f"result could not be sent back: {type(exc).__name__}: {exc}"))
    conn.close()


def _forked(
    solvers: Sequence[Any], context: Any, budget: float, deadline: float | None, parallel: int, memory: int = 0,
) -> tuple[list[Any], list[Outcome]]:
    fork = multiprocessing.get_context("fork")
    results: list[list[Any]] = [[] for _ in solvers]
    outcomes: list[Outcome | None] = [None] * len(solvers)
    waiting = list(range(len(solvers)))
    running: dict[Any, tuple[int, Any, float]] = {}  # parent end -> (index, process, began)

    def finish(conn: Any, status: str, detail: str = "") -> None:
        index, process, began = running.pop(conn)
        # Its answer (or report) is in hand, so a child still alive has nothing left to give:
        # kill it rather than wait. One that answered may still be held open by a thread its
        # solver started, and waiting for that would put up to a second on the race clock.
        if process.is_alive():
            process.kill()
        process.join(1)
        conn.close()
        outcomes[index] = Outcome(solver_name(solvers[index]), status, time.monotonic() - began, detail)

    try:
        while waiting or running:
            while waiting and len(running) < max(1, parallel):
                now = time.monotonic()
                if deadline is not None and now >= deadline:
                    for index in waiting:
                        outcomes[index] = Outcome(solver_name(solvers[index]), "skipped", 0.0,
                                                  "the race deadline came first")
                    waiting.clear()
                    break
                index = waiting.pop(0)
                parent, child = fork.Pipe(duplex=False)
                process = fork.Process(target=_child, args=(solvers[index], context, child, memory), daemon=True)
                process.start()
                child.close()
                running[parent] = (index, process, now)
            if not running:
                break
            now = time.monotonic()
            ends = {conn: _cap(began, budget, deadline) for conn, (_, _, began) in running.items()}
            for conn in wait(list(running), timeout=max(0.0, min(ends.values()) - now)):
                try:
                    status, payload = conn.recv()
                except (EOFError, OSError):
                    _, process, _ = running[conn]
                    process.join(1)
                    finish(conn, "crashed", f"the solver process exited with code {process.exitcode}")
                    continue
                if status == "ok":
                    results[running[conn][0]] = payload
                    finish(conn, "ok")
                else:
                    finish(conn, "crashed", payload)
            now = time.monotonic()
            for conn in [conn for conn in running if now >= ends[conn]]:
                finish(conn, "timeout", "killed")
    finally:
        for conn in list(running):  # Never leave a child behind (KeyboardInterrupt, a bug here).
            finish(conn, "timeout", "killed while stopping")
    return [candidate for found in results for candidate in found], [o for o in outcomes if o]


def _threaded(
    solvers: Sequence[Any], context: Any, budget: float, deadline: float | None,
) -> tuple[list[Any], list[Outcome]]:
    candidates: list[Any] = []
    outcomes = []
    for solver in solvers:
        began = time.monotonic()
        if deadline is not None and began >= deadline:
            outcomes.append(Outcome(solver_name(solver), "skipped", 0.0, "the race deadline came first"))
            continue
        box: dict[str, Any] = {}

        def work(solver: Any = solver, box: dict[str, Any] = box) -> None:
            try:
                box["found"] = list(solver.solve(context))
            except BaseException as exc:  # noqa: BLE001
                box["error"] = f"{type(exc).__name__}: {exc}"

        thread = threading.Thread(target=work, name=f"solver-{solver_name(solver)}", daemon=True)
        thread.start()
        thread.join(max(0.0, _cap(began, budget, deadline) - began))
        spent = time.monotonic() - began
        if thread.is_alive():
            outcomes.append(Outcome(solver_name(solver), "timeout", spent, "abandoned (a thread cannot be killed)"))
        elif "error" in box:
            outcomes.append(Outcome(solver_name(solver), "crashed", spent, box["error"]))
        else:
            candidates.extend(box.get("found", ()))
            outcomes.append(Outcome(solver_name(solver), "ok", spent))
    return candidates, outcomes
