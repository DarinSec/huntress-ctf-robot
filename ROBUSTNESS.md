# Robustness plan: the robot must never freeze on something it hasn't seen

**Owner: Ilse.** Overarching, long-running track — pick a workstream, branch, PR to `main`.
Coordinate with Darin (robot/deploys/Homebase). Written 25 Oct 2026.

## The goal in one line

A never-seen input (a new encoding, a weird live target, a malformed binary, a new question
type) must **degrade to a clean "no answer", never hang.** On the timed clock a hang = a lost
flag and a lost Hall of Fame time for the whole team. We win by always finishing: submit what
we proved, fail fast on the rest, and keep the other lanes moving.

## What already protects us (don't redo these — build on them)

- **Decoders** (`decoders.py`): `MAX_LAYER_DEPTH=5`, `MAX_NODES=64`, `MAX_INFLATED=4 MiB`.
- **Containers** (`containers.py`): `MAX_MEMBERS=5000`, `MAX_TOTAL_BYTES=256 MiB`, `MAX_DEPTH=3`
  — decompression-bomb guards, CRC-checked.
- **Web** (`solvers/web/handlers.py`): `DEFAULT_TIMEOUT=10 s` per request, poll budgets
  (e.g. `poll_budget_s=18`), scoped + keep-alive transport.
- **Fastpath**: `TARGET_READY_BUDGET_S=120` for a preparing web target (off the clock), and
  the registry swallows a solver that fails to **import**.

The hole: all of these bound *individual* operations. Nothing bounds **CPU-bound work** (an
infinite / near-infinite loop inside a parser on a novel file) or the **total** time of a
solve. `try/except` catches a crash, not a hang. That is where a freeze comes from.

## Workstreams (priority order — #1 is the big freeze-preventer)

### 1. Global per-solver watchdog + overall solve deadline  ← start here
Every solver call runs under a hard wall-clock cap; if it blows it, abandon that solver and
keep going with the rest. On the timed path, enforce a single overall deadline so we always
reach submit-or-fail before the server clock expires.
- Design note: solvers run in threads (`daily` runs families per-thread), and Python can't
  kill a thread, so `signal.alarm` won't do. Options to weigh: run each solver in a
  worker **subprocess** with `future.result(timeout=...)` (hard kill, clean isolation, some
  IPC cost), **or** thread a cooperative `deadline` into `SolveContext` that long loops
  check. Prefer the subprocess/hard-timeout route for true hang-immunity; cooperative
  deadlines as a cheap complement.
- Acceptance: a synthetic solver that loops forever is abandoned after its budget, the sweep
  finishes, and every other solver still runs and submits. Add a test with a deliberately
  hanging fake solver.

### 2. Budgets for the new web prober / crawler / fuzzer
The merged `handlers.py` added an autonomous prober, deep crawling, and dynamic form
fuzzing. Per-request timeout is 10 s, but hundreds of requests can still blow the 120 s race
deadline. Add an **overall per-target wall-clock budget**, a **max request count**, and
bounded **crawl depth/breadth**; stop early the moment a proof is found.
- Acceptance: against a synthetic "maze" server (many links/forms, no proof), the prober
  stops at its budget and returns nothing, well under the deadline.

### 3. Fuzz every lane's parsers for hangs and uncaught errors
Feed truncated / malformed / adversarial / novel-format inputs to the metadata, binary,
script and warmup solvers. Any input that hangs or raises an *uncaught* exception is a bug:
fix it to fail fast to `[]`. Build a reusable fuzz harness (random + mutated real-shaped
inputs) that runs each solver under a per-input timeout and asserts none hang or crash.
- Acceptance: the harness runs N inputs/solver in CI; zero hangs, zero uncaught exceptions.

### 4. Resource ceilings
A memory cap per solve so a novel huge artifact can't OOM the sweep; confirm every
decode/parse path honours size caps end to end (not just the entry point).

### 5. Observability so a slowdown surfaces before it freezes live
Print per-solver timings in the sweep; add a "slowest solvers today" line; a corpus test
that **fails** if any solver exceeds its budget. A creeping regression then shows up in a
PR, not at 14:00 on release day.

### 6. Safe-mode sweep
One misbehaving solver/lane must never take down the whole sweep. Workstream #1's watchdog
gives this at runtime; make the sweep **report** which solver/lane was skipped and why, so a
new-day problem is visible immediately and the other flags still land.

## How to work
- Branch per workstream (`robust/watchdog`, `robust/web-budgets`, `robust/parser-fuzz`, …),
  PR to `main`. Keep solvers deterministic and in the millisecond range; **synthetic
  fixtures only**, never commit real artifacts/answers.
- The release-day priority is still a fast new-type parser (Metadata/Warmups Mastery is the
  slow flag). This track is the safety net under all of that: it buys time by guaranteeing
  the robot never sits frozen while the clock runs.
