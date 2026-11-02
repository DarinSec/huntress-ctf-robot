# Huntress CTF Robot: usage

**Teammates: start with [TEAM.md](TEAM.md)** (roles, setup, how to add your lane).

A Python client and autonomous solver pipeline for Huntress CTF 2026. It can fetch an assignment, analyze its assigned artifact, submit supported answers, and interpret the Game Master's result. The client has no third-party runtime dependencies.

The current solver library supports explicit Base64, ROT13, hexadecimal, and 8-bit binary decoding tasks, assignments explicitly requesting a JSON answer map, and stacked encodings (Morse, binary, hex, decimal, Base32, Base64, ROT13/ROT47 in any order, e.g. Morse → hex → text) whose decoded text explicitly states the answer. It does **not yet solve arbitrary CTF challenges**, investigate live targets, or run the whole contest unattended.

## Requirements

- A working Python 3.10 or newer installation.
- A Huntress CTF 2026 account/enrollment for live use.
- A paired Game Master token for direct HTTPS access, or access to the Game Master proxy from Homebase.

Help and offline tests need no credentials. The transport and response handling follow the supplied contest guide; the live OpenAPI schema and actual contest responses still need to be checked before relying on live automation.

## Install for development

First check that `python --version` works. On Windows, an unusable WindowsApps alias must be replaced by a working Python installation or an explicit path to its executable.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m huntress_ctf --help
```

Activation is optional. Examples below use the virtual environment's Python directly. The installed `huntress-ctf` command provides the same interface.

For artifact analysis, `pip install -e ".[analysis]"` adds pefile and pyelftools. Android work uses jadx unpacked into the ignored `tools/jadx/` directory (requires Java 11+).

## Configure live access

For the guided Windows workflow, including first pairing and a read-only connection check, see [CONNECT.md](CONNECT.md). The workspace launcher works with the Python runtime available on this computer:

```powershell
.\scripts\huntress.ps1 --base-url https://2026.huntress.ctf.games --prompt-token doctor --output integration-data
```

Pair through the authenticated Homebase flow described in the organizer's `AGENTS.md` (not included in this repository). Enter the resulting token privately in the current PowerShell session; avoid putting its literal value in shell history, chat, screenshots, or files:

```powershell
$huntressSecret = Read-Host 'Game Master token' -AsSecureString
$env:HUNTRESS_GM_TOKEN = [System.Net.NetworkCredential]::new('', $huntressSecret).Password
Remove-Variable huntressSecret
```

The default base URL is `https://2026.huntress.ctf.games/`. From Homebase, the proxy can supply identity instead:

```powershell
$env:HUNTRESS_GM_URL = 'http://10.0.0.219/huntress-ctf-proxy'
```

The proxy path is preserved without a trailing slash, and the client does not inherit a bearer token when using this proxy. Tokens supplied to the client require HTTPS. Redirects are rejected.

Choose where timed runs execute by measuring: `bench --compare --pipeline --challenge ID` reports both routes and recommends the faster one. The robot is standard-library Python, so running it on Homebase only needs the `src/` folder: `PYTHONPATH=src python3 -m huntress_ctf --base-url http://10.0.0.219/huntress-ctf-proxy daily --timed` (set `HUNTRESS_STATE_DIR` so `hints.json` lives there too). Homebase time still costs credits.

To return to the default direct URL or clear credentials from this shell:

```powershell
Remove-Item Env:HUNTRESS_GM_URL -ErrorAction SilentlyContinue
Remove-Item Env:HUNTRESS_GM_TOKEN -ErrorAction SilentlyContinue
```

## Commands

Replace the example IDs and answer with values from the current assignment.

```powershell
.\.venv\Scripts\python.exe -m huntress_ctf list --day 1 --lane warmups
.\.venv\Scripts\python.exe -m huntress_ctf start CHALLENGE_ID
.\.venv\Scripts\python.exe -m huntress_ctf solve CHALLENGE_ID
.\.venv\Scripts\python.exe -m huntress_ctf solve CHALLENGE_ID --timed
.\.venv\Scripts\python.exe -m huntress_ctf status CHALLENGE_ID
.\.venv\Scripts\python.exe -m huntress_ctf artifact CHALLENGE_ID
.\.venv\Scripts\python.exe -m huntress_ctf submit CHALLENGE_ID ANSWER_ID ANSWER
.\.venv\Scripts\python.exe -m huntress_ctf retry CHALLENGE_ID
.\.venv\Scripts\python.exe -m huntress_ctf api-schema
.\.venv\Scripts\python.exe -m huntress_ctf doctor --output integration-data
.\.venv\Scripts\python.exe -m huntress_ctf bench --challenge CHALLENGE_ID --count 10
.\.venv\Scripts\python.exe -m huntress_ctf bench --compare --pipeline --challenge CHALLENGE_ID
.\.venv\Scripts\python.exe -m huntress_ctf daily --day 1
.\.venv\Scripts\python.exe -m huntress_ctf daily --timed
.\.venv\Scripts\python.exe -m huntress_ctf triage artifacts\sample.bin
.\.venv\Scripts\python.exe -m huntress_ctf triage artifacts\sample.bin --time --question "What URL does it contact?"
```

- `daily` solves every listed challenge untimed (only routes where an ordinary start cannot begin a timer) and prints a summary. `daily --timed` races only challenges whose solver already scored CORRECT (`.huntress/hints.json`).
- `triage` is offline: a one-page report (kind, unpacked members, metadata, IOCs, decoded blobs, stated answers) for any local file. `triage --time` instead prints what unpacking and each solver cost on the clock for that file (median ms over cold runs) and what a race would submit; use it to keep new solvers in the millisecond range.
- Unsolved runs write `work/<id>/` with the redacted assignment, the artifact, unpacked members (`.bin` suffix), and `triage.md`.
- `solve --capture` / `daily --capture` save redacted live responses under `integration-data/` after the run.
- The token can live in a git-ignored `.env` (`HUNTRESS_GM_TOKEN=...`, see `.env.example`); real environment variables win.

- `solve` is the autonomous entry point. Timed and untimed runs share one engine (`fastpath.py`): start → artifact → solve → one submission with all answers in one POST, then the full report. Untimed that is four requests (list, start, artifact, submit) plus a final status; `start` only reconnects, and the robot never retries on its own. Because `solve <id>` runs exactly the code that races, an untimed CORRECT also verifies the timed path, and an ordinary start on an older timed-by-default route is just as fast.
- `solve --timed` is for a requested timed run. List, status, route choice, solver warm-up (including the external ZIP reader), and connection setup happen before start; only start → artifact → solve → one submission run on the server clock, with garbage collection paused. A proven solver runs first and the rest are skipped when it answers everything. After a completed or expired attempt the race uses `retry` with `run_for_time` (`start` only reconnects); it refuses to start while scoring is pending, while a regular untimed attempt is active, or when no fresh timed variant remains. The full assignment, artifact SHA-256, evidence, final status, and a millisecond timing table (`start_sent_to_submit_response` is the client-side total) are printed after the submission response.
- `bench --challenge ID` is read-only (GET only): it times that challenge's status with a new connection per request vs one kept-alive connection, plus a few artifact downloads. `--compare` also benches the other documented route (direct HTTPS or the Homebase proxy) and recommends the faster one. `--pipeline` sends status and artifact GETs in one write and saves the verdict in `.huntress/network.json`: on only if the pair comes back in order *and* faster than two requests in a row.
- Pipelining: where that probe passed, a race sends start and the artifact GET in one write. The early bytes are used only when they match the start response's SHA-256; otherwise the artifact is fetched again with an ordinary GET, and pipelining is switched off for that route. `--no-pipeline` on `solve`/`daily` opts out. A POST is never repeated. Measured on 19 Oct 2026, the direct route answers a pipelined pair correctly but one request after the other, about 100–270 ms *slower* than two plain requests, so it stays off there.
- Server costs that shape the robot (19 Oct 2026): an authenticated request takes about 0.7 s from Sweden and 0.3 s from Homebase, almost all of it behind Cloudflare. `list` grows with its size: about 1 s for one day and lane, 4 s for a day, 80 s for every day. So `solve <id>` lists only the ID's own day and lane, `list` requests get a 180 s timeout, and untimed `daily` skips challenges the list marks as solved.
- `start` is a lower-level command that prints the assignment without solving it.
- `retry` is an explicit request for another variant. Use it after expiry or confirmed completion when another run is intended. The solver never retries automatically.
- `submit` sends one answer under its exact issued ID. Use `solve` for automatic assignment and artifact checks.
- `doctor` checks schema/list access and optionally existing statuses via repeated `--challenge ID`. `--output` preserves redacted response captures in a new directory. It never starts attempts, downloads artifacts, or submits answers. Zero means the requested read-only checks passed; gameplay integration remains unverified.
- `--prompt-token` reads a token privately in an interactive terminal for any command. It goes before the command and does not save credentials.
- `--base-url` and `--timeout` are global options and go before the command.

## The three modes

| Mode | Pipeline behavior |
| --- | --- |
| Single Solve | Works on the assigned task; checks the server's completion result. |
| Time Trial | Uses the server's deadline. On upgraded routes, `--timed` opts in; an ordinary start is untimed. Older routes may be timed by default. |
| Mastery | Uses the exact answer IDs issued by start, submits all supported answers in one POST, skips IDs already reported as accepted, and preserves partial progress. |

The robot reads the mode from explicit service fields. Answer count and deadlines are not used to guess a mode. Reconnecting does not reset a timer. A partial `accepted` result is not completion, including when `remaining` is zero. A pending result stops the run so the current attempt is preserved.

The Game Master can confirm completion; CourseStack is the official points ledger. This client does not directly inspect CourseStack, so it cannot independently confirm awarded points.

## Solving and attempt integrity

- Text decoders require a direct decoding instruction naming exactly one supported encoding and a single issued answer ID. Ambiguous, negative, or recognized multi-step instructions are skipped. This is a conservative heuristic, not a general understanding of every prompt.
- The JSON map strategy requires explicit instructions to use an answer map. Merely finding matching keys in an arbitrary file is insufficient.
- All candidates are collected before submission. Conflicting values for the same ID are skipped.
- The download is compared with the start response's SHA-256 before anything is solved, and the answers go out milliseconds later in one POST. The submission response is checked against the start response's identity fields (attempt ID, artifact SHA-256, deadline, mode, answer IDs).
- Untimed runs no longer re-check status before each answer or re-download when status omits a hash: as in a race, download and submit are milliseconds apart. A teammate changing the attempt inside that window is still possible; the documented submit operation has no atomic attempt-ID condition.
- Requests share one kept-alive HTTP(S) connection. Transport failures never automatically repeat a POST: it may already have reached the server. A GET that fails on a stale kept-alive connection is repeated once on a new connection, and a POST after more than 5 idle seconds opens a fresh connection first.
- Current response parsing supports explicit top-level fields and `attempt` / `current_attempt` wrappers. `answer_ids` must be an array of strings. History and examples do not define current attempt state. Unsupported or contradictory responses stop processing.
- Routes without issued answer IDs, including native CourseStack tasks, need additional integration.

## Artifacts and output

Default downloads are saved under ignored `artifacts/` with a sanitized challenge ID and full SHA-256 in the filename. Different variants are preserved. A repeated download of identical bytes reuses its file.

An explicit destination is supported:

```powershell
.\.venv\Scripts\python.exe -m huntress_ctf artifact CHALLENGE_ID --output artifacts\sample.bin
```

Existing explicit destinations require `--force` to overwrite. The current limits are 64 MiB per artifact, 4 MiB per JSON response, and 1 MiB for text solvers. Triage previews are bounded and escape terminal control characters. ZIP triage lists entries without extracting or executing them.

Encrypted ZIPs: the standard library decrypts ZipCrypto in pure Python at about 1 MB/s, close to a second per megabyte on a timed clock, and cannot read AES at all. When the encrypted entries total 32 KiB or more, or any entry is AES, the robot uses the Windows built-in `tar.exe` (bsdtar), 7-Zip, or `unzip` instead (about 40 ms for 1 MB, AES included). The archive bytes go to a private temporary file, the tool streams members to stdout (nothing is extracted to archive-named paths and nothing is executed), and every member must match the ZIP's own size and CRC-32; anything else falls back to the standard library.

Antivirus: Binary and Script Analysis artifacts are often real malware samples. Real-time protection may quarantine files in `artifacts/` or `work/<id>/members/` (or even command output that quotes suspicious script text), which makes those challenges fail or slow down. Whether to exclude those two folders is the player's own security decision.

Output redacts configured tokens and recognized private fields while retaining public answer-format instructions. Keep private artifacts and answers out of version control.

## Exit codes

For `solve` and `submit`:

| Code | Meaning |
| --- | --- |
| 0 | Game Master reports completion; verify points in CourseStack |
| 1 | Configuration, transport, response, or file error |
| 2 | Invalid command-line usage |
| 3 | Unresolved, partial, unavailable, or unsupported work |
| 4 | An answer was rejected |
| 5 | Attempt expired |
| 6 | Conflicting or invalid solver candidates |
| 7 | Scoring pending |
| 130 | Interrupted; check status before repeating a POST |

For other commands, zero means that the requested operation succeeded, not that a challenge was solved.

## Offline verification

The tests use synthetic artifacts and mocked service responses. They do not contact the contest, start timers, or require credentials.

```powershell
$env:PYTHONPATH = Join-Path (Get-Location) 'src'
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Coverage includes the three modes, partial and pending results, malformed responses, solver ambiguity, artifact hash mismatches, preserved variants, token redaction, redirect rejection, request bodies, transport failures, pipelining and its fallbacks, and the external ZIP reader.

## Code layout

- `client.py`: kept-alive HTTP transport and documented Game Master operations.
- `state.py`: current attempt parsing and identity checks.
- `autopilot.py`: shared attempt helpers (outcome codes, challenge lookup, candidate selection, solver context).
- `fastpath.py`: the one solve engine, timed and untimed, with only start, download, solve, and one submission on the clock; also `triage --time`.
- `network.py`: measured transport facts per route (pipelining verdicts), kept beside the hints.
- `solvers/`: deterministic strategies, one module per lane (`encoding.py`, `facts.py`), auto-discovered by `solvers/__init__.py`.
- `decoders.py`: strict layer decoders, chain replay, and answer-statement extraction.
- `containers.py`: in-memory ZIP (incl. ZipCrypto, and AES through an external reader), gzip, and tar unpacking with limits.
- `evidence.py`: metadata, IOC, and script-blob extraction (stdlib only).
- `hints.py`: proven solvers per challenge; `daily.py`: batch runs; `workspace.py`: triage reports and work folders; `config.py`: `.env` loading; `capture.py`: redacted response captures.

How the AI works in this repo (daily loop, lane routing, solver rules) is in [CLAUDE.md](CLAUDE.md). Heavy lanes have subagents in `.claude/agents/` (`ctf-binary`, `ctf-android`).
- `artifacts.py`: file preservation and bounded previews.
- `display.py`: output redaction and escaping.
- `cli.py`: commands, configuration, and exit codes.
- `diagnostics.py`: read-only endpoint checks, redacted response capture, and latency bench.

Use `doctor` to obtain the real OpenAPI schema and response samples for available modes. The next integration step is to inspect those captures, adapt unsupported response shapes, and then add challenge-specific strategies using actual assigned artifacts.

