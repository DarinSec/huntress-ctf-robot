# Huntress CTF Robot

A Python client and autonomous solver pipeline for Huntress CTF 2026. It can fetch an assignment, analyze its assigned artifact, submit supported answers, and interpret the Game Master's result. The client has no third-party runtime dependencies.

The current solver library supports explicit Base64, ROT13, hexadecimal, and 8-bit binary decoding tasks, plus assignments explicitly requesting a JSON answer map. It does **not yet solve arbitrary CTF challenges**, investigate live targets, or run the whole contest unattended.

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

## Configure live access

For the guided Windows workflow, including first pairing and a read-only connection check, see [CONNECT.md](CONNECT.md). The workspace launcher works with the Python runtime available on this computer:

```powershell
.\scripts\huntress.ps1 --base-url https://2026.huntress.ctf.games --prompt-token doctor --output integration-data
```

Pair through the authenticated Homebase flow described in [AGENTS.md](AGENTS.md). Enter the resulting token privately in the current PowerShell session; avoid putting its literal value in shell history, chat, screenshots, or files:

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
```

- `solve` is the autonomous entry point. It lists and selects the challenge, starts or reconnects, displays the public assignment, downloads the artifact, tries registered solvers, and submits supported answers.
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
| Mastery | Uses the exact answer IDs issued by start, submits supported answers separately, skips IDs already reported as accepted, and preserves partial progress. |

The robot reads the mode from explicit service fields. Answer count and deadlines are not used to guess a mode. Reconnecting does not reset a timer. A partial `accepted` result is not completion, including when `remaining` is zero. A pending result stops the run so the current attempt is preserved.

The Game Master can confirm completion; CourseStack is the official points ledger. This client does not directly inspect CourseStack, so it cannot independently confirm awarded points.

## Solving and attempt integrity

- Text decoders require a direct decoding instruction naming exactly one supported encoding and a single issued answer ID. Ambiguous, negative, or recognized multi-step instructions are skipped. This is a conservative heuristic, not a general understanding of every prompt.
- The JSON map strategy requires explicit instructions to use an answer map. Merely finding matching keys in an arbitrary file is insufficient.
- All candidates are collected before submission. Conflicting values for the same ID are skipped.
- The pipeline compares attempt IDs, artifact SHA-256, deadlines, modes, and answer IDs when the service supplies them. Known identity fields remain remembered when a later response omits them.
- Before every submission, status is checked again. If the current status omits an artifact hash, the assigned bytes are downloaded again and compared.
- These checks cannot eliminate the interval between checking and submitting when another teammate changes the attempt. The documented submit operation has no atomic attempt-ID condition.
- Transport failures never automatically repeat a POST: it may already have reached the server.
- Current response parsing supports explicit top-level fields and `attempt` / `current_attempt` wrappers. `answer_ids` must be an array of strings. History and examples do not define current attempt state. Unsupported or contradictory responses stop processing.
- Routes without issued answer IDs, including native CourseStack tasks, need additional integration.

## Artifacts and output

Default downloads are saved under ignored `artifacts/` with a sanitized challenge ID and full SHA-256 in the filename. Different variants are preserved. A repeated download of identical bytes reuses its file.

An explicit destination is supported:

```powershell
.\.venv\Scripts\python.exe -m huntress_ctf artifact CHALLENGE_ID --output artifacts\sample.bin
```

Existing explicit destinations require `--force` to overwrite. The current limits are 64 MiB per artifact, 4 MiB per JSON response, and 1 MiB for text solvers. Triage previews are bounded and escape terminal control characters. ZIP triage lists entries without extracting or executing them.

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

Coverage includes the three modes, partial and pending results, malformed responses, solver ambiguity, changed attempts and artifacts, preserved variants, token redaction, redirect rejection, request bodies, and transport failures.

## Code layout

- `client.py`: HTTP transport and documented Game Master operations.
- `state.py`: current attempt parsing and identity checks.
- `autopilot.py`: orchestration for one attempt.
- `solvers.py`: supported deterministic strategies.
- `artifacts.py`: file preservation and bounded previews.
- `display.py`: output redaction and escaping.
- `cli.py`: commands, configuration, and exit codes.
- `diagnostics.py`: read-only endpoint checks and redacted response capture.

Use `doctor` to obtain the real OpenAPI schema and response samples for available modes. The next integration step is to inspect those captures, adapt unsupported response shapes, and then add challenge-specific strategies using actual assigned artifacts.

