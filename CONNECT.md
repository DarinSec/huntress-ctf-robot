# Connect from your own Windows computer

The robot uses a paired Game Master token for the direct HTTPS service. Its first live check is read-only: it requests the API schema, challenge list, and optionally the status of challenges you select.

## 1. Pair through authenticated Homebase

If you already have a token, use that token. The contest guide says an ordinary pairing request cannot reveal an existing lost token; recovery requires an explicit reset through CourseStack.

For a first pairing, open your authenticated Homebase terminal and run the guide's create-only request there:

```sh
curl -fsS -X POST 'http://10.0.0.219/huntress-ctf-proxy?op=pair'
```

Run this yourself in the Homebase terminal, where you can read the returned token privately. Keep the token in a local secret manager. Do not paste its response into AI chat, a shared terminal log, screenshots, or this repository. This command belongs inside Homebase, where CourseStack provides your identity.

## 2. Run the connection check locally

Open PowerShell in the project folder and run:

```powershell
.\scripts\huntress.ps1 --base-url https://2026.huntress.ctf.games --prompt-token doctor --output integration-data
```

Enter your paired token at the hidden terminal prompt. The token is used for this process and is not saved by the robot. If the terminal cannot hide input, the command stops before reading it. A credential already supplied in `HUNTRESS_GM_TOKEN` can be used by omitting `--prompt-token`.

The launcher uses the project's virtual environment when present, then the bundled Python available on this computer, then an ordinary Python installation. A WindowsApps alias is not used. It adds this workspace's source directory to the child process's import path.

The explicit URL above selects the direct HTTPS service even if `HUNTRESS_GM_URL` was previously set to the Homebase proxy.

## 3. Inspect the report

Each run creates a separate folder under the ignored `integration-data/` directory:

| File | Content |
| --- | --- |
| `report.json` | Each check's result and the scope of verification |
| `schema.json` | Actual OpenAPI response, with recognized private values redacted |
| `challenges.json` | Actual challenge list, with recognized private values redacted |
| `status-001.json`, etc. | Optional actual status responses |

Responses with an unfamiliar structure are still captured so the integration can be adapted; the affected check is reported as failed. A transport or authentication failure has no response file for that operation. The command exits with zero only when every requested check passes.

This checks endpoint access and compatibility with the current local parsers. It does not verify start/submit behavior, artifact downloads, or awarded points. Captures can contain your team's public assignment data, IDs, and links even after redaction; the directory remains out of version control.

## 4. Capture mode-specific status

Read the real challenge IDs in `challenges.json`. To inspect existing attempts in any of the three modes, repeat `--challenge` with those IDs:

```powershell
.\scripts\huntress.ps1 --base-url https://2026.huntress.ctf.games --prompt-token doctor --output integration-data --challenge ACTUAL_SINGLE_ID --challenge ACTUAL_TRIAL_ID --challenge ACTUAL_MASTERY_ID
```

Replace the example IDs with real IDs from the live list. If a mode has no available challenge or current attempt, leave it out. The diagnostic never starts a challenge to manufacture a status sample.

Once captures exist locally, ask the coding agent to review the newest capture folder and adapt the client. Never send the token with that request. Any live solving run is performed separately with `solve ACTUAL_CHALLENGE_ID`; `--timed` explicitly requests timed play on routes supporting it.
