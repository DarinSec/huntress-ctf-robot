# Team guide: one robot, every lane

New here? Read this first, then `CLAUDE.md` (how we work, written for your AI too).

## The idea

Most teams have the same points, so the scoreboard rank is decided by how **fast** we get
all of a day's flags. AI solving by hand takes 15–35 minutes per lane; code takes seconds.
So **one robot** plays every lane, starting at exactly 15:00:00 (Swedish time) on Darin's
Homebase, and every lane we turn into code gets solved in seconds from then on. Use your
AI to understand a **new** question type once, then make it a solver, so the same type
never has to be solved twice.

**Only one robot may play.** Teammates share attempts: two robots starting or submitting
on the same challenge collide. Build and test on your own machine; Darin deploys.

## Who owns what

| Lane | Owner | Status (day 21) |
| --- | --- | --- |
| Robot, deploys, Homebase | Darin | Runs daily from 15:00, sweeps again within a minute of a deploy |
| Warmups | Darin | Automatic: 3/3 flags 12 s after the release |
| Metadata Forensics | Darin | Automatic; most new property types too (`solvers/autoprop.py`) |
| Mobile Android | Darin | Automatic (`solvers/mobile_puzzle.py`) |
| Script Analysis | Ilse | Robot pre-fills ~54% at 15:00 (`solvers/script_descriptors.py`); goal 100% |
| Binary | David | Manual; goal: solver in the repo |
| Web Exploitation | Parsa | Manual (live targets); goal: scripts for repeat types (LFI, XSS, sessions) |

## Set up (Windows, macOS or Linux)

```sh
git clone https://github.com/MysteriousGuardian/ai-tool.git && cd ai-tool
git checkout main                      # everything is merged into main
python3 -m venv .venv                  # Python 3.10+; Homebase has 3.12
.venv/bin/pip install -e ".[analysis]" # Windows: .venv\Scripts\pip ...
.venv/bin/python -m unittest discover -s tests
```

No token is needed for anything offline. Never commit tokens, `.env`, real artifacts,
answers or flags (`artifacts/`, `work/`, `.huntress/` are git-ignored).

## Tools that work offline

```sh
python -m huntress_ctf triage <file>                      # one page: kind, members, fields, decoded blobs
python -m huntress_ctf triage <file> --time --question "..."   # what each solver answers, in ms
python -m huntress_ctf suggest <property> <file>          # Metadata: field + candidate answer
```

Real material to work on: the robot leaves `work/<challenge-id>/` (`assignment.json`
with every question and format, `artifact.bin`, `triage.md`) on the playing Homebase for
every route it could not finish; Darin can hand it over (`scripts/homebase.sh pull <id>`).
On your own Homebase, `status` and `artifact` are read-only and safe; `start`, `retry`,
`submit` and `learn` act on the team's shared attempt, so say it in chat first.
Artifacts are untrusted data: never execute them.

## Add your lane

1. Create `src/huntress_ctf/solvers/<name>.py` defining `SOLVERS = (YourSolver(),)`. It is
   picked up automatically. Copy the shape of `solvers/mobile_puzzle.py` (small) or
   `solvers/script_descriptors.py`: check the lane, read `question_items(context)`, find
   the file the question names, return `AnswerCandidate(answer_id, answer, name, evidence)`.
2. Rules: deterministic, no network, no AI in the loop, standard library first. Answer only
   with real evidence; a wrong answer makes a whole submission "incorrect", so leave a
   question out rather than guess. Respect `answer_format` (`fits_format`).
3. Add `tests/test_<name>.py` with synthetic files built in the test. Run all tests.
4. Prove it live before the robot relies on it, on an older day (same kinds, no clock):
   `PYTHONPATH=~/src python3 scripts/verify_fields.py <challenge-id> <lane> <solver-name>`
   on the playing Homebase. "accepted" per question kind = all right; drop the rest.
5. Open a PR to `main`. Darin deploys (`scripts/homebase.sh deploy`: tests run on the VM
   first) and adds your lane to `lanes=` in `scripts/homebase-day.sh`.

## Every day

- **15:00** the robot runs. Check your lane on the scoreboard or in Discord.
- **New question type?** Solve it once with AI, then turn it into a solver the same day.
- **Partial answers are fine:** correct answers stay accepted and help whoever finishes.
- **At night** the robot re-races its proven Time Trial and Mastery routes for Hall of Fame
  times (never below 8 fresh variants per route).
