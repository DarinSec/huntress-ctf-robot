#!/usr/bin/env python3
"""What the robot answers on a work folder, offline (no network, nothing submitted).

  PYTHONPATH=src python3 scripts/solve_offline.py work/<challenge-id-folder> [--answers out.json]
  python3 -I scripts/solve_offline.py <folder> --src src --show "machine|zip"

Reads assignment.json, artifact.bin and any delivery-N-* files that `prepare` (or the robot)
wrote, runs every solver exactly as the race does, and prints per question kind how many
questions are answered, so a new day's unanswered kinds stand out. The kind of an ID is the
ID without its set prefix, day number, digits and hex tokens ("set3.d24_analysis_x_2" ->
"analysis_x").

A kind with no answer needs code. A kind that is answered but was rejected needs the right
convention instead, and `--show <regex>` prints the values of the kinds it matches, so a
wrong one is visible without spending a variant (day 23: the zip member names were stored
in central-directory order where the service wanted them sorted). `--src` makes the robot
importable without PYTHONPATH, so this runs under `-I`, including piped over ssh
(`scripts/homebase.sh gaps <id> [regex]` does exactly that).
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys

if "--src" in sys.argv:  # Before the robot is imported, so -I can replace PYTHONPATH.
    sys.path.insert(0, sys.argv[sys.argv.index("--src") + 1])

from huntress_ctf.autopilot import build_context, select_candidates  # noqa: E402
from huntress_ctf.containers import Member  # noqa: E402
from huntress_ctf.solvers import LOAD_ERRORS, SOLVERS  # noqa: E402
from huntress_ctf.solvers.base import question_items  # noqa: E402
from huntress_ctf.state import AttemptState  # noqa: E402


def kind(answer_id: str) -> str:
    local = answer_id.split(".", 1)[1] if re.match(r"set\d+\.", answer_id) else answer_id
    local = re.sub(r"^d\d\d_", "", local)
    local = re.sub(r"-[0-9a-f]{6}-", "-", local)
    return re.sub(r"[_-]\d+$", "", local)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("folder", type=Path)
    parser.add_argument("--answers", type=Path, help="Write the selected answers as JSON here")
    parser.add_argument("--show", help="Regex: also print the answers of the kinds it matches")
    parser.add_argument("--src", help="The robot's src/ directory, for running under -I")
    args = parser.parse_args(argv)
    saved = json.loads((args.folder / "assignment.json").read_text(encoding="utf-8"))
    challenge, attempt = saved.get("challenge") or {}, saved.get("attempt") or {}
    deliveries = sorted(args.folder.glob("delivery-*"), key=lambda path: int(path.name.split("-")[1]))
    artifact = (args.folder / "artifact.bin").read_bytes()
    extra = tuple(Member(f"delivery {path.name.split('-')[1]}: {path.name.split('-', 2)[2]}", path.read_bytes())
                  for path in deliveries) if len(deliveries) > 1 else ()
    answer_ids = AttemptState.parse(attempt).answer_ids
    context, _ = build_context(str(challenge.get("id") or args.folder.name), challenge, attempt, artifact,
                               args.folder / "artifact.bin", answer_ids, None, extra)
    for error in LOAD_ERRORS:
        print(f"solver module not loaded: {error}")
    candidates = []
    for solver in SOLVERS:
        try:
            found = solver.solve(context)
        except Exception as exc:  # A crash is a finding to report, not a reason to stop.
            print(f"{getattr(solver, 'name', solver)} crashed: {type(exc).__name__}: {exc}")
            continue
        if found:
            print(f"{getattr(solver, 'name', solver)}: {len(found)} candidates")
        candidates += found
    notes: list[str] = []
    selected, conflict = select_candidates(candidates, answer_ids, notes)
    answered = {candidate.answer_id for candidate in selected}
    total, done = Counter(kind(i) for i in answer_ids), Counter(kind(i) for i in answered)
    print(f"\n{len(answered)}/{len(answer_ids)} answered" + ("; CONFLICT between solvers" if conflict else ""))
    for name, count in sorted(total.items(), key=lambda item: (done[item[0]] == item[1], item[0])):
        mark = "ok " if done[name] == count else "-- "
        print(f"  {mark}{done[name]:5}/{count:<5} {name}")
    for note in notes[:10]:
        print(f"note: {note}")
    if args.show:
        wanted = re.compile(args.show)
        files = {item.answer_id: item.artifact for item in question_items(context)}
        values = {candidate.answer_id: candidate.answer for candidate in selected}
        print(f"\n== answers of the kinds matching {args.show!r}")
        for answer_id in answer_ids:
            if not wanted.search(kind(answer_id)):
                continue
            value = json.dumps(values[answer_id]) if answer_id in values else "(no answer)"
            print(f"  {answer_id:44} {files.get(answer_id) or '':34} {value[:160]}")
    if args.answers:
        args.answers.write_text(json.dumps({c.answer_id: c.answer for c in selected}, indent=1, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
