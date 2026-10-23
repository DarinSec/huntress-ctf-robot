#!/usr/bin/env python3
"""What the robot answers for a saved work dir, kind by kind, offline.

    python3 -I scripts/answer_gaps.py <work dir> [--src DIR] [--show REGEX] [--solver NAME]

`daily` leaves work/<id>/ for every route it could not finish, but an unresolved route
names nothing, and an "incorrect" names the rejected kind only in the log of the resend
that followed it. This replays the saved assignment with the current solvers and prints
one line per question kind, grouped the way `learn` groups a resend, so the two read the
same: how many of the kind's questions the robot answers, and by which solver. Kinds
under "no answer from the robot" need code; `--show` prints the values of the matching
kinds, so a wrong convention is visible without spending a variant.

Offline: no network and no Game Master request. The saved bytes are untrusted data; this
only reads them, and so should you (never execute them).
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import re
import sys
import time


def _import_from(src: Path | None) -> None:
    """Import the robot from `src`, the repo beside this script, or the installed project."""
    for candidate in (src, Path(__file__).resolve().parents[1] / "src" if "__file__" in globals() else None):
        if candidate and (candidate / "huntress_ctf" / "__init__.py").exists():
            sys.path.insert(0, str(candidate))
            return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("work_dir", type=Path, help="work/<challenge-id>/ with assignment.json and artifact.bin")
    parser.add_argument("--src", type=Path, help="The robot's src/ directory (default: beside this script)")
    parser.add_argument("--show", help="Regex: print the answers of the kinds it matches")
    parser.add_argument("--solver", action="append", default=[], help="Only this solver (repeatable)")
    parser.add_argument("--artifact", type=Path, help="Assigned bytes (default: <work dir>/artifact.bin)")
    args = parser.parse_args(argv)

    _import_from(args.src)
    try:
        from huntress_ctf.autopilot import build_context, select_candidates
        from huntress_ctf.learn import MAX_KIND_REQUESTS, field_of, kind_of
        from huntress_ctf.solvers import SOLVERS
        from huntress_ctf.solvers.base import question_items
        from huntress_ctf.state import AttemptState, deliveries
    except ImportError as exc:
        print(f"The robot is not importable ({exc}); pass --src <repo>/src.", file=sys.stderr)
        return 2

    saved = json.loads((args.work_dir / "assignment.json").read_text(encoding="utf-8-sig"))
    challenge, attempt = saved["challenge"], saved["attempt"]
    challenge_id = challenge["id"]
    state = AttemptState.parse(attempt)
    if not state.answer_ids:
        print("The saved assignment issued no answer_ids.", file=sys.stderr)
        return 1
    artifact = (args.artifact or args.work_dir / "artifact.bin").read_bytes()
    listed = deliveries(attempt)
    notes = [] if len(listed) < 2 else [
        f"{len(listed)} deliveries: only the first one's bytes are saved, so questions naming"
        " the others stay unanswered here."
    ]

    context, _ = build_context(
        challenge_id, challenge, attempt, artifact, args.work_dir / "artifact.bin", state.answer_ids, None,
    )
    chosen = [s for s in SOLVERS if not args.solver or getattr(s, "name", None) in args.solver]
    started = time.perf_counter()
    candidates = [candidate for solver in chosen for candidate in solver.solve(context)]
    selected, conflict = select_candidates(candidates, state.answer_ids, notes)
    elapsed = (time.perf_counter() - started) * 1000

    open_ids = set(state.answer_ids) - state.accepted_ids
    kind = kind_of if len({kind_of(i) for i in open_ids}) <= MAX_KIND_REQUESTS else field_of
    answers = {c.answer_id: c for c in selected}
    counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    solvers: dict[str, set[str]] = defaultdict(set)
    for answer_id in open_ids:
        group = counts[kind(answer_id)]
        group[1] += 1
        if answer_id in answers:
            group[0] += 1
            solvers[kind(answer_id)].add(answers[answer_id].solver)

    print(f"{challenge_id}  ({challenge.get('mode') or 'single solve'}, {challenge.get('lane')})")
    print(f"{len(state.answer_ids)} questions, {len(state.accepted_ids)} already accepted,"
          f" {len(open_ids & set(answers))} of {len(open_ids)} open ones answered"
          f" by {len(chosen)} solvers in {elapsed:.0f} ms"
          + (", answers in conflict" if conflict else ""))
    for note in notes:
        print(f"note: {note}")
    print()
    for name in sorted(counts):
        answered, total = counts[name]
        print(f"  {answered:5}/{total:<5} {','.join(sorted(solvers[name])) or '-':24} {name}")
    missing = sorted(name for name, (answered, _) in counts.items() if not answered)
    if missing:
        print(f"\nno answer from the robot ({len(missing)} kinds): " + ", ".join(missing))

    if args.show:
        wanted = re.compile(args.show)
        files = {item.answer_id: item.artifact for item in question_items(context)}
        print(f"\n== answers of the kinds matching {args.show!r}")
        for answer_id in sorted(open_ids):
            if not wanted.search(kind(answer_id)):
                continue
            candidate = answers.get(answer_id)
            value = "(no answer)" if candidate is None else json.dumps(candidate.answer)
            print(f"  {answer_id:44} {files.get(answer_id) or '':34} {value[:160]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
