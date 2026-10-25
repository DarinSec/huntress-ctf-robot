#!/usr/bin/env python3
"""Fuzz every solver with mutants of the local replay corpus (offline; no network, no submit).

  PYTHONPATH=src python3 scripts/fuzz.py --count 50              # 50 mutants per corpus entry, every solver
  PYTHONPATH=src python3 scripts/fuzz.py --only day-23 --solver metadata-facts --count 200
  PYTHONPATH=src python3 scripts/fuzz.py --salt 7 --count 50     # another 50 (the salt picks the mutants)
  PYTHONPATH=src python3 scripts/fuzz.py --repro 'binary-...-day-19-jack-in-the-box/f4053d98#17' --solver binary-static-facts

Findings are grouped by where they happen (one bug usually shows on many inputs); each names
an input as <seed>#<index>, which --repro (same --salt) replays here with the full traceback.
Exit status 1 when anything hung, raised or died. Seeds are real artifacts: they stay local.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
import sys
import time

from huntress_ctf import fuzz
from huntress_ctf.solvers import SOLVERS
from huntress_ctf.watchdog import solver_name


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--corpus", type=Path, default=None)
    parser.add_argument("--only", default="", help="entries whose path contains this text")
    parser.add_argument("--solver", action="append", default=[], help="only this solver (repeatable)")
    parser.add_argument("--count", type=int, default=20, help="mutants per seed")
    parser.add_argument("--salt", default="0")
    parser.add_argument("--budget", type=float, default=fuzz.BUDGET_S, help="seconds per input")
    parser.add_argument("--parallel", type=int, default=None)
    parser.add_argument("--repro", default=None, help="<seed>#<index>: replay one input in this process")
    args = parser.parse_args(argv)
    solvers = [s for s in SOLVERS if not args.solver or solver_name(s) in args.solver]
    seeds = list(fuzz.corpus_seeds(args.corpus, args.only))
    if not seeds or not solvers:
        print("No seeds (corpus entries) or no matching solver.")
        return 0
    if args.repro:
        name, _, index = args.repro.rpartition("#")
        seed = next(s for s in seeds if s.name == name)
        changed, how = fuzz.mutant(seed, int(index), args.salt)
        print(f"{args.repro}: {how}")
        for solver in solvers:
            found = list(solver.solve(fuzz.context(changed)))  # Raises here, with the traceback.
            print(f"{solver_name(solver)}: {len(found)} candidate(s)")
        return 0
    began = time.monotonic()
    print(f"{len(seeds)} seed(s) x {args.count} mutants x {len(solvers)} solver(s), salt {args.salt}")
    findings = fuzz.run(solvers, seeds, args.count, budget=args.budget, salt=args.salt, parallel=args.parallel)
    groups: dict[tuple[str, str, str, str], list[fuzz.Finding]] = defaultdict(list)
    for finding in findings:
        groups[(finding.solver, finding.status, finding.where, finding.detail.split(":")[0])].append(finding)
    for (solver, status, where, kind), found in sorted(groups.items(), key=lambda item: -len(item[1])):
        print(f"{len(found):4} x {solver} {status} {kind} at {where or '?'}")
        for finding in found[:2]:
            print(f"       {finding.seed}#{finding.index}: {finding.mutation}: {finding.detail[:160]}")
    print(f"{len(findings)} finding(s) in {len(groups)} place(s), {time.monotonic() - began:.0f} s")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
