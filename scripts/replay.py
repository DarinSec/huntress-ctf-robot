#!/usr/bin/env python3
"""Re-solve every recorded assignment offline and report regressions (no network, no submit).

  PYTHONPATH=src python3 scripts/replay.py                 # all of ~/.huntress/corpus (or $HUNTRESS_STATE_DIR)
  PYTHONPATH=src python3 scripts/replay.py --only day-23   # entries whose path contains the text
  PYTHONPATH=src python3 scripts/replay.py --dry           # do not update last_replay.json
  PYTHONPATH=src python3 scripts/replay.py import <challenge-id> <lane> <start.json> <file>... --log <submits.jsonl>...

Run it before every deploy: exit status 1 means an answer that matched the accepted one in the
previous replay no longer does (or is gone). "differs" alone is normal: the service accepts
several spellings of many fields (ELF/ELF64, x86_64/x86-64), and the accepted column holds
whichever one was submitted.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import time

from huntress_ctf import corpus


def main(argv: list[str]) -> int:
    if argv[:1] == ["import"]:
        parser = argparse.ArgumentParser(prog="replay.py import")
        parser.add_argument("challenge_id")
        parser.add_argument("lane")
        parser.add_argument("start_json", type=Path)
        parser.add_argument("files", type=Path, nargs="+", help="the artifact, or every delivery in order")
        parser.add_argument("--log", type=Path, action="append", default=[], help="JSONL submit log (repeatable)")
        args = parser.parse_args(argv[1:])
        saved = corpus.import_entry(args.challenge_id, args.lane, args.start_json, args.files, args.log)
        print(f"saved {saved}" if saved else "nothing saved (no accepted answers, or the route already has two entries)")
        return 0
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--only", default="")
    parser.add_argument("--dry", action="store_true")
    parser.add_argument("--corpus", type=Path, default=None)
    args = parser.parse_args(argv)
    found = corpus.entries(args.corpus, args.only)
    if not found:
        print(f"No entries in {args.corpus or corpus.corpus_root()}.")
        return 0
    failed = False
    for entry in found:
        began = time.monotonic()
        report = corpus.replay(entry, keep=not args.dry)
        name = f"{entry.parent.name}/{entry.name[:8]}"
        print(f"{name:72} {report['answered']:5}/{report['questions']:<5} answered | "
              f"{report['equal']:5}/{report['accepted']:<5} = accepted | {len(report['differs']):4} differ | "
              f"{time.monotonic() - began:5.1f}s" + ("  REGRESSION" if report["regressions"] else ""))
        for key in report["regressions"][:10]:
            failed = True
            print(f"    regression: {key}")
        if report["regressions"][10:]:
            print(f"    ... {len(report['regressions']) - 10} more")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
