#!/usr/bin/env python3
"""Replay a saved single-delivery Binary assignment offline, without answer values.

Uses source from PYTHONPATH or the installed project. No client is created, no
environment/token file is read, and no Game Master operation is performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

from huntress_ctf.autopilot import build_context
from huntress_ctf.client import GameMasterError
from huntress_ctf.solvers.binary import BinarySolver
from huntress_ctf.state import AttemptState, deliveries


def audit(assignment_path: Path, artifact_path: Path) -> dict:
    saved = json.loads(assignment_path.read_text(encoding="utf-8-sig"))
    challenge, attempt = saved["challenge"], saved["attempt"]
    challenge_id = challenge["id"]
    lane = challenge.get("lane") or challenge_id.split("-day-")[0]
    if lane not in BinarySolver.lanes:
        raise ValueError("The saved assignment does not belong to the Binary lane")
    if len(deliveries(attempt)) > 1:
        raise ValueError("This audit requires one delivery; preserve separate delivery files")
    state = AttemptState.parse(attempt)
    if not state.answer_ids or not state.artifact_sha256:
        raise ValueError("The saved assignment needs answer IDs and an assigned artifact SHA-256")
    artifact = artifact_path.read_bytes()
    digest = hashlib.sha256(artifact).hexdigest()
    if digest != state.artifact_sha256:
        raise ValueError("Artifact SHA-256 does not match the saved assignment")
    context, _ = build_context(challenge_id, challenge, attempt, artifact,
                               artifact_path, state.answer_ids, None)
    started = time.perf_counter()
    candidates = BinarySolver().solve(context)
    elapsed = (time.perf_counter() - started) * 1000
    found = {candidate.answer_id for candidate in candidates}
    return {
        "scope": "Offline candidate coverage; newly computed values are not live-verified.",
        "challenge_id": challenge_id,
        "artifact_sha256": digest,
        "hash_matches_assignment": True,
        "questions": len(state.answer_ids),
        "candidates": len(found),
        "accepted_id_overlap": len(found & state.accepted_ids),
        "accepted_id_note": "Matching previously accepted IDs does not prove candidate values correct.",
        "missing_ids": [answer_id for answer_id in state.answer_ids if answer_id not in found],
        "solve_ms": round(elapsed, 3),
        "game_master_requests": 0,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("assignment", type=Path, help="Path to saved assignment.json")
    parser.add_argument("--artifact", type=Path, help="Assigned bytes (default: sibling artifact.bin)")
    parser.add_argument("--output", type=Path, help="Optional report path; keep real assignment reports under ignored work/")
    args = parser.parse_args(argv)
    try:
        result = audit(args.assignment, args.artifact or args.assignment.with_name("artifact.bin"))
        text = json.dumps(result, indent=2, ensure_ascii=True) + "\n"
        if args.output:
            args.output.write_text(text, encoding="utf-8")
        print(text, end="")
        return 0
    except (OSError, ValueError, KeyError, TypeError, GameMasterError) as error:
        print(f"Binary audit failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
