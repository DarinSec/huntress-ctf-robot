"""Deterministic solver registry, discovered automatically: one module per lane.

To add a lane, create `solvers/<lane>.py` that defines `SOLVERS = (MySolver(),)`. It is
picked up on the next run; no registration is needed. A module that fails to import is
reported in LOAD_ERRORS instead of stopping the robot. Every solver runs on every
attempt; disagreeing candidates block submission.
"""

from __future__ import annotations

import importlib
import pkgutil

from .base import (
    MAX_TEXT_BYTES, AnswerCandidate, Solver, SolveContext, instruction_text, questions,
)
from .encoding import (
    Base64AnswerSolver, CluedTextDecoderSolver, JsonAnswerMapSolver, LayeredDecodeSolver,
    answer_text, encoding_clue,
)

_FIRST = ("encoding",)
_NOT_LANES = {"base"}
LOAD_ERRORS: list[str] = []


def _discover() -> tuple[Solver, ...]:
    names = [
        module.name for module in pkgutil.iter_modules(__path__)
        if module.name not in _NOT_LANES and not module.name.startswith("_")
    ]
    ordered = [name for name in _FIRST if name in names] + sorted(
        name for name in names if name not in _FIRST
    )
    found: list[Solver] = []
    for name in ordered:
        try:
            module = importlib.import_module(f"{__name__}.{name}")
        except Exception as exc:  # A broken lane must not take the others down.
            LOAD_ERRORS.append(f"solvers.{name}: {type(exc).__name__}: {exc}")
            continue
        found.extend(getattr(module, "SOLVERS", ()))
    return tuple(found)


SOLVERS: tuple[Solver, ...] = _discover()

__all__ = [
    "MAX_TEXT_BYTES", "AnswerCandidate", "Solver", "SolveContext", "instruction_text",
    "questions", "Base64AnswerSolver", "CluedTextDecoderSolver", "JsonAnswerMapSolver",
    "LayeredDecodeSolver", "answer_text", "encoding_clue", "SOLVERS", "LOAD_ERRORS",
]
