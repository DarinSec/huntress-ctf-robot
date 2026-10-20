"""One-file triage for the AI, and a work folder for challenges the robot could not solve.

The AI reads `work/<id>/triage.md` instead of making many separate tool calls. Unpacked
members get a `.bin` suffix so nothing in the folder is executable by double-click.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .artifacts import artifact_kind, artifact_summary
from .client import GameMasterError
from .containers import Member
from .decoders import peel
from .display import safe_value
from .evidence import collect
from .macho import describe, field, slices
from .solvers.metadata import PROPERTIES
from .state import current_fields

MAX_BLOB_CHARS = 2000
MAX_VALUES = 25
MAX_QUESTION_GROUPS = 60
_PROPERTY = re.compile(r"Determine ([a-z0-9_.]+) for ")


def _quoted(value: str, limit: int = 500) -> str:
    return json.dumps(value[:limit] + ("..." if len(value) > limit else ""), ensure_ascii=True)


def issued_questions(attempt: Any) -> list[dict[str, Any]]:
    try:
        listed = current_fields(attempt).get("questions")
    except GameMasterError:
        return []
    return [item for item in listed if isinstance(item, dict)] if isinstance(listed, list) else []


def _question_section(questions: list[dict[str, Any]], members: tuple[Member, ...]) -> list[str]:
    """Questions grouped by identical text, with format, file and parser status.

    A Script Analysis day holds ~1,300 questions but only ~80 distinct texts.
    """
    kinds = {member.name.rsplit("/", 1)[-1]: artifact_kind(member.data) for member in members}
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in questions:
        groups.setdefault(str(item.get("question", "")), []).append(item)
    lines = ["", f"## Questions ({len(questions)}, {len(groups)} distinct)", ""]
    for text, items in sorted(groups.items(), key=lambda group: -len(group[1]))[:MAX_QUESTION_GROUPS]:
        first = items[0]
        target = str(first.get("artifact") or "")
        member = target.rsplit("->", 1)[-1].strip().rsplit("/", 1)[-1]
        prop = _PROPERTY.search(text)
        status = "" if not prop else (" **(parser exists)**" if prop[1] in PROPERTIES else " **(NO PARSER: add it to PROPERTIES)**")
        lines.append(f"- {len(items)} x `{first.get('id')}`: {_quoted(text, 400)}{status}")
        lines.append(f"  - format: {_quoted(json.dumps(first.get('answer_format'), ensure_ascii=True), 300)}")
        if target:
            lines.append(f"  - file: {_quoted(target, 200)}" + (f" ({kinds[member]})" if member in kinds else ""))
    if len(groups) > MAX_QUESTION_GROUPS:
        lines.append(f"- ... {len(groups) - MAX_QUESTION_GROUPS} more distinct questions in assignment.json")
    return lines


def render_triage(
    artifact: bytes, members: tuple[Member, ...] = (), notes: tuple[str, ...] = (),
    title: str = "artifact", questions: list[dict[str, Any]] | None = None,
) -> str:
    facts = collect(artifact, members)
    lines = [
        f"# Triage: {title}", "",
        f"- SHA-256: `{hashlib.sha256(artifact).hexdigest()}`",
        f"- Bytes: {len(artifact)}",
        f"- Kind: {artifact_kind(artifact)}",
    ]
    for note in notes:
        lines.append(f"- Note: {note}")
    if questions:
        lines += _question_section(questions, members)
    if members:
        lines += ["", "## Unpacked members", "", "| # | Name | Bytes | Kind |", "| --- | --- | --- | --- |"]
        for index, member in enumerate(members):
            lines.append(
                f"| {index} | {_quoted(member.name, 120)} | {len(member.data)} | {artifact_kind(member.data)} |"
            )
    binaries = [(name, images) for name, data in (("artifact", artifact), *(
        (member.name, member.data) for member in members)) if (images := slices(data))]
    if binaries:
        lines += ["", "## Mach-O slices", ""]
        for name, images in binaries:
            lines.append(f"- {_quoted(name, 120)}: cpu_type_set `{field('cpu_type_set', images)}`")
            lines += [f"  - {describe(item)}" for item in images[:MAX_VALUES]]
    found = [(name, chain, answer) for name, data in (("artifact", artifact), *(
        (member.name, member.data) for member in members)) for chain, _, answer in peel(data)]
    if found:
        lines += ["", "## Stated answers after decoding", ""]
        lines += [f"- {_quoted(name, 120)}: {' -> '.join(chain)} gives {_quoted(answer)}" for name, chain, answer in found]
    if facts.metadata:
        lines += ["", "## Metadata", ""]
        for key, values in facts.metadata.items():
            lines.append(f"- `{key}`: " + ", ".join(_quoted(value) for value in values[:MAX_VALUES]))
    if facts.iocs:
        lines += ["", "## Indicators", ""]
        for kind, values in facts.iocs.items():
            more = f" (+{len(values) - MAX_VALUES} more)" if len(values) > MAX_VALUES else ""
            lines.append(f"- {kind}: " + ", ".join(_quoted(value, 200) for value in values[:MAX_VALUES]) + more)
    if facts.blobs:
        lines += ["", "## Decoded blobs", ""]
        for label, value in facts.blobs:
            lines.append(f"- {label}: {_quoted(value, MAX_BLOB_CHARS)}")
    lines += ["", "## Preview", "", "```text", *artifact_summary(artifact), "```"]
    for member in members[:10]:
        lines += ["", f"### Member {_quoted(member.name, 120)}", "", "```text", *artifact_summary(member.data), "```"]
    return "\n".join(lines) + "\n"


def _safe(name: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]", "_", name.replace("\\", "/").rsplit("/", 1)[-1])
    return base.strip("._")[:80] or "member"


def write_workspace(
    work_dir: Path, challenge_id: str, *, challenge: Any, attempt: Any, artifact: bytes,
    members: tuple[Member, ...] = (), notes: tuple[str, ...] = (), secrets: tuple[str, ...] = (),
) -> Path:
    directory = work_dir / (re.sub(r"[^A-Za-z0-9_-]", "_", challenge_id)[:64] or "unknown")
    (directory / "members").mkdir(parents=True, exist_ok=True)
    (directory / "assignment.json").write_text(json.dumps(
        safe_value({"challenge": challenge, "attempt": attempt}, secrets),
        indent=2, ensure_ascii=True, sort_keys=True,
    ) + "\n", encoding="utf-8")
    (directory / "artifact.bin").write_bytes(artifact)
    for index, member in enumerate(members):
        (directory / "members" / f"{index:03}-{_safe(member.name)}.bin").write_bytes(member.data)
    (directory / "triage.md").write_text(
        render_triage(artifact, members, notes, title=challenge_id, questions=issued_questions(attempt)),
        encoding="utf-8",
    )
    return directory.resolve()
