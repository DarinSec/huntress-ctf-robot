"""Release-day deploy: only the tests and the corpus lanes a change can affect (run on the Homebase).

`scripts/homebase.sh fastdeploy [lane ...]` ships src/ and runs, against ~/src:
  python3 -I fastdeploy.py plan <old src> <new src> <tests dir> [lane ...]
which prints MODE=fast|full, TESTS=<test files>, REPLAY=<corpus lanes> and '# ' notes, then
  PYTHONPATH=src python3 fastdeploy.py test <tests dir> <test file> ...
which runs those files as `unittest discover` would (a module-level SkipTest skips).

Why: `deploy` replays the whole corpus before the swap, 7 of its 8.5 minutes on the 2-core
Homebase (27 Oct: Binary 296 s, Script 91 s, Metadata 24 s, Warmups 10 s, Mobile 5 s), and on
release day those minutes come after the team has its parser. A new Metadata property is one
PROPERTIES line that only Metadata's entries can answer differently. Here a lane is replayed
when it owns a changed file, or runs a changed shared helper (formats, decoders, ...); a lane
named on the command line replaces that choice. A change to the robot itself (fastpath, daily,
client, containers, ...) is MODE=full: the whole suite and corpus, as `deploy` runs them.
"""

from __future__ import annotations

import ast
from pathlib import Path
import sys

PACKAGE = "huntress_ctf"
# Corpus lane -> the modules only that lane's solvers run (a name, or a prefix ending in "." or "_").
LANES: dict[str, tuple[str, ...]] = {
    "warmups": ("solvers.warmups",),
    "metadata-forensics": ("solvers.metadata", "solvers.autoprop"),
    "binary-reverse-engineering": ("solvers.binary", "solvers._binary_"),
    "script-analysis": ("solvers.script", "solvers.script_descriptors", "analysis", "analysis."),
    "mobile-android": ("solvers.mobile_puzzle", "dexvm"),
    "web-exploitation": ("solvers.web", "solvers.web."),
}
# Solvers that answer in every lane: a change they run reaches every lane.
GENERIC = ("solvers.encoding", "solvers.facts")
# Helpers the solvers share; the lanes whose solvers import them (transitively) are replayed.
SHARED = ("formats", "formats_dfir", "macho", "suggest", "decoders", "ciphers", "evidence")
ALWAYS_TESTS = ("test_solvers_state.py", "test_fuzz.py")  # The registry loads; damaged input answers nothing.
NO_CORPUS = {"web-exploitation"}  # Live targets: no recorded artifacts to replay.


def _matches(module: str, prefixes: tuple[str, ...]) -> bool:
    return any(module == prefix or (prefix[-1] in "._" and module.startswith(prefix)) for prefix in prefixes)


def owner(module: str) -> str | None:
    return next((lane for lane, prefixes in LANES.items() if _matches(module, prefixes)), None)


def modules(src: Path) -> dict[str, Path]:
    """Module name (relative to the package, "" for its __init__) -> file."""
    root = src / PACKAGE
    found = {}
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        parts = list(path.relative_to(root).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        found[".".join(parts)] = path
    return found


def imports(path: Path, name: str, known: set[str], package_file: bool) -> set[str]:
    """The package modules a file imports, at the top or inside functions."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        return set()
    package = name.split(".") if package_file else name.split(".")[:-1]
    if name == "":
        package = []
    found = set()

    def add(target: str, names: list[str]) -> None:
        if target in known:
            found.add(target)
        for alias in names:
            child = f"{target}.{alias}" if target else alias
            if child in known:
                found.add(child)

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names = [alias.name for alias in node.names]
            if node.level:
                base = package[:len(package) - (node.level - 1)] if node.level > 1 else package
                target = ".".join(base + (node.module.split(".") if node.module else []))
                add(target, names)
            elif node.module and (node.module == PACKAGE or node.module.startswith(PACKAGE + ".")):
                add(node.module[len(PACKAGE) + 1:], names)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith(PACKAGE + "."):
                    add(alias.name[len(PACKAGE) + 1:], [])
    found.discard(name)
    return found


def graph(src: Path) -> dict[str, set[str]]:
    found = modules(src)
    known = set(found)
    return {name: imports(path, name, known, path.name == "__init__.py") for name, path in found.items()}


def closure(start: set[str], edges: dict[str, set[str]], lane: str | None = None, stop: bool = False) -> set[str]:
    """Every module `start` imports, transitively. With `stop`, the walk does not enter another
    lane's own modules: Binary imports metadata.Files, but a new Metadata PROPERTIES line is no
    Binary answer, so it replays Metadata only (a shared helper such as suggest still counts)."""
    seen, todo = set(), list(start)
    while todo:
        name = todo.pop()
        if name not in seen:
            seen.add(name)
            todo.extend(dep for dep in edges.get(name, ()) if not stop or owner(dep) in (None, lane))
    return seen


def changed(old: Path, new: Path) -> set[str]:
    before, after = modules(old), modules(new)
    return {name for name in set(before) | set(after)
            if name not in before or name not in after or before[name].read_bytes() != after[name].read_bytes()}


def test_imports(path: Path, known: set[str]) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        return set()
    found = set()
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names = [node.module] + [f"{node.module}.{alias.name}" for alias in node.names]
        elif isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        for full in names:
            if full == PACKAGE or full.startswith(PACKAGE + "."):
                short = full[len(PACKAGE) + 1:]
                if short in known:
                    found.add(short)
    return found


def plan(old: Path, new: Path, tests: Path, lanes: list[str]) -> list[str]:
    edges = graph(new)
    known = set(edges)
    touched = changed(old, new) if (old / PACKAGE).is_dir() else None
    notes = []
    if touched is None:
        return ["MODE=full", "TESTS=", "REPLAY=", f"# no {old}/{PACKAGE} to compare with"]
    core = sorted(name for name in touched if not owner(name) and not _matches(name, GENERIC + SHARED))
    notes.append("# changed: " + (", ".join(sorted(name or "__init__" for name in touched)) or "nothing"))
    if core:
        return ["MODE=full", "TESTS=", "REPLAY=", *notes,
                "# the robot itself changed (" + ", ".join(name or "__init__" for name in core) + "): whole suite and corpus"]
    affected = {owner(name) for name in touched if owner(name)}
    for name in edges:  # Every solver module that runs a changed shared helper or generic solver.
        lane = owner(name)
        if (lane or _matches(name, GENERIC)) and closure({name}, edges, lane, stop=True) & touched:
            affected.update(LANES if _matches(name, GENERIC) else {lane})
    selected = [path.name for path in sorted(tests.glob("test_*.py"))
                if path.name in ALWAYS_TESTS or closure(test_imports(path, known), edges) & touched]
    replay = sorted(affected - NO_CORPUS)
    if lanes:
        wanted = [full for lane in lanes for full in LANES if full == lane or full.startswith(lane + "-")]
        skipped = sorted(set(replay) - set(wanted))
        replay = sorted(set(wanted) - NO_CORPUS)
        if skipped:
            notes.append("# not replayed although affected: " + ", ".join(skipped)
                         + " (scripts/homebase.sh replay after the day)")
    return ["MODE=fast", "TESTS=" + " ".join(selected), "REPLAY=" + " ".join(replay), *notes]


def run_tests(tests: Path, files: list[str]) -> int:
    import unittest
    # As `python3 -m unittest discover -s tests` from the deploy folder: some tests import
    # `tests.test_binary` fixtures, which needs that folder on the path.
    sys.path.insert(0, str(tests.resolve().parent))
    loader = unittest.TestLoader()
    suite = unittest.TestSuite(loader.discover(str(tests), pattern=name) for name in files)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() else 1


def main(argv: list[str]) -> int:
    if len(argv) >= 4 and argv[0] == "plan":
        print("\n".join(plan(Path(argv[1]), Path(argv[2]), Path(argv[3]), argv[4:])))
        return 0
    if len(argv) >= 2 and argv[0] == "test":
        return run_tests(Path(argv[1]), argv[2:])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
