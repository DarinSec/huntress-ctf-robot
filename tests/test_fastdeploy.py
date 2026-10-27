"""The release-day deploy replays only the corpus lanes a change can reach (scripts/fastdeploy.py)."""
from pathlib import Path
import runpy
import shutil
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "fastdeploy.py"
if not SCRIPT.exists():  # A Homebase deploy copies src/ and tests/ only.
    raise unittest.SkipTest("scripts/fastdeploy.py is not deployed here")
FAST = runpy.run_path(str(SCRIPT))

# A miniature robot: the import shapes that decide the plan.
PACKAGE = {
    "__init__.py": "",
    "fastpath.py": "from .solvers import base\n",
    "formats.py": "",
    "decoders.py": "",
    "suggest.py": "from . import formats\n",
    "solvers/__init__.py": "",
    "solvers/base.py": "",
    "solvers/metadata.py": "from .. import formats\nfrom .base import x\n",
    # Binary uses metadata.Files, and suggest only lazily, as the real one does.
    "solvers/binary.py": "from .metadata import Files\ndef f():\n    from ..suggest import confident\n",
    "solvers/encoding.py": "from ..decoders import peel\n",
    "solvers/warmups.py": "from ..decoders import peel\n",
}
TESTS = {
    "test_metadata.py": "from huntress_ctf.solvers.metadata import PROPERTIES\n",
    "test_warmups.py": "from huntress_ctf.solvers import warmups\n",
    "test_solvers_state.py": "",
}


class FastDeployPlanTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name, text in PACKAGE.items():
            path = self.root / "old" / "huntress_ctf" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        shutil.copytree(self.root / "old", self.root / "new")
        for name, text in TESTS.items():
            (self.root / "tests").mkdir(exist_ok=True)
            (self.root / "tests" / name).write_text(text, encoding="utf-8")

    def plan(self, change: str | None, *lanes: str) -> dict[str, str]:
        if change:
            with open(self.root / "new" / "huntress_ctf" / change, "a", encoding="utf-8") as file:
                file.write("# changed\n")
        lines = FAST["plan"](self.root / "old", self.root / "new", self.root / "tests", list(lanes))
        result = dict(line.split("=", 1) for line in lines if not line.startswith("#"))
        result["notes"] = "\n".join(line for line in lines if line.startswith("#"))
        return result

    def test_a_metadata_parser_replays_metadata_only(self):
        plan = self.plan("solvers/metadata.py")
        self.assertEqual((plan["MODE"], plan["REPLAY"]), ("fast", "metadata-forensics"))
        self.assertEqual(plan["TESTS"].split(), ["test_metadata.py", "test_solvers_state.py"])

    def test_a_shared_helper_replays_every_lane_that_runs_it(self):
        plan = self.plan("formats.py")  # Binary through suggest (lazily), Metadata directly.
        self.assertEqual(plan["REPLAY"], "binary-reverse-engineering metadata-forensics")

    def test_a_helper_of_a_generic_solver_replays_every_lane(self):
        plan = self.plan("decoders.py")
        self.assertEqual(plan["REPLAY"].split(), ["binary-reverse-engineering", "metadata-forensics",
                                                   "mobile-android", "script-analysis", "warmups"])
        self.assertIn("test_warmups.py", plan["TESTS"].split())

    def test_named_lanes_replace_the_choice_and_the_rest_is_named(self):
        plan = self.plan("decoders.py", "warmups")
        self.assertEqual(plan["REPLAY"], "warmups")
        self.assertIn("not replayed although affected: binary-reverse-engineering", plan["notes"])

    def test_a_change_to_the_robot_itself_is_a_full_deploy(self):
        self.assertEqual(self.plan("fastpath.py")["MODE"], "full")
        self.assertEqual(self.plan("solvers/base.py")["MODE"], "full")

    def test_no_change_runs_the_registry_test_and_replays_nothing(self):
        plan = self.plan(None)
        self.assertEqual((plan["MODE"], plan["TESTS"], plan["REPLAY"]), ("fast", "test_solvers_state.py", ""))


if __name__ == "__main__":
    unittest.main()
