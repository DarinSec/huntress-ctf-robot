from contextlib import redirect_stdout
from io import StringIO
from itertools import count
from pathlib import Path
import tempfile
import unittest

from huntress_ctf.client import GameMasterError
from huntress_ctf.lock import robot_lock


class LockTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "state" / "robot.lock"

    def test_second_holder_is_told_who_has_it(self):
        with robot_lock("daily --day 21", path=self.path):
            with self.assertRaises(GameMasterError) as raised:
                with robot_lock("solve x", path=self.path):
                    pass
        self.assertIn("daily --day 21", str(raised.exception))
        self.assertIn("--lock-wait", str(raised.exception))
        with robot_lock("solve x", path=self.path):  # Free again once released.
            pass

    def test_waiting_gives_up_after_the_limit(self):
        ticks = count()
        sleeps = []
        with robot_lock("daily", path=self.path):
            with redirect_stdout(StringIO()) as output, self.assertRaises(GameMasterError):
                with robot_lock("solve x", path=self.path, wait=3, sleep=sleeps.append,
                                clock=lambda: float(next(ticks))):
                    pass
        self.assertEqual(len(sleeps), 2)
        self.assertIn("Waiting up to 3 s", output.getvalue())


if __name__ == "__main__":
    unittest.main()
