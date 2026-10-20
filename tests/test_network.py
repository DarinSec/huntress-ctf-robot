"""Clock offset used to place the server's started_at on our timeline (offline)."""

import subprocess
import unittest
from unittest.mock import patch

from huntress_ctf import network


class ClockTests(unittest.TestCase):
    def test_blocked_ntp_falls_back_to_a_synchronized_system_clock(self):
        blocked = patch.object(network.socket, "socket", side_effect=OSError("blocked"))
        no_marker = patch.object(network.Path, "exists", return_value=False)
        for answer, expected in (("yes\n", 0.0), ("no\n", None)):
            reply = subprocess.CompletedProcess([], 0, stdout=answer)
            with self.subTest(answer=answer), blocked, no_marker, \
                    patch.object(network.subprocess, "run", return_value=reply):
                self.assertEqual(network.clock_offset(tries=1), expected)

    def test_no_timedatectl_means_unknown(self):
        with patch.object(network.socket, "socket", side_effect=OSError("blocked")), \
                patch.object(network.Path, "exists", return_value=False), \
                patch.object(network.subprocess, "run", side_effect=FileNotFoundError()):
            self.assertIsNone(network.clock_offset(tries=1))


if __name__ == "__main__":
    unittest.main()
