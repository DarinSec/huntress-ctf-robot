"""A submit POST lost in transit: on an untimed attempt the fast path checks status, then resends.

Day 27: three of fifteen release-time POSTs failed and waited ~5 min for the next sweep.
"""
import unittest
from unittest.mock import patch

from huntress_ctf.client import GameMasterError, UncertainPost
from huntress_ctf.fastpath import Run, _submit
from huntress_ctf.state import AttemptState

OPEN = {"attempt_id": "att-1", "answer_ids": ["a", "b"], "accepted_ids": ["a"], "deadline": None}
SOLVED = {**OPEN, "accepted_ids": ["a", "b"], "result": "CORRECT"}


class Flaky:
    """The first `failures` POSTs are lost in transit; status answers from `statuses` in order."""

    def __init__(self, statuses, failures=1):
        self.statuses, self.failures, self.posts, self.status_calls = list(statuses), failures, [], 0

    def submit_many(self, challenge_id, answers):
        self.posts.append(dict(answers))
        if self.failures:
            self.failures -= 1
            raise UncertainPost("Game Master transport failed (TimeoutError). A POST may have reached the server")
        return {"result": "CORRECT", "accepted_ids": ["a", "b"]}

    def status(self, challenge_id):
        self.status_calls += 1
        reply = self.statuses.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def run(deadline=None, timed=False):
    started = AttemptState(answer_ids=("a", "b"), attempt_id="att-1", deadline=deadline)
    return Run(timed=timed, started=started, submitted={"a": "1", "b": "2"})


@patch("huntress_ctf.fastpath.SUBMIT_RECOVERY_WAITS_S", (0, 0))
class SubmitRecoveryTests(unittest.TestCase):
    def test_open_attempt_gets_the_unaccepted_answers_again(self):
        client, current = Flaky([OPEN]), run()
        self.assertEqual(_submit(client, current, "x")["result"], "CORRECT")
        self.assertEqual(client.posts, [{"a": "1", "b": "2"}, {"b": "2"}])

    def test_solved_attempt_is_the_result_but_nothing_is_proven(self):
        client, current = Flaky([SOLVED]), run()
        self.assertEqual(_submit(client, current, "x")["result"], "CORRECT")
        self.assertEqual(len(client.posts), 1)
        self.assertEqual(current.submitted, {})  # No hint: a teammate may have solved it.

    def test_timed_attempt_is_never_resent(self):
        for current in (run(timed=True), run(deadline="2026-10-27T13:05:43.845Z")):
            client = Flaky([OPEN])
            with self.assertRaises(UncertainPost):
                _submit(client, current, "x")
            self.assertEqual((len(client.posts), client.status_calls), (1, 0))

    def test_another_attempt_never_gets_the_old_answers(self):
        client = Flaky([{**OPEN, "attempt_id": "att-2"}])
        with self.assertRaises(UncertainPost):
            _submit(client, run(), "x")
        self.assertEqual(len(client.posts), 1)

    def test_status_failing_twice_gives_up_with_the_first_error(self):
        client = Flaky([GameMasterError("down"), GameMasterError("down")])
        with self.assertRaises(UncertainPost):
            _submit(client, run(), "x")
        self.assertEqual((len(client.posts), client.status_calls), (1, 2))


if __name__ == "__main__":
    unittest.main()
