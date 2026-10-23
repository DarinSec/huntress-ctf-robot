import base64
from pathlib import Path
import time
import unittest

from huntress_ctf.client import GameMasterError
from huntress_ctf.display import safe_value
from huntress_ctf.solvers import (
    Base64AnswerSolver, CluedTextDecoderSolver, JsonAnswerMapSolver, SolveContext,
)
from huntress_ctf.solvers.base import question_items
from huntress_ctf.state import AttemptState, ensure_same_attempt, mode_name, remember_identity


def context(instructions, artifact, ids=("a",), **extra):
    return SolveContext("c", {}, {"instructions": instructions, **extra}, artifact, Path("sample"), ids)


class SolverTests(unittest.TestCase):
    def test_base64_explicit_task_and_wrapped_lines(self):
        answers = Base64AnswerSolver().solve(context("Decode this Base64 text.", b"Zmxh\nZ3t4fQ==\n"))
        self.assertEqual([answer.answer for answer in answers], ["flag{x}"])

    def test_vague_negative_or_other_tasks_are_not_decoded(self):
        for prompt in ("This is encoded.", "Decode this file.", "Do not decode Base64.",
                       "Count the bytes in this Base64 text.", "Decode Base64 and give its SHA256.",
                       "Decode Base64 then ROT13."):
            with self.subTest(prompt=prompt):
                self.assertEqual(Base64AnswerSolver().solve(context(prompt, b"aGVsbG8=")), [])
        self.assertEqual(Base64AnswerSolver().solve(
            context("Solve the puzzle.", b"aGVsbG8=", debug="Decode Base64")), [])

    def test_base64_no_binary_control_or_noncanonical_output(self):
        for data in (b"Zg===", base64.b64encode(b"\x1b[31m"), base64.b64encode(b"\x7f"), b""):
            with self.subTest(data=data):
                self.assertEqual(Base64AnswerSolver().solve(context("Decode Base64.", data)), [])
        self.assertEqual(Base64AnswerSolver().solve(
            context("Decode Base64.", b"aGVsbG8=", ("a", "b"))), [])

    def test_clued_decoders(self):
        for prompt, data, expected in (
            ("Decode ROT13.", b"uryyb", "hello"),
            ("Decode hexadecimal text.", b"68 65 6c 6c 6f", "hello"),
            ("Decode binary text.", b"0110100001101001", "hi"),
            ("Decode 8-bit binary.", b"01101000 01101001", "hi"),
            ("Decode ROT13.", b" uryyb \n", " hello "),
        ):
            with self.subTest(prompt=prompt):
                answers = CluedTextDecoderSolver().solve(context(prompt, data))
                self.assertEqual([answer.answer for answer in answers], [expected])

    def test_invalid_text_does_not_generate_candidates(self):
        for prompt, data in (("Decode hexadecimal.", b"GG"),
                             ("Decode binary.", b"011"),
                             ("Decode ROT13 then hex.", b"abcd")):
            with self.subTest(prompt=prompt):
                self.assertEqual(CluedTextDecoderSolver().solve(context(prompt, data)), [])

    def test_json_mapping_requires_assignment_evidence(self):
        artifact = b'{"answers":{"a":"value","b":42,"c":false}}'
        solver = JsonAnswerMapSolver()
        self.assertEqual(solver.solve(context("Investigate this file.", artifact, ("a", "b"))), [])
        answers = solver.solve(context(
            "Submit the answers from the JSON answer map.", artifact, ("a", "b", "c")
        ))
        self.assertEqual([(item.answer_id, item.answer) for item in answers], [("a", "value"), ("b", "42")])

    def test_json_duplicates_and_unknown_ids(self):
        solver = JsonAnswerMapSolver()
        prompt = "Read the JSON answer map and submit it."
        self.assertEqual(solver.solve(context(prompt, b'{"a":"one","a":"two"}')), [])
        answers = solver.solve(context(
            prompt, b'[{"answer_id":"a","answer":"one"},{"answer_id":"unknown","answer":"bad"}]'
        ))
        self.assertEqual([(item.answer_id, item.answer) for item in answers], [("a", "one")])


class QuestionItemsTests(unittest.TestCase):
    """A Mastery assignment issues thousands of questions and every solver reads them."""

    def assignment(self, count):
        questions = [{"id": f"set1.q{n:05}", "question": f"question {n}?", "artifact": f"f{n}.bin",
                      "answer_format": {"kind": "exact_text"}} for n in range(count)]
        ids = tuple(q["id"] for q in questions)
        return SolveContext("c/mastery", {}, {"questions": questions}, b"", Path("x"), ids)

    def test_thousands_of_questions_parse_in_one_pass(self):
        # Day 23's Script Mastery issued 10,465. Matching each one against the answer_ids
        # tuple instead of a set was 365 ms of a 446 ms solve, paid by every solver.
        context = self.assignment(20000)
        started = time.perf_counter()
        items = question_items(context)
        elapsed = time.perf_counter() - started
        self.assertEqual(len(items), 20000)
        # Linear takes ~0.1 s here and the quadratic scan took 2.3 s, so this sits well
        # clear of both: it is a shape check, not a benchmark.
        self.assertLess(elapsed, 1.0, "question_items is scanning the answer_ids per question again")

    def test_the_parse_is_shared_by_every_solver_of_one_run(self):
        context = self.assignment(3)
        first = question_items(context)
        context.challenge["questions"] = [{"id": "set1.q00000", "question": "changed?"}]
        self.assertEqual([item.answer_id for item in question_items(context)],
                         [item.answer_id for item in first])  # Read from the memo, not re-parsed.
        self.assertIsNot(question_items(context), question_items(context))  # A copy each time.


class StateTests(unittest.TestCase):
    def test_only_current_fields_define_state(self):
        state = AttemptState.parse({
            "answer_ids": ["a"], "state": "active",
            "history": [{"state": "expired", "answer_ids": ["other"], "remaining": 99}],
            "expires_at": "token expiry",
        })
        self.assertEqual(state.answer_ids, ("a",))
        self.assertFalse(state.expired)
        self.assertIsNone(state.deadline)
        self.assertIsNone(state.remaining)

    def test_live_schema_accepted_ids_and_listed_artifact_hash(self):
        digest = "AB" * 32
        state = AttemptState.parse({
            "answer_ids": ["q1", "q2"], "accepted_ids": ["q1"], "mode": "mastery",
            "artifacts": [{"filename": "a.zip", "sha256": digest, "size": 3, "download": "/x"}],
        })
        self.assertEqual(state.accepted_ids, frozenset({"q1"}))
        self.assertEqual(state.artifact_sha256, digest.lower())
        # Two listed artifacts do not say which one op=artifact returns: no hash is assumed.
        two = AttemptState.parse({"artifacts": [{"sha256": digest}, {"sha256": "cd" * 32}]})
        self.assertIsNone(two.artifact_sha256)
        with self.assertRaises(GameMasterError):
            AttemptState.parse({"artifacts": [{"sha256": "not-a-hash"}]})

    def test_modes_are_explicit_not_guessed(self):
        self.assertEqual(mode_name({}, AttemptState(mode="mastery_mode")), "Mastery Mode")
        self.assertEqual(mode_name({}, AttemptState(mode="untimed")), "untimed")
        self.assertIn("Unknown", mode_name({}, AttemptState(
            answer_ids=("a", "b"), deadline="2026-10-17T10:00:00Z")))

    def test_bad_answer_ids_and_remaining(self):
        for ids in ([1], [{"id": "a"}], {"q": "a"}, ["a", "a"], [""]):
            with self.subTest(ids=ids), self.assertRaises(GameMasterError):
                AttemptState.parse({"answer_ids": ids})
        for remaining in (True, -1, "2"):
            with self.subTest(remaining=remaining), self.assertRaises(GameMasterError):
                AttemptState.parse({"remaining": remaining})

    def test_attempt_identity_changes_are_rejected(self):
        before = AttemptState(attempt_id="one", answer_ids=("a",))
        for after in (AttemptState(attempt_id="two"), AttemptState(answer_ids=("b",))):
            with self.assertRaises(GameMasterError):
                ensure_same_attempt(before, after)

    def test_remaining_zero_is_not_proof_of_completion(self):
        self.assertFalse(AttemptState.parse({"result": "accepted", "remaining": 0}).complete)
        self.assertTrue(AttemptState.parse({"result": "CORRECT", "status": "pending"}).pending)

    def test_sparse_responses_do_not_erase_known_identity(self):
        identity = remember_identity(AttemptState(), AttemptState(attempt_id="one"))
        identity = remember_identity(identity, AttemptState())
        with self.assertRaises(GameMasterError):
            remember_identity(identity, AttemptState(attempt_id="two"))

    def test_contradictory_completion_is_rejected(self):
        for response in ({"result": "incorrect", "status": "completed"},
                         {"result": "CORRECT", "remaining": 1}):
            with self.subTest(response=response), self.assertRaises(GameMasterError):
                AttemptState.parse(response)

    def test_redaction_preserves_answer_format(self):
        value = safe_value({
            "token": "secret", "expected_answer": "private", "expected_format": "flag{...}",
            "nested": {"detail": "echo secret"},
            "echo secret": "value",
        }, ("secret",))
        self.assertEqual(value["expected_format"], "flag{...}")
        self.assertEqual(value["token"], "[redacted]")
        self.assertEqual(value["nested"]["detail"], "echo [redacted]")
        self.assertIn("echo [redacted]", value)


if __name__ == "__main__":
    unittest.main()
