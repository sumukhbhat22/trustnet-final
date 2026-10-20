"""Focused tests for duplicate analyst-verdict handling."""
import unittest

from agents.learning import is_duplicate_verdict


class LearningIdempotencyTests(unittest.TestCase):
    def test_same_verdict_is_duplicate(self):
        self.assertTrue(is_duplicate_verdict({"verdict": "true_positive"}, "true_positive"))

    def test_different_verdict_is_allowed_as_correction(self):
        self.assertFalse(is_duplicate_verdict({"verdict": "true_positive"}, "false_positive"))

    def test_missing_previous_verdict_is_not_duplicate(self):
        self.assertFalse(is_duplicate_verdict(None, "true_positive"))


if __name__ == "__main__":
    unittest.main()
