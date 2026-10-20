"""Regression tests for the persisted demo EMA learning profile."""
import unittest
from uuid import uuid4

from agents import learning


class BehaviorLearningProfileTests(unittest.TestCase):
    def test_false_positive_lowers_ema_and_versions_baseline(self):
        user = f"learning-profile-test-{uuid4().hex}"
        first = learning.update_behavior_profile(
            {"id": "INC-LP-1", "user_id": user, "risk_score": 80, "device_id": "dev-lp-1", "ip_address": "192.0.2.7"},
            "true_positive",
        )
        self.assertEqual(first["profile"]["baseline_version"], 1)
        self.assertEqual(len(first["known_bad_added"]), 2)
        second = learning.update_behavior_profile(
            {"id": "INC-LP-2", "user_id": user, "risk_score": 80, "device_id": "dev-lp-1", "ip_address": "192.0.2.7"},
            "false_positive",
        )
        self.assertLess(second["profile"]["risk_ema_after"], second["profile"]["risk_ema_before"])
        self.assertEqual(second["profile"]["baseline_version"], 2)
        self.assertEqual(second["known_bad_added"], [])
        self.assertIn("no ML model was retrained", second["note"])

    def test_alpha_validation(self):
        with self.assertRaises(ValueError):
            learning.update_behavior_profile({"id": "INC-X", "user_id": "x", "risk_score": 1}, "false_positive", alpha=0)


if __name__ == "__main__":
    unittest.main()
