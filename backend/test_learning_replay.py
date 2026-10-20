"""Tests for truthful analyst-feedback before/after evidence."""
import unittest
from agents.learning import build_incident_replay

class IncidentLearningReplayTests(unittest.TestCase):
    def test_without_verdict_returns_no_fake_comparison(self):
        result = build_incident_replay("INC-1", {"risk_score": 72}, None, None)
        self.assertEqual(result["status"], "no_feedback_effect")
        self.assertIsNone(result["score_before"])
        self.assertIsNone(result["score_after"])

    def test_persisted_comparison_includes_delta_and_policy_version(self):
        result = build_incident_replay("INC-2", {"risk_score": 81},
            {"verdict": "false_positive", "score_before": 81, "score_after": 76, "policy_version": 3, "delta": -5},
            {"baseline_version": 2, "risk_ema": 22.5})
        self.assertEqual(result["status"], "recorded")
        self.assertEqual(result["score_delta"], -5.0)
        self.assertEqual(result["policy_version"], 3)
        self.assertIn("no ML model retraining", result["learning_type"])

    def test_missing_incident_is_rejected(self):
        with self.assertRaises(ValueError):
            build_incident_replay("INC-missing", None, None, None)

if __name__ == "__main__":
    unittest.main()
