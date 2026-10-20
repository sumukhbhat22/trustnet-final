"""Regression tests for the risk-based response ladder."""
import unittest
from unittest.mock import patch

from agents.response import decide


class ResponseRiskLadderTests(unittest.TestCase):
    def investigation(self, verdict="suspicious"):
        return {"verdict": verdict, "confidence": 0.7, "fired_rules": ["elevated_risk"], "attack_type": {"type": "unknown", "evidence_summary": {}}}

    @patch("agents.response.get_user_by_id", return_value={"id": "user-1", "role": "viewer"})
    def test_risk_61_to_85_proposes_read_only_session_restriction(self, _user):
        decision = decide({"id": "INC-1", "user_id": "user-1", "device_id": None, "risk_score": 72}, self.investigation())
        self.assertEqual(decision["action"], "restrict_session")
        self.assertEqual(decision["target"], "user-1")
        self.assertIn("human approval", decision["rationale"])

    @patch("agents.response.get_user_by_id", return_value={"id": "user-1", "role": "viewer"})
    def test_medium_risk_requires_mfa(self, _user):
        decision = decide({"id": "INC-4", "user_id": "user-1", "device_id": None, "risk_score": 45}, self.investigation())
        self.assertEqual(decision["action"], "require_mfa")

    @patch("agents.response.get_user_by_id", return_value={"id": "user-1", "role": "viewer"})
    def test_critical_risk_proposes_human_approved_block(self, _user):
        decision = decide({"id": "INC-5", "user_id": "user-1", "device_id": None, "risk_score": 90}, self.investigation())
        self.assertEqual(decision["action"], "temp_block_account")

    @patch("agents.response.get_user_by_id", return_value={"id": "user-1", "role": "viewer"})
    def test_low_risk_stays_monitoring(self, _user):
        decision = decide({"id": "INC-2", "user_id": "user-1", "device_id": None, "risk_score": 25}, self.investigation("benign"))
        self.assertEqual(decision["action"], "monitor")

    @patch("agents.response.get_user_by_id", return_value={"id": "user-1", "role": "viewer"})
    def test_high_confidence_malicious_path_keeps_containment(self, _user):
        decision = decide({"id": "INC-3", "user_id": "user-1", "device_id": "device-1", "risk_score": 95}, self.investigation("likely_malicious"))
        self.assertEqual(decision["action"], "quarantine_device")


if __name__ == "__main__":
    unittest.main()
