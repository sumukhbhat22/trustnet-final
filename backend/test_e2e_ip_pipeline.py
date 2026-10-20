"""Synthetic end-to-end regression for analyst-confirmed malicious IP signals.

Exercises indicator learning -> canonical IP matching -> persisted live scoring ->
incident evidence -> investigation -> audit integrity. It does not claim real-world
network detection accuracy; the IP and attack activity are synthetic test fixtures.
"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agents import learning, orchestrator, response
from agents.common import reset_agent_state
from models import database
from models.device_registry import register_login_device
from models.incident_store import list_incidents, maybe_create_risk_incident
from models.risk_engine import record_signals, reset_risk_state
from models.security_events import persist_security_event, verify_audit_chain


class E2EIPRiskPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_patch = patch.object(database, "_DB_PATH", str(Path(self.temp.name) / "ip-e2e.db"))
        self.db_patch.start()
        reset_risk_state()
        reset_agent_state()
        database.initialize_database()
        self.device = register_login_device("synthetic-victim", {"platform": "Linux", "userAgent": "Test/1", "screen": "e2e-ip"})

    def tearDown(self):
        reset_risk_state()
        self.db_patch.stop()
        self.temp.cleanup()

    def test_confirmed_ip_flows_into_risk_incident_investigation_and_audit(self):
        # An analyst-confirmed incident seeds an indicator in canonical IPv6 form.
        learning.update_behavior_profile(
            {"id": "INC-SEED-IP", "user_id": "prior-user", "risk_score": 95,
             "device_id": "prior-device", "ip_address": "2001:0db8:0:0:0:0:0:1"},
            "true_positive",
        )
        event = persist_security_event({
            "user_id": "synthetic-victim", "request_path": "/api/login/detect",
            "http_method": "POST", "status_code": 401,
            "event_category": "synthetic_suspicious_login",
            "event_payload": {"source": "test_fixture", "observed_ip": "2001:db8::1"},
        })
        risk = record_signals(
            "synthetic-victim", behavioral_score=95, anomaly_score=90,
            classifier_label="suspicious_login", classifier_confidence=90,
            device_id=self.device["device_id"], device_trust_status="unknown",
            ip_address="2001:db8::1",
        )
        self.assertTrue(risk["known_bad_indicators"]["ip_flagged"])
        self.assertEqual(risk["adjustments"]["known_bad_ip_points"], 25.0)
        self.assertIn("2001:db8::1", risk["ip_address"])

        incident = maybe_create_risk_incident(
            risk, evidence=["synthetic suspicious login from analyst-confirmed IP"], event_ids=[event["id"]]
        )
        self.assertIsNotNone(incident)
        self.assertIn("synthetic suspicious login", " ".join(incident["evidence"]))
        self.assertEqual(len(list_incidents()), 1)

        result = orchestrator.process_incident(incident["id"], "e2e-ip-test")
        self.assertTrue(result["ran"])
        self.assertIsNotNone(result["response"])
        # Recommendations are not automatically enforced; actions remain approval-gated.
        actions = response.list_actions(incident["id"])
        self.assertTrue(actions)
        self.assertTrue(all(a.get("status") for a in actions))
        self.assertTrue(verify_audit_chain()["valid"])

    def test_unlisted_ip_does_not_trigger_known_bad_ip_points(self):
        risk = record_signals(
            "clean-synthetic-user", behavioral_score=0, anomaly_score=0,
            classifier_label="benign", classifier_confidence=0,
            device_id=None, device_trust_status="trusted", ip_address="198.51.100.123",
        )
        self.assertFalse(risk["known_bad_indicators"]["ip_flagged"])
        self.assertEqual(risk["adjustments"]["known_bad_ip_points"], 0.0)


if __name__ == "__main__":
    unittest.main()
