"""End-to-end workflow on a real temp SQLite DB (synthetic input, labelled):
signals -> single risk engine -> correlated incident (deduplicated) -> investigator -> response recommendation
-> human approval required -> approved enforcement (really quarantines) -> timeline/audit -> analyst verdict
-> observable change in later scoring -> PDF report. Uses a FastAPI stand-in only if FastAPI is not installed."""
import sys
import tempfile
import types
import unittest
from pathlib import Path

try:
    import fastapi  # noqa: F401
except ImportError:
    _fake = types.ModuleType("fastapi")

    class HTTPException(Exception):
        def __init__(self, status_code=500, detail=None, headers=None):
            super().__init__(detail)
            self.status_code, self.detail = status_code, detail

    _fake.HTTPException = HTTPException
    sys.modules["fastapi"] = _fake

from models import database
from models.device_registry import get_device, register_login_device
from models.incident_store import get_incident, list_incidents, maybe_create_risk_incident
from models.incident_report import generate_incident_pdf
from models.risk_engine import compute_risk, record_signals, reset_risk_state
from models.security_events import persist_security_event, verify_audit_chain
from agents import orchestrator, response
from agents.common import list_activity, reset_agent_state

FP = {"platform": "Linux", "userAgent": "Chrome/120", "screen": "e2e"}


class E2EPipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.orig = database._DB_PATH
        database._DB_PATH = str(Path(self.tmp.name) / "e2e.db")
        database.initialize_database()
        reset_risk_state(); reset_agent_state()
        self.device = register_login_device("victim", FP)

    def tearDown(self):
        database._DB_PATH = self.orig
        self.tmp.cleanup()

    def _attack(self):
        event = persist_security_event({"user_id": "victim", "request_path": "/api/protected-assets/admin-db",
                                        "http_method": "GET", "status_code": 403, "event_category": "protected_asset_access",
                                        "event_payload": {"asset_id": "admin-db", "allowed": False, "source": "synthetic"}})
        for path in ("finance-db", "hr-records", "file-export-log"):  # synthetic burst of flagged, denied requests
            persist_security_event({"user_id": "victim", "request_path": f"/api/protected-assets/{path}", "http_method": "GET",
                                    "status_code": 403, "event_category": "protected_asset_access",
                                    "risk_indicators": ["access_denied", "sensitive_asset"],
                                    "event_payload": {"asset_id": path, "allowed": False, "source": "synthetic"}})
        risk = record_signals("victim", behavioral_score=95, anomaly_score=95, classifier_label="unauthorized_sensitive_access",
                              classifier_confidence=95, device_id=self.device["device_id"], device_trust_status="unknown")
        incident = maybe_create_risk_incident(risk, evidence=["synthetic denied access to admin-db"], event_ids=[event["id"]])
        return risk, incident

    def test_full_workflow(self):
        risk, incident = self._attack()
        self.assertGreaterEqual(risk["score"], risk["thresholds"]["restrict"])
        self.assertIsNotNone(incident)

        # duplicate/correlated signal must not create a second incident
        again = maybe_create_risk_incident(compute_risk("victim"), evidence=["more"], event_ids=[])
        self.assertEqual(len(list_incidents()), 1)
        self.assertEqual(again["id"], incident["id"])

        summary = orchestrator.process_incident(incident["id"], "e2e")
        self.assertTrue(summary["ran"])
        self.assertIsNotNone(summary["response"])
        # idempotent: an unchanged incident is not re-investigated
        self.assertFalse(orchestrator.process_incident(incident["id"], "e2e")["ran"])

        actions = response.list_actions(incident["id"])
        quarantine = [a for a in actions if a["action"] == "quarantine_device"]
        self.assertTrue(quarantine, f'expected a quarantine proposal, got {[a["action"] for a in actions]}')
        if quarantine:
            # recommendation is NOT enforcement: default autonomy must leave it pending a human
            self.assertEqual(quarantine[-1]["status"], "pending_approval")
            self.assertFalse(get_device(self.device["device_id"])["quarantined"])
            with self.assertRaises(response.ResponseError):
                response.approve(quarantine[-1]["id"], {"id": "viewer-1", "role": "viewer"})
            self.assertFalse(get_device(self.device["device_id"])["quarantined"])
            done = response.approve(quarantine[-1]["id"], {"id": "analyst-1", "role": "analyst"})
            self.assertEqual(done["status"], "executed")
            self.assertTrue(get_device(self.device["device_id"])["quarantined"])
            self.assertIn("executed", [a["action"] for a in list_activity(50, incident["id"])])

        # analyst verdict -> bounded feedback adjustment -> later score differs
        before = compute_risk("victim")["score"]
        result = orchestrator.submit_verdict(incident["id"], "false_positive", "synthetic benign", {"id": "analyst-1", "role": "analyst"})
        self.assertFalse(result["duplicate"])
        after = compute_risk("victim")["score"]
        self.assertLess(after, before)
        self.assertEqual(result["score_effect"]["score_after"], after)
        dup = orchestrator.submit_verdict(incident["id"], "false_positive", "retry", {"id": "analyst-1", "role": "analyst"})
        self.assertTrue(dup["duplicate"])
        self.assertEqual(compute_risk("victim")["score"], after)  # retry does not double-apply

        self.assertTrue(verify_audit_chain()["valid"])
        pdf = generate_incident_pdf(incident["id"])
        self.assertTrue(pdf.startswith(b"%PDF-"))

    def test_self_verdict_denied(self):
        _, incident = self._attack()
        with self.assertRaises(response.ResponseError) as ctx:
            orchestrator.submit_verdict(incident["id"], "true_positive", "", {"id": "victim", "role": "analyst"})
        self.assertEqual(ctx.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
