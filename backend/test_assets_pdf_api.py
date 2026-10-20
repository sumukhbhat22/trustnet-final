"""F-28 / F-32 API tests: permissions, validation, persistence, risk effect, PDF validity.

NOT EXECUTED in the authoring sandbox (FastAPI/bcrypt could not be installed offline). The
database-level logic is covered by test_asset_criticality_core and test_incident_report_core,
which were executed. Run this file in a networked environment: python -m unittest test_assets_pdf_api
"""
import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

_TMP = tempfile.TemporaryDirectory(prefix="trustnet-assets-tests-")
os.environ["TRUSTNET_DB_PATH"] = str(Path(_TMP.name) / "assets.db")

import main
from models.incident_store import maybe_create_risk_incident, reset_incidents
from models.risk_engine import compute_risk, record_signals, reset_risk_state
from models.security_auth import create_user, get_user_by_id, issue_access_token, list_users, reset_auth_state
from models.security_events import persist_security_event, verify_audit_chain


def _hdr(token):
    return {"Authorization": f"Bearer {token}"}


class AssetsAndPdfApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._ctx = TestClient(main.app)
        cls.client = cls._ctx.__enter__()
        reset_auth_state(); list_users()
        cls.admin = _hdr(issue_access_token(get_user_by_id("sumukh")))
        cls.analyst = _hdr(issue_access_token(get_user_by_id("alex_chen")))
        cls.viewer = _hdr(issue_access_token(create_user("viewer.assets@example.com", "ViewerPassw0rd!x", "viewer")))

    @classmethod
    def tearDownClass(cls):
        cls._ctx.__exit__(None, None, None)

    def setUp(self):
        reset_risk_state(); reset_incidents()

    def test_asset_list_requires_auth(self):
        self.assertEqual(self.client.get("/api/assets").status_code, 401)
        self.assertEqual(self.client.get("/api/assets", headers=self.viewer).status_code, 200)

    def test_criticality_update_permissions(self):
        url = "/api/assets/asset-people-api/criticality"
        self.assertEqual(self.client.put(url, json={"criticality": 4}).status_code, 401)
        self.assertEqual(self.client.put(url, headers=self.viewer, json={"criticality": 4}).status_code, 403)
        self.assertEqual(self.client.put(url, headers=self.analyst, json={"criticality": 4}).status_code, 403)
        ok = self.client.put(url, headers=self.admin, json={"criticality": 4})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertEqual(ok.json()["criticality"], 4)

    def test_criticality_validation(self):
        url = "/api/assets/asset-people-api/criticality"
        for body in ({"criticality": 0}, {"criticality": 6}, {"criticality": "3"}, {"criticality": 2.5},
                     {"criticality": True}, {}, {"criticality": 3, "extra": 1}):
            self.assertEqual(self.client.put(url, headers=self.admin, json=body).status_code, 422, body)
        self.assertEqual(self.client.put("/api/assets/unknown/criticality", headers=self.admin,
                                         json={"criticality": 3}).status_code, 404)

    def test_criticality_persists_audited_and_changes_risk(self):
        record_signals("sumukh", behavioral_score=10, anomaly_score=10, classifier_label="benign",
                       classifier_confidence=0, device_id=None, device_trust_status="trusted")
        persist_security_event({"user_id": "sumukh", "request_path": "/api/protected-assets/asset-people-api",
                                "http_method": "GET", "status_code": 403, "event_category": "protected_asset_access",
                                "event_payload": {"asset_id": "asset-people-api", "allowed": False}})
        url = "/api/assets/asset-people-api/criticality"
        self.client.put(url, headers=self.admin, json={"criticality": 1})
        low = compute_risk("sumukh")["score"]
        self.client.put(url, headers=self.admin, json={"criticality": 5})
        high = compute_risk("sumukh")["score"]
        self.assertGreater(high, low)
        listed = {a["asset_id"]: a["criticality"] for a in self.client.get("/api/assets", headers=self.viewer).json()["assets"]}
        self.assertEqual(listed["asset-people-api"], 5)
        self.assertTrue(verify_audit_chain()["valid"])

    def _incident(self):
        return maybe_create_risk_incident({"score": 85, "level": "high", "user_id": "sumukh", "device_id": None,
                                           "breakdown": {}, "thresholds": {"restrict": 60}}, evidence=["synthetic evidence"])

    def test_pdf_export_permissions_and_validity(self):
        incident = self._incident()
        url = f"/api/incidents/{incident['id']}/report.pdf"
        self.assertEqual(self.client.get(url).status_code, 401)
        self.assertEqual(self.client.get(url, headers=self.viewer).status_code, 403)
        ok = self.client.get(url, headers=self.analyst)
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertEqual(ok.headers["content-type"], "application/pdf")
        self.assertTrue(ok.content.startswith(b"%PDF-"))
        self.assertIn(b"%%EOF", ok.content[-64:])
        self.assertEqual(self.client.get("/api/incidents/INC-NOPE/report.pdf", headers=self.analyst).status_code, 404)
        self.assertTrue(verify_audit_chain()["valid"])


if __name__ == "__main__":
    unittest.main()
