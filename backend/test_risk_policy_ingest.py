"""Risk policy, verdict-feedback effect and event-ingest tests (real DB, real endpoints; synthetic inputs are labelled)."""

import os
from pathlib import Path
import tempfile
import uuid
import unittest

from fastapi.testclient import TestClient

_TMP = tempfile.TemporaryDirectory(prefix="trustnet-policy-tests-")
os.environ["TRUSTNET_DB_PATH"] = str(Path(_TMP.name) / "policy.db")
os.environ.pop("TRUSTNET_ALLOW_EXTERNAL_INGEST", None)

import main
from agents.common import reset_agent_state
from models import risk_policy
from models.database import get_db_connection
from models.device_registry import reset_devices
from models.incident_store import reset_incidents
from models.login_detector import reset_all_baselines
from models.network_monitor import reset_network_state
from models.risk_engine import compute_risk, record_signals, reset_risk_state
from models.security_auth import get_user_by_id, issue_access_token, list_users, reset_auth_state, create_user
from models.security_events import verify_audit_chain


def _hdr(token):
    return {"Authorization": f"Bearer {token}"}


class RiskPolicyIngestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._ctx = TestClient(main.app)
        cls.client = cls._ctx.__enter__()
        reset_auth_state(); list_users()
        cls.admin = _hdr(issue_access_token(get_user_by_id("sumukh")))
        cls.analyst = _hdr(issue_access_token(get_user_by_id("alex_chen")))
        viewer = create_user("viewer.policy@example.com", "ViewerPassw0rd!x", "viewer")
        cls.viewer = _hdr(issue_access_token(viewer))

    @classmethod
    def tearDownClass(cls):
        cls._ctx.__exit__(None, None, None)

    def setUp(self):
        reset_all_baselines(); reset_devices(); reset_risk_state(); reset_incidents(); reset_network_state()
        reset_agent_state(); main.reset_live_threat()
        self.client.put("/api/risk-policy", headers=self.admin, json={
            "weights": {"behavioral": 0.30, "anomaly": 0.20, "classifier": 0.10, "device_trust": 0.20, "network": 0.20, "geo": 0.0},
            "sensitivity": 1.0, "device_trust_enabled": True, "geo_enabled": True, "learning_rate": 0.25})

    def ingest(self, event_id, **extra):
        body = {"event_id": event_id, "user_id": "policy_user", "source": "synthetic", "request_path": "/login", **extra}
        return self.client.post("/api/events/ingest", headers=self.analyst, json=body)

    # ---- policy ----
    def test_policy_defaults_and_permissions(self):
        self.assertEqual(self.client.get("/api/risk-policy").status_code, 401)
        self.assertEqual(self.client.get("/api/risk-policy", headers=self.viewer).status_code, 200)
        self.assertEqual(self.client.put("/api/risk-policy", headers=self.viewer, json={"sensitivity": 1.2}).status_code, 403)
        self.assertEqual(self.client.put("/api/risk-policy", headers=self.analyst, json={"sensitivity": 1.2}).status_code, 403)

    def test_policy_validation(self):
        for bad in ({"sensitivity": 9}, {"sensitivity": "high"}, {"learning_rate": -1}, {"weights": {"nope": 0.1}},
                    {"weights": {"behavioral": 2}}, {"geo_enabled": "yes"}, {"surprise": 1},
                    {"weights": {"behavioral": 1, "anomaly": 0.5, "network": 0.5}}):
            r = self.client.put("/api/risk-policy", headers=self.admin, json=bad)
            self.assertEqual(r.status_code, 422, bad)

    def test_policy_change_bumps_version_and_is_audited(self):
        v1 = self.client.get("/api/risk-policy", headers=self.admin).json()["version"]
        r = self.client.put("/api/risk-policy", headers=self.admin, json={"sensitivity": 1.2})
        self.assertEqual(r.json()["version"], v1 + 1)
        noop = self.client.put("/api/risk-policy", headers=self.admin, json={"sensitivity": 1.2})
        self.assertEqual(noop.json()["version"], v1 + 1)  # no change -> no new version
        connection = get_db_connection()
        try:
            rows = connection.execute("SELECT COUNT(*) c FROM security_events WHERE event_category = 'policy_change'").fetchone()
        finally:
            connection.close()
        self.assertGreaterEqual(rows["c"], 1)
        self.assertTrue(verify_audit_chain()["valid"])

    def test_sensitivity_scales_score_and_cold_start_is_zero(self):
        self.assertEqual(compute_risk("nobody")["score"], 0.0 + compute_risk("nobody")["breakdown"]["device_trust"]["contribution"])
        record_signals("pol", behavioral_score=50, anomaly_score=50, classifier_label="benign", classifier_confidence=0,
                       device_id=None, device_trust_status="trusted")
        base = compute_risk("pol")["score"]
        self.client.put("/api/risk-policy", headers=self.admin, json={"sensitivity": 1.5})
        high = compute_risk("pol")
        self.client.put("/api/risk-policy", headers=self.admin, json={"sensitivity": 0.5})
        low = compute_risk("pol")["score"]
        self.assertAlmostEqual(high["score"], round(base * 1.5, 2), places=1)
        self.assertLess(low, base)
        self.assertEqual(high["policy"]["sensitivity"], 1.5)

    def test_device_trust_toggle_changes_decision_path(self):
        record_signals("dev", behavioral_score=0, anomaly_score=0, classifier_label="benign", classifier_confidence=0,
                       device_id=None, device_trust_status="flagged")
        on = compute_risk("dev")["score"]
        self.client.put("/api/risk-policy", headers=self.admin, json={"device_trust_enabled": False})
        off = compute_risk("dev")
        self.assertGreater(on, off["score"])
        self.assertEqual(off["breakdown"]["device_trust"]["contribution"], 0.0)

    def test_geo_toggle_and_weight(self):
        record_signals("geo", behavioral_score=0, anomaly_score=0, classifier_label="benign", classifier_confidence=0,
                       device_id=None, device_trust_status="trusted", geo_score=80)
        self.assertEqual(compute_risk("geo")["breakdown"]["geo"]["contribution"], 0.0)  # default weight 0
        self.client.put("/api/risk-policy", headers=self.admin, json={"weights": {"geo": 0.25}})
        self.assertEqual(compute_risk("geo")["breakdown"]["geo"]["contribution"], 20.0)
        self.client.put("/api/risk-policy", headers=self.admin, json={"geo_enabled": False})
        self.assertEqual(compute_risk("geo")["breakdown"]["geo"]["contribution"], 0.0)

    def test_threshold_boundary_creates_incident_only_at_restrict(self):
        # trusted device so only supplied signals count; 60 behavioural*0.30 etc. -> craft exact scores via weights
        self.client.put("/api/risk-policy", headers=self.admin, json={"weights": {"behavioral": 1.0, "anomaly": 0, "classifier": 0, "device_trust": 0, "network": 0}})
        below = self.ingest("EVT-BELOW-60", behavioral_score=60.99)
        self.assertEqual(below.status_code, 200)
        self.assertIsNone(below.json()["incident_id"])
        at = self.ingest("EVT-AT-61", behavioral_score=61)
        self.assertIsNotNone(at.json()["incident_id"])

    # ---- ingest ----
    def test_ingest_requires_auth_and_role(self):
        body = {"event_id": "EVT-AUTH-1", "user_id": "u"}
        self.assertEqual(self.client.post("/api/events/ingest", json=body).status_code, 401)
        self.assertEqual(self.client.post("/api/events/ingest", headers=self.viewer, json=body).status_code, 403)

    def test_ingest_validation_errors(self):
        bad_bodies = [
            {"user_id": "u"}, {"event_id": "x", "user_id": "u"}, {"event_id": "EVT-OK-001"},
            {"event_id": "EVT-OK-002", "user_id": "u", "source": "mystery"},
            {"event_id": "EVT-OK-003", "user_id": "u", "behavioral_score": 101},
            {"event_id": "EVT-OK-004", "user_id": "u", "behavioral_score": "high"},
            {"event_id": "EVT-OK-005", "user_id": "u", "behavioral_score": True},
            {"event_id": "EVT-OK-006", "user_id": "u", "http_method": "BREW"},
            {"event_id": "EVT-OK-007", "user_id": "u", "request_path": "no-slash"},
            {"event_id": "EVT-OK-008", "user_id": "bad user!"},
        ]
        for body in bad_bodies:
            r = self.client.post("/api/events/ingest", headers=self.analyst, json=body)
            self.assertEqual(r.status_code, 422, body)

    def test_external_source_refused_unless_configured(self):
        r = self.ingest("EVT-EXT-001", source="external")
        self.assertEqual(r.status_code, 403)
        os.environ["TRUSTNET_ALLOW_EXTERNAL_INGEST"] = "1"
        try:
            self.assertEqual(self.ingest("EVT-EXT-002", source="external").status_code, 200)
        finally:
            os.environ.pop("TRUSTNET_ALLOW_EXTERNAL_INGEST", None)

    def test_ingest_is_idempotent_and_labelled(self):
        first = self.ingest("EVT-IDEM-001", behavioral_score=90, anomaly_score=90, device_trust_status="flagged")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json()["data_label"], "synthetic/demo data")
        dup = self.ingest("EVT-IDEM-001", behavioral_score=90)
        self.assertTrue(dup.json()["duplicate"])
        self.assertFalse(dup.json()["accepted"])
        connection = get_db_connection()
        try:
            n = connection.execute("SELECT COUNT(*) c FROM security_events WHERE id = 'EVT-IDEM-001'").fetchone()["c"]
        finally:
            connection.close()
        self.assertEqual(n, 1)

    def test_ingest_correlates_into_one_incident(self):
        self.client.put("/api/risk-policy", headers=self.admin, json={"weights": {"behavioral": 1.0, "anomaly": 0, "classifier": 0, "device_trust": 0, "network": 0}})
        a = self.ingest("EVT-CORR-001", behavioral_score=95)
        b = self.ingest("EVT-CORR-002", behavioral_score=96)
        self.assertIsNotNone(a.json()["incident_id"])
        self.assertEqual(a.json()["incident_id"], b.json()["incident_id"])
        incidents = [i for i in self.client.get("/api/incidents", headers=self.admin).json()["incidents"] if i["user_id"] == "policy_user"] \
            if isinstance(self.client.get("/api/incidents", headers=self.admin).json(), dict) else \
            [i for i in self.client.get("/api/incidents", headers=self.admin).json() if i["user_id"] == "policy_user"]
        self.assertEqual(len(incidents), 1)

    def test_missing_scores_keep_previous_signal_not_invented(self):
        self.ingest("EVT-KEEP-001", behavioral_score=40)
        r = self.ingest("EVT-KEEP-002")  # no scores supplied
        self.assertEqual(r.json()["risk"]["breakdown"]["behavioral"]["score"], 40.0)

    def test_ingest_pushes_live_websocket_update(self):
        ticket = self.client.post("/api/auth/ws-ticket", headers=self.admin).json()["ticket"]
        with self.client.websocket_connect(f"/ws/admin?ticket={ticket}") as ws:
            self.ingest("EVT-WS-0001", behavioral_score=70)
            seen = {}
            for _ in range(6):
                msg = ws.receive_json()
                seen[msg["type"]] = msg
                if "event_ingested" in seen and "dashboard_update" in seen:
                    break
        self.assertEqual(seen["event_ingested"]["event_id"], "EVT-WS-0001")
        self.assertEqual(seen["event_ingested"]["source"], "synthetic")

    # ---- dashboard summary contract ----
    def test_summary_aliases_match_legacy_fields_and_follow_ingested_data(self):
        empty = self.client.get("/api/dashboard/summary", headers=self.viewer).json()
        self.assertEqual(empty["systemRisk"], 0.0)
        self.assertEqual(empty["openIncidents"], 0)
        self.client.put("/api/risk-policy", headers=self.admin, json={"weights": {"behavioral": 1.0, "anomaly": 0, "classifier": 0, "device_trust": 0, "network": 0}})
        self.ingest(f"EVT-SUM-{uuid.uuid4().hex[:8]}", behavioral_score=88)
        s = self.client.get("/api/dashboard/summary", headers=self.viewer).json()
        self.assertEqual(s["systemRisk"], s["overall_risk"]["maximum"])
        self.assertEqual(s["avgUserRisk"], s["overall_risk"]["average"])
        self.assertEqual(s["openIncidents"], s["active_incident_count"])
        self.assertEqual(s["networkAnomalies"], s["network_anomalies"])
        self.assertEqual(s["systemRisk"], 88.0)
        self.assertEqual(s["openIncidents"], 1)
        self.assertEqual(s["dataSource"], "runtime")
        self.assertIn("generated_at", s)
        self.assertEqual(self.client.get("/api/dashboard/summary").status_code, 401)

    # ---- verdict feedback ----
    def _incident_for_policy_user(self):
        self.client.put("/api/risk-policy", headers=self.admin, json={"weights": {"behavioral": 1.0, "anomaly": 0, "classifier": 0, "device_trust": 0, "network": 0}})
        r = self.ingest(f"EVT-VERD-{uuid.uuid4().hex[:10]}", behavioral_score=80)
        return r.json()["incident_id"]

    def test_verdict_changes_later_score_with_before_after(self):
        incident_id = self._incident_for_policy_user()
        before = compute_risk("policy_user")["score"]
        r = self.client.post(f"/api/incidents/{incident_id}/verdict", headers=self.admin, json={"verdict": "false_positive", "notes": "known admin task"})
        self.assertEqual(r.status_code, 200, r.text)
        effect = r.json()["score_effect"]
        self.assertEqual(effect["score_before"], before)
        self.assertEqual(effect["score_after"], round(before - 5.0, 2))  # 0.25 * 20
        self.assertIn("no ML model is retrained", effect["mechanism"])
        self.assertEqual(compute_risk("policy_user")["score"], effect["score_after"])  # persists to later evaluations
        self.assertEqual(compute_risk("policy_user")["adjustments"]["analyst_feedback_points"], -5.0)

    def test_duplicate_verdict_does_not_double_apply_and_correction_replaces(self):
        incident_id = self._incident_for_policy_user()
        url = f"/api/incidents/{incident_id}/verdict"
        self.client.post(url, headers=self.admin, json={"verdict": "false_positive"})
        dup = self.client.post(url, headers=self.admin, json={"verdict": "false_positive"}).json()
        self.assertTrue(dup["duplicate"])
        self.assertEqual(risk_policy.user_adjustment("policy_user"), -5.0)
        self.client.post(url, headers=self.admin, json={"verdict": "true_positive"})  # correction
        self.assertEqual(risk_policy.user_adjustment("policy_user"), 5.0)

    def test_learning_rate_scales_and_zero_disables_effect(self):
        incident_id = self._incident_for_policy_user()
        self.client.put("/api/risk-policy", headers=self.admin, json={"learning_rate": 0.0})
        r = self.client.post(f"/api/incidents/{incident_id}/verdict", headers=self.admin, json={"verdict": "false_positive"})
        self.assertEqual(r.json()["score_effect"]["score_before"], r.json()["score_effect"]["score_after"])

    def test_verdict_permissions_and_invalid(self):
        incident_id = self._incident_for_policy_user()
        url = f"/api/incidents/{incident_id}/verdict"
        self.assertEqual(self.client.post(url, json={"verdict": "true_positive"}).status_code, 401)
        self.assertEqual(self.client.post(url, headers=self.viewer, json={"verdict": "true_positive"}).status_code, 403)
        self.assertEqual(self.client.post(url, headers=self.admin, json={"verdict": "maybe"}).status_code, 422)

    def test_adjustment_is_bounded(self):
        for i in range(10):
            risk_policy.record_verdict_effect(incident_id=f"INC-X{i}", user_id="cap", verdict="true_positive", feedback_id=f"F{i}",
                                              score_before=0, score_after_fn=lambda: 0)
        self.assertEqual(risk_policy.user_adjustment("cap"), risk_policy.MAX_USER_ADJUSTMENT)


if __name__ == "__main__":
    unittest.main()
