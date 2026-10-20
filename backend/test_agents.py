"""Integration tests for the Investigator -> Response -> Feedback -> Orchestrator pipeline."""

import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from uuid import uuid4

_DIR = tempfile.TemporaryDirectory(prefix="trustnet-agent-tests-")
os.environ["TRUSTNET_DB_PATH"] = str(Path(_DIR.name) / "agents-test.db")

from fastapi.testclient import TestClient

import main
from agents import learning, notifier, orchestrator, response
from agents.common import get_settings, reset_agent_state, update_settings
from agents.investigator import EvidenceTools, investigate
from models.database import get_db_connection, get_readonly_connection
from models.device_registry import get_device, register_login_device, reset_devices
from models.incident_store import get_incident, list_incidents, reset_incidents
from models.login_detector import reset_all_baselines
from models.network_monitor import reset_network_state
from models.risk_engine import record_signals, reset_risk_state
from models.security_auth import create_user, get_user_by_id, issue_access_token, list_users, reset_auth_state
from models.security_events import verify_audit_chain

FP = {"userAgent": "agent-test", "platform": "test-os", "language": "en-US", "screenResolution": "1280x720",
      "timezone": "UTC", "canvasHash": "agent-dev", "webglRenderer": "gpu", "hardwareConcurrency": 8,
      "colorDepth": 24, "deviceType": "desktop"}


def bearer(user_id: str) -> dict:
    return {"Authorization": f"Bearer {issue_access_token(get_user_by_id(user_id))}"}


class AgentPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx = TestClient(main.app)
        cls.client = cls.ctx.__enter__()
        reset_auth_state()
        list_users()
        if get_user_by_id("viewer1") is None:
            create_user("viewer1@trustnet.local", "ViewerPassw0rd!!", "viewer", user_id="viewer1")
        cls.admin = bearer("sumukh")
        cls.analyst = bearer("alex_chen")
        cls.viewer = bearer("viewer1")

    @classmethod
    def tearDownClass(cls):
        cls.ctx.__exit__(None, None, None)

    def setUp(self):
        reset_all_baselines(); reset_devices(); reset_risk_state(); reset_incidents(); reset_network_state()
        reset_agent_state(); notifier.set_transport_override(None)
        main.reset_live_threat()
        # Keep login evidence isolated between tests. The database is shared by this
        # test class, so old attempts must not influence later investigations.
        conn = get_db_connection()
        try:
            conn.execute("DELETE FROM login_attempts")
            conn.commit()
        finally:
            conn.close()

    def make_incident(self, user="victim", failed_logins=0, headers=None):
        device = register_login_device(user, {**FP, "canvasHash": f"dev-{user}"})
        if failed_logins:
            conn = get_db_connection()
            from datetime import datetime, timezone
            try:
                for i in range(failed_logins):
                    conn.execute("INSERT INTO login_attempts (attempt_id, user_id, timestamp, success, ip, device_id, reason) VALUES (?,?,?,?,?,?,?)",
                                 (f"A-{uuid4().hex}", user, datetime.now(timezone.utc).isoformat(), 0, f"10.0.0.{i + 1}", device["device_id"], "bad_password"))
                conn.commit()
            finally:
                conn.close()
        record_signals(user, behavioral_score=95, anomaly_score=95, classifier_label="credential_theft",
                       classifier_confidence=99, device_id=device["device_id"], device_trust_status="unknown")
        r = self.client.get(f"/api/risk/{user}", headers=headers or self.admin)
        self.assertEqual(r.status_code, 200)
        return r.json()["incident"], device

    # --- pipeline ---
    def test_event_to_incident_to_investigation_to_pending_approval_with_audit(self):
        incident, device = self.make_incident()
        self.assertTrue(incident["incident_label"].startswith("TN-"))
        view = self.client.get(f"/api/incidents/{incident['id']}/agent", headers=self.admin).json()
        self.assertIsNotNone(view["investigation"])
        self.assertTrue(view["investigation"]["read_only"])
        self.assertIn(view["investigation"]["attack_type"]["type"], {
            "stolen_credentials", "brute_force", "data_exfiltration", "after_hours_insider", "unknown"
        })
        self.assertEqual({r["rule_id"] for r in view["investigation"]["rules"]}, set(learning.DEFAULT_WEIGHTS))
        quarantine = [a for a in view["responses"] if a["action"] in {"quarantine_device", "notify_analyst"}]
        self.assertTrue(quarantine, view["responses"])
        # default autonomy is 'recommend': nothing destructive happened without a human
        self.assertFalse(get_device(device["device_id"])["quarantined"])
        self.assertTrue(any(a["status"] != "executed" for a in view["responses"] if a["action"] == "quarantine_device") or
                        not any(a["action"] == "quarantine_device" for a in view["responses"]))
        self.assertTrue(any(a["agent"] == "investigator" for a in view["activity"]))
        audit_result = verify_audit_chain()
        self.assertTrue(audit_result["valid"], audit_result)
        conn = get_db_connection()
        count = conn.execute("SELECT COUNT(*) FROM security_events WHERE event_category='agent_action'").fetchone()[0]
        conn.close()
        self.assertGreaterEqual(count, 1)

    def test_orchestrator_is_idempotent(self):
        incident, _ = self.make_incident()
        first = len(response.list_actions(incident["id"]))
        orchestrator.process_incident(incident["id"], "again")
        orchestrator.process_incident(incident["id"], "again")
        self.assertEqual(len(response.list_actions(incident["id"])), first)
        self.assertEqual(len(list_incidents()), 1)

    def test_human_approval_enforces_quarantine_and_blocks_session(self):
        incident, device = self.make_incident(user="victim2", failed_logins=3)
        view = self.client.get(f"/api/incidents/{incident['id']}/agent", headers=self.admin).json()
        self.assertEqual(view["investigation"]["verdict"], "likely_malicious")
        pending = [a for a in view["responses"] if a["action"] == "quarantine_device"][0]
        self.assertEqual(pending["status"], "pending_approval")
        self.assertFalse(get_device(device["device_id"])["quarantined"])
        approved = self.client.post(f"/api/incidents/{incident['id']}/responses/{pending['id']}/approve", headers=self.analyst)
        self.assertEqual(approved.status_code, 200, approved.text)
        self.assertEqual(approved.json()["response"]["status"], "executed")
        self.assertTrue(get_device(device["device_id"])["quarantined"])
        # second approval of the same action is rejected
        again = self.client.post(f"/api/incidents/{incident['id']}/responses/{pending['id']}/approve", headers=self.analyst)
        self.assertEqual(again.status_code, 409)
        self.assertTrue(verify_audit_chain()["valid"])

    def test_viewer_cannot_approve_or_judge(self):
        incident, _ = self.make_incident(user="victim3", failed_logins=3)
        action = [a for a in response.list_actions(incident["id"]) if a["action"] == "quarantine_device"][0]
        self.assertEqual(self.client.post(f"/api/incidents/{incident['id']}/responses/{action['id']}/approve", headers=self.viewer).status_code, 403)
        self.assertEqual(self.client.post(f"/api/incidents/{incident['id']}/verdict", json={"verdict": "true_positive"}, headers=self.viewer).status_code, 403)
        self.assertEqual(self.client.post(f"/api/incidents/{incident['id']}/responses/{action['id']}/approve").status_code, 401)

    def test_agent_response_cannot_be_self_approved(self):
        incident, _ = self.make_incident(user="sumukh", failed_logins=3)  # admin 'sumukh' is the target
        action = [a for a in response.list_actions(incident["id"]) if a["action"] == "quarantine_device"][0]
        r = self.client.post(f"/api/incidents/{incident['id']}/responses/{action['id']}/approve", headers=self.admin)
        self.assertEqual(r.status_code, 403)

    def _pending(self, user):
        incident, device = self.make_incident(user=user, failed_logins=3)
        action = [a for a in response.list_actions(incident["id"]) if a["action"] == "quarantine_device"][0]
        self.assertEqual(action["status"], "pending_approval")
        self.assertIsNotNone(action["expires_at"])
        return incident, device, action

    def test_legacy_incident_approve_rejects_self_approval(self):
        incident, device = self.make_incident(user="sumukh", failed_logins=3)
        r = self.client.post(f"/api/incidents/{incident['id']}/approve", headers=self.admin)
        self.assertEqual(r.status_code, 403)
        self.assertFalse(get_device(device["device_id"])["quarantined"])

    def test_legacy_incident_approve_records_request_then_decision(self):
        incident, device = self.make_incident(user="victim20", failed_logins=3)
        r = self.client.post(f"/api/incidents/{incident['id']}/approve", headers=self.analyst)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(get_device(device["device_id"])["quarantined"])
        conn = get_db_connection()
        paths = [row[0] for row in conn.execute("SELECT request_path FROM security_events WHERE event_category='agent_action'")]
        conn.close()
        self.assertIn("/agents/response/approval_granted", paths)
        self.assertIn("/agents/response/executed", paths)
        self.assertTrue(verify_audit_chain()["valid"])

    def test_expired_approval_is_rejected_with_409_and_not_executed(self):
        incident, device, action = self._pending("victim21")
        conn = get_db_connection()
        conn.execute("UPDATE response_actions SET expires_at = ? WHERE id = ?", ("2000-01-01T00:00:00+00:00", action["id"]))
        conn.commit(); conn.close()
        r = self.client.post(f"/api/incidents/{incident['id']}/responses/{action['id']}/approve", headers=self.analyst)
        self.assertEqual(r.status_code, 409)
        self.assertFalse(get_device(device["device_id"])["quarantined"])
        self.assertEqual(response.get_action(action["id"])["status"], "expired")

    def test_concurrent_approvals_execute_exactly_once(self):
        import threading
        incident, device, action = self._pending("victim22")
        results = []
        def go():
            try:
                results.append(response.approve(action["id"], get_user_by_id("alex_chen"))["status"])
            except response.ResponseError as error:
                results.append(error.status_code)
        threads = [threading.Thread(target=go) for _ in range(6)]
        [t.start() for t in threads]; [t.join() for t in threads]
        self.assertEqual(results.count("executed"), 1, results)
        self.assertEqual(results.count(409), 5, results)

    def test_decided_approval_returns_409_on_reject_after_approve(self):
        incident, device, action = self._pending("victim23")
        self.assertEqual(self.client.post(f"/api/incidents/{incident['id']}/responses/{action['id']}/approve", headers=self.analyst).status_code, 200)
        self.assertEqual(self.client.post(f"/api/incidents/{incident['id']}/responses/{action['id']}/reject", json={}, headers=self.analyst).status_code, 409)

    def test_execute_without_pending_approval_is_not_possible_via_api(self):
        incident, device, action = self._pending("victim24")
        self.client.post(f"/api/incidents/{incident['id']}/responses/{action['id']}/reject", json={}, headers=self.analyst)
        r = self.client.post(f"/api/incidents/{incident['id']}/responses/{action['id']}/approve", headers=self.analyst)
        self.assertEqual(r.status_code, 409)
        self.assertFalse(get_device(device["device_id"])["quarantined"])

    def _blocked_incident(self, user):
        """Incident with no device -> Response agent should propose a temporary account block."""
        from models.incident_store import maybe_create_risk_incident
        from models.risk_engine import compute_risk
        conn = get_db_connection()
        from datetime import datetime, timezone
        for i in range(3):
            conn.execute("INSERT INTO login_attempts (attempt_id, user_id, timestamp, success, ip, device_id, reason) VALUES (?,?,?,?,?,?,?)",
                         (f"B-{user}-{i}", user, datetime.now(timezone.utc).isoformat(), 0, f"10.1.0.{i + 1}", None, "bad_password"))
        conn.commit(); conn.close()
        record_signals(user, behavioral_score=95, anomaly_score=95, classifier_label="credential_theft", classifier_confidence=99,
                       device_id=None, device_trust_status="unknown")
        incident = maybe_create_risk_incident(compute_risk(user))
        self.assertIsNotNone(incident)
        orchestrator.process_incident(incident["id"], "test")
        return get_incident(incident["id"])

    def test_account_block_requires_human_approval_enforces_and_expires(self):
        from models.account_restrictions import active_restriction
        create_user("blockme@trustnet.local", "BlockMePassw0rd!!", "viewer", user_id="blockme")
        incident = self._blocked_incident("blockme")
        acts = [a for a in response.list_actions(incident["id"]) if a["action"] == "temp_block_account"]
        self.assertTrue(acts and acts[0]["status"] == "pending_approval")
        self.assertIsNone(active_restriction("blockme"))  # nothing enforced without a human
        # even with Autonomous Mode ON a sensitive account action is never automatic
        update_settings({"autonomy_mode": "auto_contain"})
        orchestrator.process_incident(incident["id"], "again", force=True)
        self.assertIsNone(active_restriction("blockme"))
        token = bearer("blockme")
        self.assertEqual(self.client.get("/api/auth/me", headers=token).status_code, 200)
        r = self.client.post(f"/api/incidents/{incident['id']}/responses/{acts[0]['id']}/approve", headers=self.analyst)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIsNotNone(active_restriction("blockme"))
        self.assertEqual(self.client.get("/api/auth/me", headers=token).status_code, 403)          # token no longer works
        self.assertEqual(self.client.get("/api/incidents", headers=token).status_code, 403)        # alternate route too
        self.assertEqual(self.client.get("/api/auth/me", headers=self.admin).status_code, 200)     # unrelated users unaffected
        # expiry: move expiry into the past, access returns without any manual step
        conn = get_db_connection()
        conn.execute("UPDATE account_restrictions SET expires_at = ? WHERE user_id = ?", ("2000-01-01T00:00:00+00:00", "blockme"))
        conn.commit(); conn.close()
        self.assertIsNone(active_restriction("blockme"))
        self.assertEqual(self.client.get("/api/auth/me", headers=token).status_code, 200)
        self.assertTrue(verify_audit_chain()["valid"])

    def test_privileged_accounts_are_never_restricted(self):
        from models.account_restrictions import create_restriction
        with self.assertRaises(ValueError):
            create_restriction(get_user_by_id("alex_chen"), minutes=10, incident_id=None, action_id=None, actor="test")
        with self.assertRaises(ValueError):
            create_restriction(get_user_by_id("sumukh"), minutes=10, incident_id=None, action_id=None, actor="test")

    def test_restriction_release_and_permanent_block_refused(self):
        from models.account_restrictions import active_restriction, create_restriction, release_restriction
        create_user("rel@trustnet.local", "ReleasePassw0rd!!", "viewer", user_id="rel")
        with self.assertRaises(ValueError):
            create_restriction(get_user_by_id("rel"), minutes=10**7, incident_id=None, action_id=None, actor="t")
        item = create_restriction(get_user_by_id("rel"), minutes=10, incident_id=None, action_id=None, actor="t")
        self.assertIsNotNone(active_restriction("rel"))
        self.assertEqual(self.client.post(f"/api/account-restrictions/{item['id']}/release", headers=self.viewer).status_code, 403)
        self.assertEqual(self.client.post(f"/api/account-restrictions/{item['id']}/release", headers=self.analyst).status_code, 200)
        self.assertEqual(self.client.post(f"/api/account-restrictions/{item['id']}/release", headers=self.analyst).status_code, 409)
        self.assertIsNone(active_restriction("rel"))

    def test_stuck_executing_approval_is_recovered_as_failed_not_rerun(self):
        incident, device, action = self._pending("victim30")
        conn = get_db_connection()
        conn.execute("UPDATE response_actions SET status='executing', updated_at=? WHERE id=?", ("2000-01-01T00:00:00+00:00", action["id"]))
        conn.commit(); conn.close()
        self.assertEqual(response.recover_stuck(incident["id"]), 1)
        self.assertEqual(response.get_action(action["id"])["status"], "failed")
        self.assertFalse(get_device(device["device_id"])["quarantined"])

    def test_reject_blocks_future_auto_execution(self):
        incident, device = self.make_incident(user="victim4", failed_logins=3)
        action = [a for a in response.list_actions(incident["id"]) if a["action"] == "quarantine_device"][0]
        r = self.client.post(f"/api/incidents/{incident['id']}/responses/{action['id']}/reject", json={"reason": "known travel"}, headers=self.analyst)
        self.assertEqual(r.status_code, 200)
        self.assertFalse(get_device(device["device_id"])["quarantined"])
        checks = response.evaluate_safeguards(get_incident(incident["id"]), get_incident(incident["id"])["investigator_findings"],
                                              {"action": "quarantine_device", "target": device["device_id"]})
        self.assertFalse(next(c for c in checks if c["name"] == "no_prior_analyst_rejection")["passed"])

    def test_real_login_pipeline_failed_logins_are_investigated(self):
        atk = {**FP, "canvasHash": "attacker-box", "userAgent": "curl-bot", "deviceType": "server"}
        self.client.post("/api/login", json={"username": "sumukh", "password": "sumukh@123", "fingerprint": FP})
        for _ in range(3):
            self.client.post("/api/login", json={"username": "sumukh", "password": "wrong-pass-1", "fingerprint": atk})
        incidents = [i for i in list_incidents() if i["user_id"] == "sumukh"]
        self.assertEqual(len(incidents), 1)
        findings = incidents[0]["investigator_findings"]
        self.assertIsNotNone(findings, "agents must run on incidents created by the failed-login path")
        self.assertIn("credential_attack", findings["fired_rules"])
        actions = response.list_actions(incidents[0]["id"])
        self.assertTrue(actions and all(a["status"] == "executed" for a in actions if a["action"] == "notify_analyst"))
        self.assertTrue(verify_audit_chain()["valid"])

    # --- autonomy safeguards ---
    def test_autonomous_containment_only_when_all_safeguards_pass(self):
        update_settings({"autonomy_mode": "auto_contain", "auto_min_confidence": 0.7})
        incident, device = self.make_incident(user="victim5", failed_logins=3)
        self.assertTrue(get_device(device["device_id"])["quarantined"])
        executed = [a for a in response.list_actions(incident["id"]) if a["action"] == "quarantine_device"][0]
        self.assertEqual((executed["status"], executed["mode"]), ("executed", "auto"))
        self.assertTrue(all(c["passed"] for c in executed["safeguards"]))

    def test_kill_switch_and_privileged_accounts_force_human_approval(self):
        update_settings({"autonomy_mode": "auto_contain", "auto_min_confidence": 0.7, "kill_switch": True})
        incident, device = self.make_incident(user="victim6", failed_logins=3)
        self.assertFalse(get_device(device["device_id"])["quarantined"])
        reset_incidents(); reset_agent_state(); reset_devices(); reset_risk_state()
        update_settings({"autonomy_mode": "auto_contain", "auto_min_confidence": 0.7})
        incident, device = self.make_incident(user="alex_chen", failed_logins=3)  # privileged analyst account
        self.assertFalse(get_device(device["device_id"])["quarantined"])
        act = [a for a in response.list_actions(incident["id"]) if a["action"] == "quarantine_device"][0]
        self.assertEqual(act["status"], "pending_approval")
        self.assertFalse(next(c for c in act["safeguards"] if c["name"] == "target_not_privileged")["passed"])

    def test_hourly_cap_limits_automatic_actions(self):
        update_settings({"autonomy_mode": "auto_contain", "auto_min_confidence": 0.7, "auto_max_per_hour": 1})
        self.make_incident(user="cap1", failed_logins=3)
        _, device2 = self.make_incident(user="cap2", failed_logins=3)
        self.assertFalse(get_device(device2["device_id"])["quarantined"])

    def test_autonomy_settings_validation_and_permissions(self):
        self.assertEqual(self.client.put("/api/agents/autonomy", json={"autonomy_mode": "yolo"}, headers=self.admin).status_code, 422)
        self.assertEqual(self.client.put("/api/agents/autonomy", json={"auto_min_confidence": 0.1}, headers=self.admin).status_code, 422)
        self.assertEqual(self.client.put("/api/agents/autonomy", json={"autonomy_mode": "off"}, headers=self.analyst).status_code, 403)
        ok = self.client.put("/api/agents/autonomy", json={"autonomy_mode": "off"}, headers=self.admin)
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(get_settings()["autonomy_mode"], "off")
        self.assertTrue(verify_audit_chain()["valid"])

    # --- investigator ---
    def test_investigator_connection_is_read_only(self):
        conn = get_readonly_connection()
        with self.assertRaises(sqlite3.OperationalError):
            conn.execute("DELETE FROM incidents")
        conn.close()
        incident, _ = self.make_incident(user="ro")
        before = len(list_incidents())
        investigate(get_incident(incident["id"]))
        self.assertEqual(len(list_incidents()), before)

    def test_credential_attack_rule_uses_real_login_records(self):
        incident, _ = self.make_incident(user="stuffed", failed_logins=3)
        findings = get_incident(incident["id"])["investigator_findings"]
        rule = next(r for r in findings["rules"] if r["rule_id"] == "credential_attack")
        self.assertTrue(rule["fired"])
        quiet, _ = self.make_incident(user="quiet")
        quiet_rule = next(r for r in get_incident(quiet["id"])["investigator_findings"]["rules"] if r["rule_id"] == "credential_attack")
        self.assertFalse(quiet_rule["fired"])

    # --- feedback + learning ---
    def test_verdict_endpoint_validates_and_records(self):
        incident, _ = self.make_incident(user="fb1", failed_logins=3)
        self.assertEqual(self.client.post(f"/api/incidents/{incident['id']}/verdict", json={"verdict": "maybe"}, headers=self.analyst).status_code, 422)
        self.assertEqual(self.client.post("/api/incidents/INC-NOPE/verdict", json={"verdict": "true_positive"}, headers=self.analyst).status_code, 404)
        ok = self.client.post(f"/api/incidents/{incident['id']}/verdict", json={"verdict": "true_positive", "notes": "confirmed"}, headers=self.analyst)
        self.assertEqual(ok.status_code, 200)
        body = ok.json()
        self.assertEqual(body["learning"]["labeled_incidents"], 1)
        self.assertEqual(body["learning"]["status"], "insufficient_data")
        self.assertIn("credential_attack", body["feedback"]["rules_fired"])

    def _seed_labels(self, rows):
        for i, (verdict, fired) in enumerate(rows):
            learning.record_feedback({"id": f"FDB-T{i}", "incident_id": f"INC-T{i}", "verdict": verdict, "notes": "", "analyst_id": "t",
                                      "rules_fired": fired, "investigator_confidence": 0.5, "created_at": f"2026-01-01T00:00:{i:02d}+00:00"})

    def test_learning_reports_measured_loo_result_and_downweights_noisy_rule(self):
        rows = [("true_positive", ["credential_attack", "untrusted_device"])] * 6 + [("false_positive", ["untrusted_device"])] * 6
        self._seed_labels(rows)
        result = learning.evaluate()
        self.assertEqual(result["labeled_incidents"], 12)
        self.assertIsNotNone(result["default_accuracy"]); self.assertIsNotNone(result["learned_accuracy"])
        self.assertIn(result["status"], {"applied", "rejected"})
        self.assertLess(result["learned_weights"]["untrusted_device"] / sum(result["learned_weights"].values()),
                        learning.DEFAULT_WEIGHTS["untrusted_device"])
        self.assertAlmostEqual(sum(result["active_weights"].values()), 1.0, places=3)
        if result["applied"]:
            self.assertGreaterEqual(result["accuracy_delta"], 0)
        else:
            self.assertEqual(result["active_weights"], learning.DEFAULT_WEIGHTS)

    def test_learning_inactive_below_minimum_labels(self):
        self._seed_labels([("true_positive", ["credential_attack"])] * 3)
        result = learning.evaluate()
        self.assertFalse(result["applied"])
        self.assertEqual(result["active_weights"], learning.DEFAULT_WEIGHTS)
        self.assertEqual(self.client.get("/api/agents/learning", headers=self.viewer).status_code, 200)

    # --- notifications ---
    def test_notifications_persist_and_are_not_reported_sent_without_smtp(self):
        self.make_incident(user="n1", failed_logins=3)
        rows = self.client.get("/api/notifications", headers=self.admin).json()["notifications"]
        self.assertTrue(rows)
        self.assertTrue(all(r["status"] == "skipped" for r in rows))

    def test_mailer_sends_with_transport_and_strips_header_injection(self):
        sent = []
        notifier.set_transport_override(sent.append)
        notifier.notify("INC-X", "Hello\r\nBcc: evil@example.com", "body", recipients=["a@example.com"], wait=True)
        self.assertEqual(len(sent), 1)
        self.assertNotIn("\n", sent[0]["Subject"]); self.assertIsNone(sent[0]["Bcc"])
        rows = notifier.list_notifications(5)
        self.assertEqual(rows[0]["status"], "sent")

    def test_mailer_failure_is_recorded_not_raised(self):
        def boom(_m): raise ConnectionError("smtp down")
        notifier.set_transport_override(boom)
        notifier.notify("INC-X", "s", "b", recipients=["a@example.com"], wait=True)
        row = notifier.list_notifications(5)[0]
        self.assertEqual(row["status"], "failed"); self.assertIn("smtp down", row["error"])

    def test_duplicate_notifications_are_suppressed_within_cooldown(self):
        sent = []
        notifier.set_transport_override(lambda m: sent.append(m))
        notifier.notify("INC-D", "Same subject", "b", recipients=["a@example.com"], wait=True)
        again = notifier.notify("INC-D", "Same subject", "b", recipients=["a@example.com"], wait=True)
        self.assertEqual(again, [])
        self.assertEqual(len(sent), 1)
        self.assertEqual(len(notifier.list_notifications(10)), 1)
        notifier.notify("INC-D", "Different subject", "b", recipients=["a@example.com"], wait=True)
        self.assertEqual(len(notifier.list_notifications(10)), 2)

    def test_smtp_failure_keeps_in_app_notification_and_never_logs_password(self):
        import io, contextlib
        os.environ["TRUSTNET_SMTP_HOST"] = "smtp.invalid"; os.environ["TRUSTNET_SMTP_PASSWORD"] = "S3cretPassw0rd-test"
        try:
            def boom(_m): raise ConnectionError("smtp down")
            notifier.set_transport_override(boom)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                notifier.notify("INC-F", "s2", "b", recipients=["a@example.com"], wait=True)
            rows = notifier.list_notifications(5)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["status"], "failed")
            self.assertNotIn("S3cretPassw0rd-test", buf.getvalue() + str(rows))
        finally:
            os.environ.pop("TRUSTNET_SMTP_HOST", None); os.environ.pop("TRUSTNET_SMTP_PASSWORD", None)

    def test_notification_list_is_scoped_to_authenticated_recipient(self):
        notifier.notify("INC-PRIVATE", "admin-only", "sensitive admin incident details",
                        recipients=["sumukh@trustnet.local"])
        notifier.notify("INC-PRIVATE", "analyst-only", "sensitive analyst incident details",
                        recipients=["alex.chen@corp.com"])
        admin_rows = self.client.get("/api/notifications", headers=self.admin).json()["notifications"]
        analyst_rows = self.client.get("/api/notifications", headers=self.analyst).json()["notifications"]
        viewer_rows = self.client.get("/api/notifications", headers=self.viewer).json()["notifications"]
        self.assertEqual([row["subject"] for row in admin_rows], ["admin-only"])
        self.assertEqual([row["subject"] for row in analyst_rows], ["analyst-only"])
        self.assertEqual(viewer_rows, [])
        self.assertNotIn("sensitive analyst incident details", str(admin_rows))
        self.assertNotIn("sensitive admin incident details", str(analyst_rows))

    def test_notification_unread_count_and_mark_read_are_per_user(self):
        notifier.notify("INC-R", "n1", "b", recipients=["sumukh@trustnet.local", "alex.chen@corp.com"])
        notifier.notify("INC-R", "n2", "b", recipients=["sumukh@trustnet.local"])
        self.assertEqual(self.client.get("/api/notifications/unread-count", headers=self.admin).json()["unread_count"], 2)
        self.assertEqual(self.client.get("/api/notifications/unread-count", headers=self.analyst).json()["unread_count"], 1)
        first = [n for n in notifier.list_notifications(10) if n["recipient"] == "sumukh@trustnet.local"][0]
        # an analyst cannot mark an admin's notification read
        self.assertEqual(self.client.post(f"/api/notifications/{first['id']}/read", headers=self.analyst).status_code, 404)
        self.assertEqual(self.client.post(f"/api/notifications/{first['id']}/read", headers=self.admin).json()["unread_count"], 1)
        self.assertEqual(self.client.post("/api/notifications/read-all", headers=self.admin).json()["unread_count"], 0)
        self.assertEqual(self.client.get("/api/notifications/unread-count", headers=self.analyst).json()["unread_count"], 1)
        self.assertEqual(self.client.get("/api/notifications/unread-count").status_code, 401)

    def test_rate_limiter_blocks_after_limit_and_recovers_after_window(self):
        from models.rate_limit import SlidingWindowLimiter
        now = [0.0]
        limiter = SlidingWindowLimiter(3, 60.0, clock=lambda: now[0])
        self.assertEqual([limiter.allow("1.1.1.1") for _ in range(4)], [True, True, True, False])
        self.assertTrue(limiter.allow("2.2.2.2"))      # other clients unaffected
        now[0] = 61.0
        self.assertTrue(limiter.allow("1.1.1.1"))

    def test_rate_limiter_prunes_expired_client_keys(self):
        from models.rate_limit import SlidingWindowLimiter
        now = [0.0]
        limiter = SlidingWindowLimiter(2, 10.0, clock=lambda: now[0])
        for index in range(25):
            self.assertTrue(limiter.allow(f"192.0.2.{index}"))
        self.assertEqual(len(limiter._hits), 25)
        now[0] = 11.0
        self.assertTrue(limiter.allow("198.51.100.1"))
        # The periodic cleanup should not retain one deque for every old IP.
        self.assertEqual(set(limiter._hits), {"198.51.100.1"})

    def test_login_rate_limit_returns_429_when_enabled(self):
        from models import rate_limit
        os.environ["TRUSTNET_RATE_LIMIT_ENABLED"] = "1"
        rate_limit.login_limiter.reset(); rate_limit.api_limiter.reset()
        try:
            codes = [self.client.post("/api/login", json={"username": "nobody", "password": "x"}).status_code
                     for _ in range(rate_limit.login_limiter.limit + 2)]
            self.assertEqual(codes[-1], 429)
        finally:
            os.environ.pop("TRUSTNET_RATE_LIMIT_ENABLED", None)
            rate_limit.login_limiter.reset(); rate_limit.api_limiter.reset()

    # --- lifecycle / hardening ---
    def test_closed_incident_cannot_be_reinvestigated(self):
        incident, _ = self.make_incident(user="closed1")
        self.client.post(f"/api/incidents/{incident['id']}/dismiss", headers=self.admin)
        self.assertEqual(self.client.post(f"/api/incidents/{incident['id']}/investigate", headers=self.admin).status_code, 409)

    # --- self-decision prevention, notification privacy and WebSocket session handling (HTTP level) ---
    def test_incident_subject_cannot_dismiss_or_resolve_their_own_incident(self):
        incident, _ = self.make_incident(user="alex_chen")  # the analyst account is the subject of the incident
        for verb in ("dismiss", "resolve"):
            r = self.client.post(f"/api/incidents/{incident['id']}/{verb}", headers=self.analyst)
            self.assertEqual(r.status_code, 403, f"{verb}: {r.text}")
        self.assertNotIn(get_incident(incident["id"])["status"], {"dismissed", "resolved"})
        # a different authorized reviewer can still decide it
        self.assertEqual(self.client.post(f"/api/incidents/{incident['id']}/dismiss", headers=self.admin).status_code, 200)

    def test_incident_subject_cannot_label_or_reject_actions_on_their_own_incident(self):
        incident, _ = self.make_incident(user="alex_chen")
        verdict = self.client.post(f"/api/incidents/{incident['id']}/verdict", json={"verdict": "false_positive"}, headers=self.analyst)
        self.assertEqual(verdict.status_code, 403, verdict.text)
        actions = self.client.get(f"/api/incidents/{incident['id']}/agent", headers=self.admin).json()["responses"]
        pending = [a for a in actions if a["status"] == "pending_approval"]
        if pending:
            rejected = self.client.post(f"/api/incidents/{incident['id']}/responses/{pending[0]['id']}/reject", json={}, headers=self.analyst)
            self.assertEqual(rejected.status_code, 403, rejected.text)

    def test_websocket_requires_a_valid_single_use_ticket(self):
        from starlette.websockets import WebSocketDisconnect
        with self.assertRaises(WebSocketDisconnect):
            with self.client.websocket_connect("/ws/admin?ticket=bogus"):
                pass
        with self.assertRaises(WebSocketDisconnect):
            with self.client.websocket_connect("/ws/admin"):
                pass
        ticket = self.client.post("/api/auth/ws-ticket", headers=self.admin).json()["ticket"]
        with self.client.websocket_connect(f"/ws/admin?ticket={ticket}") as ws:
            ws.send_text("ping")
            self.assertEqual(ws.receive_json()["type"], "pong")
        with self.assertRaises(WebSocketDisconnect):  # tickets are single use
            with self.client.websocket_connect(f"/ws/admin?ticket={ticket}"):
                pass

    def test_websocket_closes_when_analyst_is_demoted_after_connecting(self):
        from starlette.websockets import WebSocketDisconnect
        from models.security_auth import update_user_account
        analyst = get_user_by_id("ws-demotion-test")
        if analyst is None:
            create_user("ws-demotion-test@trustnet.local", "StrongDemoPassw0rd!", "analyst", user_id="ws-demotion-test")
            analyst = get_user_by_id("ws-demotion-test")
        ticket = self.client.post("/api/auth/ws-ticket", headers=bearer(analyst["id"])).json()["ticket"]
        try:
            with self.client.websocket_connect(f"/ws/admin?ticket={ticket}") as ws:
                update_user_account(analyst["id"], role="viewer")
                ws.send_text("ping")
                with self.assertRaises(WebSocketDisconnect):
                    ws.receive_json()
        finally:
            update_user_account(analyst["id"], role="analyst")

    def test_viewer_cannot_join_the_soc_websocket_room(self):
        from starlette.websockets import WebSocketDisconnect
        ticket = self.client.post("/api/auth/ws-ticket", headers=self.viewer).json()["ticket"]
        with self.assertRaises(WebSocketDisconnect):
            with self.client.websocket_connect(f"/ws/admin?ticket={ticket}"):
                pass

    def test_notification_endpoints_are_private_per_user(self):
        notifier.notify("INC-PRIV", "admin-only subject", "secret body", recipients=["sumukh@trustnet.local"])
        admin_rows = self.client.get("/api/notifications", headers=self.admin).json()["notifications"]
        analyst_rows = self.client.get("/api/notifications", headers=self.analyst).json()["notifications"]
        viewer_rows = self.client.get("/api/notifications", headers=self.viewer).json()["notifications"]
        self.assertEqual([n["subject"] for n in admin_rows], ["admin-only subject"])
        self.assertEqual(analyst_rows, [])
        self.assertEqual(viewer_rows, [])
        note_id = admin_rows[0]["id"]
        # another user cannot mark it read, and unread counts are per user
        self.assertEqual(self.client.post(f"/api/notifications/{note_id}/read", headers=self.analyst).status_code, 404)
        self.assertEqual(self.client.get("/api/notifications/unread-count", headers=self.admin).json()["unread_count"], 1)
        self.assertEqual(self.client.post(f"/api/notifications/{note_id}/read", headers=self.admin).status_code, 200)
        self.assertEqual(self.client.get("/api/notifications/unread-count", headers=self.admin).json()["unread_count"], 0)
        self.assertEqual(self.client.get("/api/notifications").status_code, 401)

    def test_incident_numbers_are_sequential_and_unique(self):
        a, _ = self.make_incident(user="seq1"); b, _ = self.make_incident(user="seq2")
        self.assertEqual(b["incident_number"], a["incident_number"] + 1)

    def test_cors_and_security_headers_and_unauthenticated_model_endpoints(self):
        r = self.client.get("/api/health", headers={"Origin": "https://evil.example"})
        self.assertNotIn("access-control-allow-origin", r.headers)
        ok = self.client.get("/api/health", headers={"Origin": "http://localhost:8080"})
        self.assertEqual(ok.headers.get("access-control-allow-origin"), "http://localhost:8080")
        self.assertEqual(r.headers.get("x-content-type-options"), "nosniff")
        self.assertEqual(r.headers.get("x-frame-options"), "DENY")
        anon = TestClient(main.app)
        self.assertEqual(anon.post("/api/csf/train", json={}).status_code, 401)
        self.assertEqual(anon.post("/api/csf/score", json={}).status_code, 401)


    def test_synthetic_hr_records_are_authorized_and_marked_synthetic(self):
        denied = self.client.get("/api/hr/records", headers=self.viewer)
        self.assertEqual(denied.status_code, 403)
        allowed = self.client.get("/api/hr/records", headers=self.admin)
        self.assertEqual(allowed.status_code, 200, allowed.text)
        body = allowed.json()
        self.assertTrue(body["synthetic_data"])
        self.assertTrue(body["sensitive"])
        self.assertTrue(all(row["employee_id"].startswith("SYN-") for row in body["records"]))

    def test_synthetic_file_export_returns_metadata_not_file_contents(self):
        denied = self.client.get("/api/files/export", headers=self.viewer)
        self.assertEqual(denied.status_code, 403)
        allowed = self.client.get("/api/files/export", headers=self.admin)
        self.assertEqual(allowed.status_code, 200, allowed.text)
        body = allowed.json()
        self.assertTrue(body["synthetic_data"])
        self.assertTrue(body["sensitive"])
        self.assertFalse(body["file_content_included"])



if __name__ == "__main__":
    unittest.main()
