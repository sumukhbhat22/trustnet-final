"""API and service tests for TOTP enrolment, replay/lockout protection and anchored audit verification."""
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

_DIR = tempfile.TemporaryDirectory(prefix="trustnet-totp-api-")
os.environ["TRUSTNET_DB_PATH"] = str(Path(_DIR.name) / "totp-api.db")
os.environ["TRUSTNET_TOTP_KEY"] = "unit-test-totp-key-0123456789abcdef-not-a-secret"
os.environ["TRUSTNET_AUDIT_CHECKPOINT_KEY"] = "unit-test-anchor-key-0123456789abcdef-not-a-secret"
os.environ["TRUSTNET_AUDIT_CHECKPOINT_FILE"] = str(Path(_DIR.name) / "audit-checkpoints.jsonl")
os.environ["TRUSTNET_AUDIT_CHECKPOINT_EVERY"] = "1000"

from fastapi.testclient import TestClient

import main
from models import totp, totp_service
from models.database import get_db_connection
from models.mfa import clear_mfa_state, enforce_mfa, require_mfa_for_user
from models.security_auth import get_user_by_id, issue_access_token, list_users, reset_auth_state
from models.security_events import persist_security_event, verify_audit_anchors, write_anchor_now


class TotpApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx = TestClient(main.app)
        cls.client = cls.ctx.__enter__()
        reset_auth_state()
        list_users()
        cls.admin = get_user_by_id("sumukh")
        cls.client.headers.update({"Authorization": f"Bearer {issue_access_token(cls.admin)}"})

    @classmethod
    def tearDownClass(cls):
        cls.ctx.__exit__(None, None, None)

    def setUp(self):
        totp_service.disable(self.admin["id"])
        clear_mfa_state()

    def _enrol(self):
        started = self.client.post("/api/mfa/totp/enroll")
        self.assertEqual(started.status_code, 200, started.text)
        secret = started.json()["secret"]
        self.assertTrue(started.json()["otpauth_uri"].startswith("otpauth://totp/"))
        code = totp.totp(secret, time.time())
        confirmed = self.client.post("/api/mfa/totp/confirm", json={"code": code})
        self.assertEqual(confirmed.status_code, 200, confirmed.text)
        return secret, confirmed.json()["backup_codes"], code

    def test_enrol_confirm_status_and_secret_is_encrypted_at_rest(self):
        self.assertFalse(self.client.get("/api/mfa/totp/status").json()["enrolled"])
        secret, backups, _ = self._enrol()
        self.assertEqual(len(backups), totp.BACKUP_CODE_COUNT)
        status = self.client.get("/api/mfa/totp/status").json()
        self.assertTrue(status["enrolled"])
        self.assertEqual(status["backup_codes_remaining"], totp.BACKUP_CODE_COUNT)
        conn = get_db_connection()
        try:
            row = conn.execute("SELECT * FROM totp_credentials WHERE user_id=?", (self.admin["id"],)).fetchone()
        finally:
            conn.close()
        self.assertNotIn(secret, row["secret_enc"])
        for plain in backups:
            self.assertNotIn(plain, row["backup_json"])
        self.assertEqual(self.client.post("/api/mfa/totp/enroll").status_code, 409)  # cannot overwrite a confirmed secret

    def test_confirm_rejects_wrong_code_and_malformed_code(self):
        self.client.post("/api/mfa/totp/enroll")
        self.assertEqual(self.client.post("/api/mfa/totp/confirm", json={"code": "abc"}).status_code, 422)
        self.assertEqual(self.client.post("/api/mfa/totp/confirm", json={"code": "000000"}).status_code, 403)

    def test_verify_satisfies_step_up_and_a_used_code_cannot_be_replayed(self):
        secret, _, used = self._enrol()
        require_mfa_for_user(self.admin["id"], "account")
        with self.assertRaises(Exception):
            enforce_mfa(self.admin["id"], "account")
        # The enrolment code was already used for this time step; replaying it must fail.
        replay = self.client.post("/api/mfa/totp/verify", json={"code": used})
        self.assertEqual(replay.status_code, 403)
        self.assertEqual(replay.json()["detail"]["code"], "TOTP_INVALID")
        next_step = totp.totp(secret, time.time() + totp.STEP_SECONDS)  # one step ahead is inside the drift window
        ok = self.client.post("/api/mfa/totp/verify", json={"code": next_step})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertEqual(ok.json()["method"], "totp")
        enforce_mfa(self.admin["id"], "account")  # no exception now

    def test_backup_code_is_single_use(self):
        _, backups, _ = self._enrol()
        first = self.client.post("/api/mfa/totp/verify", json={"code": backups[0]})
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(first.json()["method"], "backup")
        self.assertEqual(first.json()["backup_codes_remaining"], totp.BACKUP_CODE_COUNT - 1)
        again = self.client.post("/api/mfa/totp/verify", json={"code": backups[0]})
        self.assertEqual(again.status_code, 403)

    def test_five_wrong_codes_lock_totp_and_even_a_correct_code_is_then_refused(self):
        secret, _, _ = self._enrol()
        statuses = [self.client.post("/api/mfa/totp/verify", json={"code": "000000"}).status_code for _ in range(5)]
        self.assertEqual(statuses[:4], [403] * 4)
        self.assertEqual(statuses[4], 423)
        good = totp.totp(secret, time.time() + totp.STEP_SECONDS)
        locked = self.client.post("/api/mfa/totp/verify", json={"code": good})
        self.assertEqual(locked.status_code, 423)
        self.assertEqual(locked.json()["detail"]["code"], "TOTP_LOCKED")

    def test_verify_requires_enrolment(self):
        self.assertEqual(self.client.post("/api/mfa/totp/verify", json={"code": "123456"}).status_code, 409)

    def test_missing_encryption_key_fails_closed(self):
        saved = os.environ.pop("TRUSTNET_TOTP_KEY")
        try:
            response = self.client.post("/api/mfa/totp/enroll")
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json()["detail"]["code"], "TOTP_NOT_CONFIGURED")
        finally:
            os.environ["TRUSTNET_TOTP_KEY"] = saved

    def test_requires_authentication(self):
        anonymous = TestClient(main.app)
        for method, path in (("get", "/api/mfa/totp/status"), ("post", "/api/mfa/totp/enroll"),
                             ("post", "/api/mfa/totp/confirm"), ("post", "/api/mfa/totp/verify")):
            response = getattr(anonymous, method)(path, **({"json": {"code": "123456"}} if method == "post" else {}))
            self.assertIn(response.status_code, (401, 403), f"{method} {path}")

    def test_admin_cannot_reset_own_totp_but_can_reset_another_users(self):
        self.assertEqual(self.client.delete(f"/api/users/{self.admin['id']}/mfa/totp").status_code, 403)
        others = [u for u in list_users() if u["id"] != self.admin["id"]]
        self.assertTrue(others)
        self.assertEqual(self.client.delete(f"/api/users/{others[0]['id']}/mfa/totp").status_code, 200)
        self.assertEqual(self.client.delete("/api/users/does-not-exist/mfa/totp").status_code, 404)

    def test_totp_events_are_audited_without_secrets(self):
        secret, backups, code = self._enrol()
        conn = get_db_connection()
        try:
            blob = " ".join(str(tuple(r)) for r in conn.execute("SELECT request_path, risk_indicators, event_payload FROM security_events").fetchall())
        finally:
            conn.close()
        self.assertIn("totp_enrolment_confirmed", blob)
        for forbidden in [secret, code, *backups]:
            self.assertNotIn(forbidden, blob)


class AnchoredAuditVerifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx = TestClient(main.app)
        cls.client = cls.ctx.__enter__()
        reset_auth_state()
        list_users()
        cls.client.headers.update({"Authorization": f"Bearer {issue_access_token(get_user_by_id('sumukh'))}"})
        cls.path = os.environ["TRUSTNET_AUDIT_CHECKPOINT_FILE"]

    @classmethod
    def tearDownClass(cls):
        cls.ctx.__exit__(None, None, None)

    def setUp(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def _event(self, n):
        return {"id": f"evt-anchor-{time.time_ns()}-{n}", "timestamp": "2026-10-19T10:00:00+00:00", "user_id": "u-anchor",
                "ip_address": "203.0.113.9", "device_fingerprint_hash": "fp", "request_path": "/api/x", "http_method": "GET",
                "status_code": 200, "session_id": "s", "event_category": "request", "risk_indicators": [], "event_payload": {}}

    def test_endpoint_reports_no_checkpoints_then_ok_then_detects_edit(self):
        for i in range(3):
            persist_security_event(self._event(i))
        body = self.client.get("/api/audit/verify").json()
        self.assertTrue(body["valid"], body)
        self.assertEqual(body["anchors"]["status"], "no_checkpoints")
        write_anchor_now()
        body = self.client.get("/api/audit/verify").json()
        self.assertEqual(body["anchors"]["status"], "ok", body)
        self.assertTrue(body["valid_with_anchors"])
        # Forge: rewrite the checkpoint file with a changed head. Signature no longer matches.
        lines = [json.loads(l) for l in Path(self.path).read_text().splitlines()]
        lines[-1]["head"] = "0" * 64
        Path(self.path).write_text("\n".join(json.dumps(l, sort_keys=True) for l in lines) + "\n")
        body = self.client.get("/api/audit/verify").json()
        self.assertEqual(body["anchors"]["status"], "failed")
        self.assertFalse(body["valid_with_anchors"])

    def test_tail_deletion_is_detected_even_though_the_internal_chain_still_validates(self):
        for i in range(4):
            persist_security_event(self._event(i))
        write_anchor_now()
        conn = get_db_connection()
        try:
            conn.execute("DROP TRIGGER audit_entries_no_delete")  # simulates an attacker with raw database access
            conn.execute("DELETE FROM audit_entries WHERE sequence=(SELECT MAX(sequence) FROM audit_entries)")
            conn.commit()
        finally:
            conn.close()
        after = verify_audit_anchors()
        self.assertEqual(after["status"], "failed", after)
        self.assertTrue(any("tail deleted" in p or "no longer matches" in p for p in after["problems"]))

    def test_unconfigured_key_is_reported_not_silently_ok(self):
        saved = os.environ.pop("TRUSTNET_AUDIT_CHECKPOINT_KEY")
        try:
            self.assertEqual(self.client.get("/api/audit/verify").json()["anchors"]["status"], "unconfigured")
        finally:
            os.environ["TRUSTNET_AUDIT_CHECKPOINT_KEY"] = saved


if __name__ == "__main__":
    unittest.main()
