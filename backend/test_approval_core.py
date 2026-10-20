"""Approval-bypass and enforcement tests against the response agent (real SQLite; no web framework needed).

Proves: unauthorised/self approval cannot enforce anything, approval enforces for real, double approval is
idempotent (409, single execution), expired and rejected approvals never execute, audit chain stays valid.
"""
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:  # models.mfa only needs HTTPException; use a tiny stand-in when FastAPI isn't installed (offline sandbox)
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
from models.incident_store import get_incident, maybe_create_risk_incident
from models.security_events import verify_audit_chain
from agents import response
from agents.response import ResponseError

FP = {"platform": "Linux", "userAgent": "Chrome/120", "screen": "1x1"}


class ApprovalCoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.orig = database._DB_PATH
        database._DB_PATH = str(Path(self.tmp.name) / "t.db")
        database.initialize_database()
        self.device = register_login_device("victim", FP)
        self.incident = maybe_create_risk_incident(
            {"score": 90, "level": "critical", "user_id": "victim", "device_id": self.device["device_id"],
             "breakdown": {}, "thresholds": {"restrict": 60}}, evidence=["synthetic"])
        decision = {"action": "quarantine_device", "target": self.device["device_id"], "rationale": "test"}
        action = response.new_action(self.incident, decision)
        self.action = response.request_approval(action, self.incident, actor="agent:response")
        self.analyst = {"id": "analyst-1", "role": "analyst"}

    def tearDown(self):
        database._DB_PATH = self.orig
        self.tmp.cleanup()

    def _quarantined(self):
        return bool(get_device(self.device["device_id"])["quarantined"])

    def test_pending_action_does_not_enforce_anything(self):
        self.assertEqual(self.action["status"], "pending_approval")
        self.assertFalse(self._quarantined())

    def test_viewer_cannot_approve_and_nothing_is_enforced(self):
        with self.assertRaises(ResponseError) as ctx:
            response.approve(self.action["id"], {"id": "v", "role": "viewer"})
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertFalse(self._quarantined())
        self.assertEqual(response.get_action(self.action["id"])["status"], "pending_approval")

    def test_self_approval_is_denied(self):
        with self.assertRaises(ResponseError) as ctx:
            response.approve(self.action["id"], {"id": "victim", "role": "analyst"})
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertFalse(self._quarantined())

    def test_unknown_action_is_404(self):
        with self.assertRaises(ResponseError) as ctx:
            response.approve("RSP-NOPE", self.analyst)
        self.assertEqual(ctx.exception.status_code, 404)

    def test_approval_really_enforces_and_is_idempotent(self):
        done = response.approve(self.action["id"], self.analyst)
        self.assertEqual(done["status"], "executed")
        self.assertEqual(done["mode"], "human")
        self.assertTrue(self._quarantined())
        self.assertEqual(get_incident(self.incident["id"])["response_action"], "device_quarantined")
        with self.assertRaises(ResponseError) as ctx:  # replay must not execute twice
            response.approve(self.action["id"], self.analyst)
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertTrue(verify_audit_chain()["valid"])

    def test_expired_approval_never_executes(self):
        past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        conn = database.get_db_connection()
        conn.execute("UPDATE response_actions SET expires_at=? WHERE id=?", (past, self.action["id"]))
        conn.commit(); conn.close()
        with self.assertRaises(ResponseError) as ctx:
            response.approve(self.action["id"], self.analyst)
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertFalse(self._quarantined())

    def test_rejected_action_cannot_be_approved_later(self):
        response.reject(self.action["id"], self.analyst, "false alarm")
        with self.assertRaises(ResponseError) as ctx:
            response.approve(self.action["id"], self.analyst)
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertFalse(self._quarantined())

    def test_viewer_cannot_reject(self):
        with self.assertRaises(ResponseError) as ctx:
            response.reject(self.action["id"], {"id": "v", "role": "viewer"})
        self.assertEqual(ctx.exception.status_code, 403)

    def test_auto_mode_cannot_bypass_human_only_action(self):
        block = response.new_action(self.incident, {"action": "temp_block_account", "target": "victim", "rationale": "t"})
        with self.assertRaises(ResponseError) as ctx:
            response.execute(block, actor="agent:response", mode="auto")
        self.assertIn(ctx.exception.status_code, (403, 409))  # kill switch/autonomy default or human-only rule

    def test_enforcement_on_missing_device_is_reported_failed_not_executed(self):
        conn = database.get_db_connection()
        conn.execute("DELETE FROM devices WHERE device_id=?", (self.device["device_id"],))
        conn.commit(); conn.close()
        with self.assertRaises(ResponseError):
            response.approve(self.action["id"], self.analyst)
        self.assertNotEqual(response.get_action(self.action["id"])["status"], "executed")


if __name__ == "__main__":
    unittest.main()
