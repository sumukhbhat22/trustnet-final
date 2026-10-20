"""Security-core tests that need only the standard library plus the real PyJWT/numpy/sklearn stack.

They exercise the REAL production modules against REAL SQLite files and REAL threads. They deliberately do not need
FastAPI, httpx or bcrypt, so they can run in minimal environments. What they do NOT cover (see docs/STATUS.md):
HTTP routing/RBAC through FastAPI, real bcrypt password verification, WebSocket handshake, and the frontend.

Run:  cd backend && python -m unittest test_core_security -v
"""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

_DIR = tempfile.TemporaryDirectory(prefix="trustnet-core-tests-")
os.environ.setdefault("TRUSTNET_DB_PATH", str(Path(_DIR.name) / "core-test.db"))
os.environ.pop("TRUSTNET_ENV", None)

import jwt  # noqa: E402

from agents import notifier, orchestrator, response  # noqa: E402
from agents.common import update_settings, reset_agent_state  # noqa: E402
from models import account_restrictions as restrictions  # noqa: E402
from models import database as database_module  # noqa: E402
from models import rate_limit  # noqa: E402
from models import security_auth  # noqa: E402
from models import security_events  # noqa: E402
from models.database import get_db_connection, initialize_database  # noqa: E402
from models.device_registry import get_device, register_login_device, reset_devices  # noqa: E402
from models.incident_store import get_incident, reset_incidents  # noqa: E402

BACKEND_DIR = str(Path(__file__).resolve().parent)
FP = {"userAgent": "core-test", "platform": "test-os", "language": "en-US", "screenResolution": "1280x720",
      "timezone": "UTC", "canvasHash": "core-dev", "webglRenderer": "gpu", "hardwareConcurrency": 8,
      "colorDepth": 24, "deviceType": "desktop"}
PLACEHOLDER_HASH = "not-a-real-hash-never-verified-in-these-tests"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _insert_user(user_id: str, role: str, active: bool = True) -> None:
    connection = get_db_connection()
    try:
        connection.execute(
            "INSERT OR REPLACE INTO users (id,email,password_hash,role,is_active,created_at,last_login_at) VALUES (?,?,?,?,?,?,NULL)",
            (user_id, f"{user_id}@example.test", PLACEHOLDER_HASH, role, int(active), _now()))
        connection.commit()
    finally:
        connection.close()
    security_auth._AUTH_DATABASE_PATH = None  # force the in-memory identity cache to reload from SQLite


def _user(user_id: str) -> dict:
    return security_auth.get_user_by_id(user_id)


def _make_incident(user_id: str, device_id: str | None = None, status: str = "open") -> dict:
    incident_id = "INC-" + uuid4().hex[:10].upper()
    connection = get_db_connection()
    try:
        connection.execute(
            "INSERT INTO incidents (id,title,severity,user_id,device_id,ip_address,risk_score,status,reason,created_at,updated_at,"
            "event_ids,evidence,risk_breakdown) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (incident_id, "test incident", "High", user_id, device_id, "203.0.113.9", 90.0, status, "test", _now(), _now(),
             "[]", "[]", "{}"))
        connection.commit()
    finally:
        connection.close()
    return get_incident(incident_id)


def _pending_action(incident: dict, action: str = "quarantine_device", target: str | None = None) -> dict:
    decision = {"action": action, "target": target or incident.get("device_id") or incident["user_id"],
                "rationale": "test proposal"}
    item = response.new_action(incident, decision)
    return response.request_approval(item, incident, actor="agent:response", blocked_by=["test"])


def _audit_actions(incident_id: str) -> list[str]:
    connection = get_db_connection()
    try:
        rows = connection.execute(
            "SELECT request_path, event_payload FROM security_events WHERE request_path LIKE '/agents/%'").fetchall()
    finally:
        connection.close()
    import json
    return [r["request_path"].rsplit("/", 1)[-1] for r in rows if json.loads(r["event_payload"]).get("incident_id") == incident_id]


class CoreTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        initialize_database()
        # Pre-seed the demo identities so authenticate()'s demo seeding never needs to hash (bcrypt not required).
        for uid, role in (("sumukh", "admin"), ("alex_chen", "analyst"), ("admin", "admin")):
            _insert_user(uid, role)
        for uid, role in (("victim", "viewer"), ("analyst1", "analyst"), ("analyst2", "analyst"), ("admin1", "admin"),
                          ("viewer1", "viewer")):
            _insert_user(uid, role)

    def setUp(self):
        reset_incidents()
        reset_devices()
        reset_agent_state()
        notifier.set_transport_override(None)


# ───────────────────────────── approvals ─────────────────────────────
class ApprovalTests(CoreTestCase):
    def _device_incident(self, user="victim"):
        device = register_login_device(user, {**FP, "canvasHash": f"dev-{user}-{uuid4().hex[:6]}"})
        incident = _make_incident(user, device["device_id"])
        return incident, device, _pending_action(incident)

    def test_viewer_cannot_approve_and_attempt_is_audited(self):
        incident, device, action = self._device_incident()
        with self.assertRaises(response.ResponseError) as ctx:
            response.approve(action["id"], _user("viewer1"))
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertFalse(get_device(device["device_id"])["quarantined"])
        self.assertEqual(response.get_action(action["id"])["status"], "pending_approval")
        self.assertIn("approval_denied", _audit_actions(incident["id"]))

    def test_self_approval_is_blocked_for_privileged_target(self):
        # An analyst who is the subject of the incident must not approve the action against themselves.
        device = register_login_device("analyst1", {**FP, "canvasHash": "analyst1-dev"})
        incident = _make_incident("analyst1", device["device_id"])
        action = _pending_action(incident)
        with self.assertRaises(response.ResponseError) as ctx:
            response.approve(action["id"], _user("analyst1"))
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertFalse(get_device(device["device_id"])["quarantined"])
        self.assertEqual(response.get_action(action["id"])["status"], "pending_approval")

    def test_authorized_approval_executes_exactly_once(self):
        incident, device, action = self._device_incident()
        done = response.approve(action["id"], _user("analyst1"))
        self.assertEqual(done["status"], "executed")
        self.assertEqual(done["decided_by"], "user:analyst1")
        self.assertTrue(get_device(device["device_id"])["quarantined"])
        with self.assertRaises(response.ResponseError) as ctx:
            response.approve(action["id"], _user("analyst2"))
        self.assertEqual(ctx.exception.status_code, 409)

    def test_concurrent_approvals_exactly_one_wins(self):
        incident, device, action = self._device_incident()
        approvers = [_user("analyst1"), _user("analyst2"), _user("admin1"), _user("sumukh"), _user("alex_chen"), _user("admin")]
        barrier = threading.Barrier(len(approvers))
        results: list[tuple[str, int | None]] = []
        lock = threading.Lock()

        def worker(approver):
            barrier.wait()
            try:
                response.approve(action["id"], approver)
                outcome = ("ok", None)
            except response.ResponseError as error:
                outcome = ("err", error.status_code)
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker, args=(a,)) for a in approvers]
        [t.start() for t in threads]
        [t.join(timeout=60) for t in threads]
        self.assertEqual(len(results), len(approvers), "a worker hung")
        self.assertEqual([r for r in results if r[0] == "ok"].__len__(), 1, results)
        self.assertTrue(all(code == 409 for kind, code in results if kind == "err"), results)
        self.assertEqual(response.get_action(action["id"])["status"], "executed")
        self.assertEqual(_audit_actions(incident["id"]).count("executed"), 1)
        self.assertEqual(_audit_actions(incident["id"]).count("approval_granted"), 1)

    def test_expired_approval_cannot_be_approved_and_is_closed_and_audited(self):
        incident, device, action = self._device_incident()
        connection = get_db_connection()
        connection.execute("UPDATE response_actions SET expires_at = ? WHERE id = ?",
                           ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(), action["id"]))
        connection.commit(); connection.close()
        with self.assertRaises(response.ResponseError) as ctx:
            response.approve(action["id"], _user("analyst1"))
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(response.get_action(action["id"])["status"], "expired")
        self.assertFalse(get_device(device["device_id"])["quarantined"])
        self.assertIn("approval_expired", _audit_actions(incident["id"]))

    def test_claim_itself_rejects_expired_rows(self):
        # Defence in depth: even if approve()'s pre-check were bypassed, the atomic claim refuses expired approvals.
        incident, device, action = self._device_incident()
        connection = get_db_connection()
        connection.execute("UPDATE response_actions SET expires_at = ? WHERE id = ?",
                           ((datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat(), action["id"]))
        connection.commit(); connection.close()
        self.assertFalse(response._claim(action["id"], "user:analyst1"))

    def test_expire_stale_only_touches_overdue_pending(self):
        incident, device, fresh = self._device_incident()
        other_incident, _, overdue = self._device_incident("viewer1")
        connection = get_db_connection()
        connection.execute("UPDATE response_actions SET expires_at = ? WHERE id = ?",
                           ((datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(), overdue["id"]))
        connection.commit(); connection.close()
        self.assertEqual(response.expire_stale(), 1)
        self.assertEqual(response.get_action(overdue["id"])["status"], "expired")
        self.assertEqual(response.get_action(fresh["id"])["status"], "pending_approval")
        self.assertEqual(response.expire_stale(), 0)  # idempotent

    def test_crash_recovery_marks_stuck_execution_failed_and_never_replays(self):
        incident, device, action = self._device_incident()
        old = (datetime.now(timezone.utc) - timedelta(seconds=response.EXECUTING_TIMEOUT_SECONDS + 30)).isoformat()
        connection = get_db_connection()
        connection.execute("UPDATE response_actions SET status='executing', decided_by='user:analyst1', updated_at=? WHERE id=?",
                           (old, action["id"]))
        connection.commit(); connection.close()
        self.assertEqual(response.recover_stuck(), 1)
        self.assertEqual(response.get_action(action["id"])["status"], "failed")
        self.assertFalse(get_device(device["device_id"])["quarantined"], "recovery must not replay enforcement")
        self.assertIn("recovered_stuck_execution", _audit_actions(incident["id"]))
        with self.assertRaises(response.ResponseError) as ctx:
            response.approve(action["id"], _user("analyst2"))
        self.assertEqual(ctx.exception.status_code, 409)

    def test_recent_executing_row_is_not_recovered(self):
        incident, device, action = self._device_incident()
        connection = get_db_connection()
        connection.execute("UPDATE response_actions SET status='executing', updated_at=? WHERE id=?", (_now(), action["id"]))
        connection.commit(); connection.close()
        self.assertEqual(response.recover_stuck(), 0)
        self.assertEqual(response.get_action(action["id"])["status"], "executing")

    def test_unexpected_enforcement_error_is_recorded_not_left_executing(self):
        # Fault injection: force the enforcement step to blow up and check the approval does not stay stranded.
        incident = _make_incident("victim")
        action = _pending_action(incident, "temp_block_account", target="victim")
        original = response.create_restriction
        response.create_restriction = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("injected"))
        try:
            with self.assertRaises(response.ResponseError) as ctx:
                response.approve(action["id"], _user("analyst1"))
        finally:
            response.create_restriction = original
        self.assertEqual(ctx.exception.status_code, 500)
        self.assertEqual(response.get_action(action["id"])["status"], "failed")

    def test_reject_rules(self):
        incident, device, action = self._device_incident()
        with self.assertRaises(response.ResponseError) as ctx:
            response.reject(action["id"], _user("viewer1"))
        self.assertEqual(ctx.exception.status_code, 403)
        rejected = response.reject(action["id"], _user("analyst1"), "known travel")
        self.assertEqual(rejected["status"], "rejected")
        with self.assertRaises(response.ResponseError) as ctx:
            response.approve(action["id"], _user("analyst2"))
        self.assertEqual(ctx.exception.status_code, 409)

    def test_privileged_target_cannot_reject_action_against_themselves(self):
        device = register_login_device("admin1", {**FP, "canvasHash": "admin1-dev"})
        incident = _make_incident("admin1", device["device_id"])
        action = _pending_action(incident)
        with self.assertRaises(response.ResponseError) as ctx:
            response.reject(action["id"], _user("admin1"))
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(response.get_action(action["id"])["status"], "pending_approval")
        self.assertIn("rejection_denied", _audit_actions(incident["id"]))

    def test_self_decision_helper_blocks_and_audits(self):
        incident = _make_incident("analyst1")
        with self.assertRaises(response.ResponseError) as ctx:
            response.assert_not_self_target(incident, _user("analyst1"), "dismiss")
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("decision_denied", _audit_actions(incident["id"]))
        response.assert_not_self_target(incident, _user("analyst2"), "dismiss")  # a different account is allowed

    def test_legacy_incident_approve_blocks_self_and_viewer_but_allows_other_analyst(self):
        device = register_login_device("analyst1", {**FP, "canvasHash": "legacy-dev"})
        incident = _make_incident("analyst1", device["device_id"])
        with self.assertRaises(response.ResponseError) as ctx:
            orchestrator.approve_incident(incident["id"], _user("analyst1"))
        self.assertEqual(ctx.exception.status_code, 403)
        with self.assertRaises(response.ResponseError) as ctx:
            orchestrator.approve_incident(incident["id"], _user("viewer1"))
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertFalse(get_device(device["device_id"])["quarantined"])
        result = orchestrator.approve_incident(incident["id"], _user("analyst2"))
        self.assertTrue(result["device"]["quarantined"])
        self.assertEqual(result["action"]["status"], "executed")

    def test_verdict_rules(self):
        incident = _make_incident("analyst1")
        with self.assertRaises(response.ResponseError) as ctx:
            orchestrator.submit_verdict(incident["id"], "true_positive", "", _user("analyst1"))
        self.assertEqual(ctx.exception.status_code, 403)
        with self.assertRaises(response.ResponseError) as ctx:
            orchestrator.submit_verdict(incident["id"], "true_positive", "", _user("viewer1"))
        self.assertEqual(ctx.exception.status_code, 403)
        with self.assertRaises(response.ResponseError) as ctx:
            orchestrator.submit_verdict(incident["id"], "maybe", "", _user("analyst2"))
        self.assertEqual(ctx.exception.status_code, 422)

    def test_temp_block_needs_human_and_protected_accounts_are_never_blocked(self):
        update_settings({"autonomy_mode": "auto_contain"})
        incident = _make_incident("victim")
        action = _pending_action(incident, "temp_block_account", target="victim")
        with self.assertRaises(response.ResponseError) as ctx:
            response.execute(action, actor="agent:response", mode="auto")
        self.assertEqual(ctx.exception.status_code, 403, "sensitive account action must require recorded human approval")
        self.assertIsNone(restrictions.active_restriction("victim"))
        done = response.approve(action["id"], _user("analyst1"))
        self.assertEqual(done["status"], "executed")
        self.assertIsNotNone(restrictions.active_restriction("victim"))
        # protected role target
        p_incident = _make_incident("analyst2")
        p_action = _pending_action(p_incident, "temp_block_account", target="analyst2")
        with self.assertRaises(response.ResponseError) as ctx:
            response.approve(p_action["id"], _user("admin1"))
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIsNone(restrictions.active_restriction("analyst2"))

    def test_kill_switch_refuses_automatic_quarantine(self):
        update_settings({"autonomy_mode": "auto_contain", "kill_switch": True})
        device = register_login_device("victim", {**FP, "canvasHash": "ks-dev"})
        incident = _make_incident("victim", device["device_id"])
        action = response.new_action(incident, {"action": "quarantine_device", "target": device["device_id"], "rationale": "t"})
        with self.assertRaises(response.ResponseError) as ctx:
            response.execute(action, actor="agent:response", mode="auto")
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertFalse(get_device(device["device_id"])["quarantined"])


# ───────────────────────── account restrictions ─────────────────────────
class RestrictionTests(CoreTestCase):
    def test_restriction_expires_and_is_audited(self):
        item = restrictions.create_restriction(_user("victim"), minutes=5, incident_id=None, action_id=None, actor="user:analyst1")
        self.assertIsNotNone(restrictions.active_restriction("victim"))
        connection = get_db_connection()
        connection.execute("UPDATE account_restrictions SET expires_at=? WHERE id=?",
                           ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), item["id"]))
        connection.commit(); connection.close()
        self.assertIsNone(restrictions.active_restriction("victim"))
        stored = [r for r in restrictions.list_restrictions("victim") if r["id"] == item["id"]][0]
        self.assertEqual(stored["status"], "expired")

    def test_duration_bounds_and_no_permanent_blocks(self):
        for bad in (0, -5, restrictions.MAX_MINUTES + 1, True, 1.5, "30"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                restrictions.create_restriction(_user("victim"), minutes=bad, incident_id=None, action_id=None, actor="t")
        ok = restrictions.create_restriction(_user("victim"), minutes=restrictions.MAX_MINUTES, incident_id=None, action_id=None, actor="t")
        expires = datetime.fromisoformat(ok["expires_at"])
        self.assertLessEqual(expires - datetime.now(timezone.utc), timedelta(minutes=restrictions.MAX_MINUTES, seconds=5))

    def test_protected_roles_cannot_be_restricted(self):
        for uid in ("analyst1", "admin1"):
            with self.assertRaises(ValueError):
                restrictions.create_restriction(_user(uid), minutes=10, incident_id=None, action_id=None, actor="t")

    def test_early_release(self):
        item = restrictions.create_restriction(_user("victim"), minutes=10, incident_id=None, action_id=None, actor="t")
        released = restrictions.release_restriction(item["id"], "user:analyst1")
        self.assertEqual(released["status"], "released")
        self.assertIsNone(restrictions.active_restriction("victim"))
        self.assertIsNone(restrictions.release_restriction(item["id"], "user:analyst1"))

    def test_concurrent_creation_yields_one_active_restriction(self):
        barrier = threading.Barrier(8)
        ids: list[str] = []
        errors: list[BaseException] = []
        lock = threading.Lock()

        def worker():
            barrier.wait()
            try:
                item = restrictions.create_restriction(_user("victim"), minutes=10, incident_id=None, action_id=None, actor="t")
                with lock:
                    ids.append(item["id"])
            except BaseException as error:  # noqa: BLE001
                with lock:
                    errors.append(error)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        [t.start() for t in threads]
        [t.join(timeout=60) for t in threads]
        self.assertEqual(errors, [])
        self.assertEqual(len(set(ids)), 1, ids)
        connection = get_db_connection()
        active = connection.execute("SELECT COUNT(*) FROM account_restrictions WHERE user_id='victim' AND status='active'").fetchone()[0]
        connection.close()
        self.assertEqual(active, 1)

    def test_legacy_duplicate_active_rows_are_collapsed_before_index_creation(self):
        connection = get_db_connection()
        connection.execute("DROP INDEX IF EXISTS idx_restrictions_one_active")
        for n in range(2):
            connection.execute(
                "INSERT INTO account_restrictions (id,user_id,kind,status,created_by,created_at,expires_at) VALUES (?,?,?,?,?,?,?)",
                (f"RST-LEGACY{n}", "viewer1", "temp_block", "active", "t", _now(),
                 (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()))
        connection.commit(); connection.close()
        restrictions._ensure_table()
        connection = get_db_connection()
        active = connection.execute("SELECT COUNT(*) FROM account_restrictions WHERE user_id='viewer1' AND status='active'").fetchone()[0]
        connection.close()
        self.assertEqual(active, 1)

    def test_restricted_account_cannot_authenticate(self):
        restrictions.create_restriction(_user("victim"), minutes=10, incident_id=None, action_id=None, actor="t")
        user, reason, _ = security_auth.authenticate("victim", "anything-at-all", ip="198.51.100.7")
        self.assertIsNone(user)
        self.assertEqual(reason, "account_restricted")

    def test_restricted_account_cannot_obtain_websocket_session(self):
        ticket = security_auth.create_websocket_ticket("victim")
        restrictions.create_restriction(_user("victim"), minutes=10, incident_id=None, action_id=None, actor="t")
        self.assertIsNone(security_auth.consume_websocket_ticket(ticket))


# ───────────────────────────── notifications ─────────────────────────────
class NotificationTests(CoreTestCase):
    def test_listing_is_scoped_to_recipient(self):
        notifier.notify("INC-A", "private subject A", "body for a", recipients=["a@example.test"])
        notifier.notify("INC-B", "private subject B", "body for b", recipients=["b@example.test"])
        a = notifier.list_notifications(50, None, "a@example.test")
        b = notifier.list_notifications(50, None, "b@example.test")
        nobody = notifier.list_notifications(50, None, "c@example.test")
        self.assertEqual([n["subject"] for n in a], ["private subject A"])
        self.assertEqual([n["subject"] for n in b], ["private subject B"])
        self.assertEqual(nobody, [])

    def test_unread_tracking_and_cross_user_mark_read_is_a_noop(self):
        notifier.notify("INC-1", "s1", "b", recipients=["a@example.test"])
        notifier.notify("INC-2", "s2", "b", recipients=["a@example.test"])
        notifier.notify("INC-3", "s3", "b", recipients=["b@example.test"])
        self.assertEqual(notifier.unread_count("a@example.test"), 2)
        self.assertEqual(notifier.unread_count("b@example.test"), 1)
        target = notifier.list_notifications(50, None, "a@example.test")[0]["id"]
        self.assertEqual(notifier.mark_read("b@example.test", target), 0, "another user's notification must not be marked read")
        self.assertEqual(notifier.unread_count("a@example.test"), 2)
        self.assertEqual(notifier.mark_read("a@example.test", target), 1)
        self.assertEqual(notifier.mark_read("a@example.test", target), 0, "already read")
        self.assertEqual(notifier.unread_count("a@example.test"), 1)
        self.assertEqual(notifier.mark_read("a@example.test"), 1)
        self.assertEqual(notifier.unread_count("a@example.test"), 0)
        self.assertEqual(notifier.unread_count("b@example.test"), 1, "other user's unread state untouched")

    def test_dedup_within_cooldown_then_allowed_after(self):
        first = notifier.notify("INC-D", "same subject", "body", recipients=["a@example.test"])
        second = notifier.notify("INC-D", "same subject", "body", recipients=["a@example.test"])
        different = notifier.notify("INC-D", "different subject", "body", recipients=["a@example.test"])
        other_recipient = notifier.notify("INC-D", "same subject", "body", recipients=["b@example.test"])
        self.assertEqual((len(first), len(second), len(different), len(other_recipient)), (1, 0, 1, 1))
        connection = get_db_connection()
        connection.execute("UPDATE notifications SET created_at=? WHERE subject='same subject' AND recipient='a@example.test'",
                           ((datetime.now(timezone.utc) - timedelta(minutes=notifier.COOLDOWN_MINUTES + 1)).isoformat(),))
        connection.commit(); connection.close()
        again = notifier.notify("INC-D", "same subject", "body", recipients=["a@example.test"])
        self.assertEqual(len(again), 1)

    def test_concurrent_identical_notifications_store_one_row(self):
        barrier = threading.Barrier(8)

        def worker():
            barrier.wait()
            notifier.notify("INC-C", "burst", "body", recipients=["a@example.test"])

        threads = [threading.Thread(target=worker) for _ in range(8)]
        [t.start() for t in threads]
        [t.join(timeout=60) for t in threads]
        self.assertEqual(len(notifier.list_notifications(50, "INC-C", "a@example.test")), 1)

    def test_without_smtp_rows_are_skipped_never_reported_sent(self):
        row = notifier.notify("INC-S", "s", "b", recipients=["a@example.test"])[0]
        self.assertEqual(row["status"], "skipped")
        self.assertIn("SMTP not configured", row["error"])

    def test_smtp_failure_keeps_in_app_record_and_redacts_secrets(self):
        secret = "unit-test-smtp-secret-123"  # fake value used only to prove redaction
        os.environ["TRUSTNET_SMTP_PASSWORD"] = secret

        def failing(message):
            raise RuntimeError(f"auth failed using {secret}")

        notifier.set_transport_override(failing)
        try:
            row = notifier.notify("INC-F", "s", "b", recipients=["a@example.test"], wait=True)[0]
        finally:
            notifier.set_transport_override(None)
            os.environ.pop("TRUSTNET_SMTP_PASSWORD", None)
        stored = notifier.list_notifications(10, "INC-F", "a@example.test")[0]
        self.assertEqual(stored["status"], "failed")
        self.assertNotIn(secret, stored["error"] or "")
        self.assertIn("[redacted]", stored["error"])
        self.assertEqual(row["id"], stored["id"], "the in-app record survives a delivery failure")

    def test_successful_delivery_marks_sent_and_blocks_header_injection(self):
        captured = []
        notifier.set_transport_override(captured.append)
        try:
            notifier.notify("INC-H", "line1\r\nBcc: evil@example.test", "b", recipients=["a@example.test"], wait=True)
        finally:
            notifier.set_transport_override(None)
        self.assertEqual(len(captured), 1)
        self.assertNotIn("\n", captured[0]["Subject"])
        self.assertIsNone(captured[0]["Bcc"])
        self.assertEqual(notifier.list_notifications(10, "INC-H", "a@example.test")[0]["status"], "sent")


# ───────────────────────────── rate limiting ─────────────────────────────
class RateLimitTests(unittest.TestCase):
    def test_limit_window_and_per_client_isolation(self):
        now = [1000.0]
        limiter = rate_limit.SlidingWindowLimiter(3, 60.0, clock=lambda: now[0])
        self.assertEqual([limiter.allow("1.1.1.1") for _ in range(5)], [True, True, True, False, False])
        self.assertTrue(limiter.allow("2.2.2.2"), "another client has its own budget")
        now[0] += 61
        self.assertTrue(limiter.allow("1.1.1.1"), "budget returns after the window")

    def test_sliding_not_fixed_window(self):
        now = [0.0]
        limiter = rate_limit.SlidingWindowLimiter(2, 10.0, clock=lambda: now[0])
        self.assertTrue(limiter.allow("k")); now[0] = 5
        self.assertTrue(limiter.allow("k")); now[0] = 9
        self.assertFalse(limiter.allow("k"))
        now[0] = 10.5  # the first hit (t=0) has aged out, the second (t=5) has not
        self.assertTrue(limiter.allow("k"))
        self.assertFalse(limiter.allow("k"))

    def test_inactive_client_keys_are_pruned(self):
        now = [0.0]
        limiter = rate_limit.SlidingWindowLimiter(5, 10.0, clock=lambda: now[0])
        for n in range(200):
            limiter.allow(f"10.0.0.{n}")
        now[0] = 25.0
        limiter.allow("active")
        self.assertLessEqual(len(limiter._hits), 2)

    def test_invalid_configuration_fails_fast(self):
        for limit, window in ((0, 60), (-1, 60), (5, 0), (5, -3)):
            with self.assertRaises(ValueError):
                rate_limit.SlidingWindowLimiter(limit, window)

    def test_thread_safety_never_exceeds_limit(self):
        limiter = rate_limit.SlidingWindowLimiter(50, 60.0)
        allowed = []
        lock = threading.Lock()

        def worker():
            n = sum(1 for _ in range(40) if limiter.allow("same"))
            with lock:
                allowed.append(n)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(sum(allowed), 50)

    def test_enabled_defaults_follow_environment(self):
        saved = {k: os.environ.get(k) for k in ("TRUSTNET_ENV", "TRUSTNET_RATE_LIMIT_ENABLED")}
        try:
            os.environ.pop("TRUSTNET_RATE_LIMIT_ENABLED", None)
            os.environ["TRUSTNET_ENV"] = "production"
            self.assertTrue(rate_limit.enabled())
            os.environ["TRUSTNET_ENV"] = "development"
            self.assertFalse(rate_limit.enabled())
            os.environ["TRUSTNET_RATE_LIMIT_ENABLED"] = "1"
            self.assertTrue(rate_limit.enabled())
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


# ───────────────────────────── audit chain ─────────────────────────────
class AuditChainTests(unittest.TestCase):
    """Each test uses its own SQLite file so deliberate tampering cannot affect other tests."""

    def setUp(self):
        self._saved_path = database_module._DB_PATH
        self._saved_boot = security_events._AUDIT_BOOTSTRAPPED_PATH
        self._tmp = tempfile.TemporaryDirectory(prefix="trustnet-audit-")
        database_module._DB_PATH = str(Path(self._tmp.name) / "audit.db")
        security_events._AUDIT_BOOTSTRAPPED_PATH = None
        initialize_database()

    def tearDown(self):
        database_module._DB_PATH = self._saved_path
        security_events._AUDIT_BOOTSTRAPPED_PATH = self._saved_boot
        self._tmp.cleanup()

    def _event(self, n=0, **extra):
        return security_events.persist_security_event({
            "user_id": f"u{n}", "request_path": f"/test/{n}", "http_method": "POST", "event_category": "test",
            "risk_indicators": ["x"], "event_payload": {"n": n}, **extra})

    def test_valid_chain_verifies(self):
        for n in range(5):
            self._event(n)
        result = security_events.verify_audit_chain()
        self.assertTrue(result["valid"], result)
        self.assertEqual(result["checked"], 5)
        self.assertEqual(len(result["head_hash"]), 64)

    def test_tampering_with_event_row_is_detected(self):
        events = [self._event(n) for n in range(3)]
        connection = get_db_connection()
        connection.execute("UPDATE security_events SET event_payload='{\"n\":999}' WHERE id=?", (events[1]["id"],))
        connection.commit(); connection.close()
        result = security_events.verify_audit_chain()
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "event_record_mismatch")
        self.assertEqual(result["broken_event_id"], events[1]["id"])

    def test_audit_entries_are_append_only(self):
        self._event(1)
        connection = get_db_connection()
        with self.assertRaises(sqlite3.DatabaseError):
            connection.execute("UPDATE audit_entries SET event_hash='0'")
        with self.assertRaises(sqlite3.DatabaseError):
            connection.execute("DELETE FROM audit_entries")
        connection.close()

    def test_rewriting_the_ledger_after_dropping_triggers_is_detected(self):
        events = [self._event(n) for n in range(3)]
        connection = get_db_connection()
        connection.execute("DROP TRIGGER audit_entries_no_update")
        connection.execute("UPDATE audit_entries SET payload_json='{}' WHERE event_id=?", (events[0]["id"],))
        connection.commit(); connection.close()
        result = security_events.verify_audit_chain()
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "event_hash_mismatch")

    def test_deleting_an_event_row_is_detected(self):
        events = [self._event(n) for n in range(3)]
        connection = get_db_connection()
        connection.execute("DELETE FROM security_events WHERE id=?", (events[2]["id"],))
        connection.commit(); connection.close()
        result = security_events.verify_audit_chain()
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "event_missing")

    def test_event_inserted_outside_the_chain_is_reported(self):
        self._event(1)
        connection = get_db_connection()
        connection.execute(
            "INSERT INTO security_events (id,timestamp,request_path,http_method,event_category,risk_indicators,event_payload) "
            "VALUES ('EVT-SNEAKY', ?, '/x', 'GET', 'test', '[]', '{}')", (_now(),))
        connection.commit(); connection.close()
        result = security_events.verify_audit_chain()
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "untracked_events")

    def test_pruning_never_breaks_the_chain(self):
        old = "2000-01-01T00:00:00+00:00"
        self._event(1, timestamp=old)
        self._event(2)
        self.assertEqual(security_events.prune_old_events(), 0, "audited events are retained regardless of age")
        self.assertTrue(security_events.verify_audit_chain()["valid"])

    def test_pruning_removes_only_unaudited_legacy_rows(self):
        self._event(1)
        connection = get_db_connection()
        connection.execute(
            "INSERT INTO security_events (id,timestamp,request_path,http_method,event_category,risk_indicators,event_payload) "
            "VALUES ('EVT-LEGACY', '2000-01-01T00:00:00+00:00', '/x', 'GET', 'test', '[]', '{}')")
        connection.commit(); connection.close()
        self.assertEqual(security_events.prune_old_events(), 1)
        self.assertTrue(security_events.verify_audit_chain()["valid"])

    def test_concurrent_writers_keep_a_single_linear_chain(self):
        barrier = threading.Barrier(6)

        def worker(n):
            barrier.wait()
            for k in range(5):
                self._event(n * 100 + k)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
        [t.start() for t in threads]
        [t.join(timeout=90) for t in threads]
        result = security_events.verify_audit_chain()
        self.assertTrue(result["valid"], result)
        self.assertEqual(result["checked"], 30)

    def test_validation_rejects_malformed_events(self):
        for bad in ({}, {"request_path": "no-slash", "http_method": "GET", "event_category": "x"},
                    {"request_path": "/x", "http_method": "BREW", "event_category": "x"},
                    {"request_path": "/x", "http_method": "GET"},
                    {"request_path": "/x", "http_method": "GET", "event_category": "x", "status_code": 99}):
            with self.assertRaises(ValueError):
                security_events.validate_security_event(bad)


# ───────────────────── tokens, tickets, identity ─────────────────────
class AuthCoreTests(CoreTestCase):
    def test_token_roundtrip_and_rejections(self):
        token = security_auth.issue_access_token(_user("analyst1"))
        claims = security_auth.decode_access_token(token)
        self.assertEqual((claims["sub"], claims["role"]), ("analyst1", "analyst"))
        expired = jwt.encode({"sub": "analyst1", "role": "analyst", "jti": "x", "exp": datetime.now(timezone.utc) - timedelta(seconds=5)},
                             security_auth.JWT_SECRET, algorithm="HS256")
        with self.assertRaises(jwt.PyJWTError):
            security_auth.decode_access_token(expired)
        forged = jwt.encode({"sub": "admin", "role": "admin", "jti": "y", "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
                            "attacker-chosen-secret-that-is-long-enough-123", algorithm="HS256")
        with self.assertRaises(jwt.PyJWTError):
            security_auth.decode_access_token(forged)
        unsigned = jwt.encode({"sub": "admin", "role": "admin", "jti": "z"}, key=None, algorithm="none")
        with self.assertRaises(jwt.PyJWTError):
            security_auth.decode_access_token(unsigned)
        with self.assertRaises(jwt.PyJWTError):
            security_auth.decode_access_token(token[:-3] + ("AAA" if not token.endswith("AAA") else "BBB"))

    def test_logout_revocation_persists(self):
        token = security_auth.issue_access_token(_user("analyst1"))
        claims = security_auth.decode_access_token(token)
        security_auth.revoke_access_token(claims)
        with self.assertRaises(jwt.PyJWTError):
            security_auth.decode_access_token(token)
        security_auth._AUTH_DATABASE_PATH = None  # simulate a restart: revocations reload from SQLite
        with self.assertRaises(jwt.PyJWTError):
            security_auth.decode_access_token(token)

    def test_websocket_ticket_is_single_use_expiring_and_requires_active_user(self):
        ticket = security_auth.create_websocket_ticket("analyst1")
        self.assertEqual(security_auth.consume_websocket_ticket(ticket)["id"], "analyst1")
        self.assertIsNone(security_auth.consume_websocket_ticket(ticket), "second use must fail")
        self.assertIsNone(security_auth.consume_websocket_ticket("not-a-ticket"))
        self.assertIsNone(security_auth.consume_websocket_ticket(""))
        expired = security_auth.create_websocket_ticket("analyst1")
        user_id, _ = security_auth._WS_TICKETS[expired]
        security_auth._WS_TICKETS[expired] = (user_id, datetime.now(timezone.utc) - timedelta(seconds=1))
        self.assertIsNone(security_auth.consume_websocket_ticket(expired))
        _insert_user("inactive1", "analyst", active=False)
        self.assertIsNone(security_auth.consume_websocket_ticket(security_auth.create_websocket_ticket("inactive1")))

    def test_unused_expired_tickets_are_pruned(self):
        for _ in range(20):
            t = security_auth.create_websocket_ticket("analyst1")
            security_auth._WS_TICKETS[t] = ("analyst1", datetime.now(timezone.utc) - timedelta(seconds=1))
        security_auth.create_websocket_ticket("analyst1")
        self.assertLessEqual(len(security_auth._WS_TICKETS), 2)

    def test_lockout_applies_to_repeated_attempts_on_unknown_accounts(self):
        # Use a unique identifier/IP so persisted attempts or in-memory lockout
        # state from another test run cannot affect this test's initial attempts.
        identifier = f"ghost-{uuid4().hex}@example.test"
        ip = "198.51.100.20"
        lockout_key = f"unknown:{ip}:{identifier}"
        security_auth._FAILED_BY_USER.pop(lockout_key, None)
        try:
            reasons = [security_auth.authenticate(identifier, "x", ip=ip)[1] for _ in range(7)]
            self.assertEqual(reasons[:5], ["unknown_account"] * 5)
            self.assertEqual(reasons[5:], ["account_locked"] * 2)
        finally:
            security_auth._FAILED_BY_USER.pop(lockout_key, None)

    def test_password_policy_is_enforced_before_hashing(self):
        for email, password, role in (("a@example.test", "short", "viewer"),
                                      ("a@example.test", "x" * 73, "viewer"),
                                      ("a@example.test", "long-enough-password", "superuser"),
                                      ("not-an-email", "long-enough-password", "viewer")):
            with self.assertRaises(ValueError):
                security_auth.create_user(email, password, role)

    def test_permission_matrix(self):
        perms = security_auth.PERMISSIONS
        self.assertEqual(perms["viewer"], {"view_dashboard"})
        self.assertNotIn("approve_incidents", perms["viewer"])
        self.assertIn("approve_incidents", perms["analyst"])
        self.assertNotIn("manage_users", perms["analyst"])
        self.assertIn("manage_users", perms["admin"])


class ProductionStartupTests(unittest.TestCase):
    def _run(self, code: str, env_extra: dict) -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items() if not k.startswith("TRUSTNET_")}
        env.update(env_extra)
        return subprocess.run([sys.executable, "-I", "-c", f"import sys; sys.path.insert(0, {BACKEND_DIR!r}); {code}"],
                              capture_output=True, text=True, env=env, timeout=120)

    def test_production_refuses_short_or_missing_jwt_secret(self):
        for secret in ({}, {"TRUSTNET_JWT_SECRET": "too-short"}):
            result = self._run("import models.security_auth", {"TRUSTNET_ENV": "production", **secret})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("TRUSTNET_JWT_SECRET", result.stderr)

    def test_production_does_not_seed_demo_accounts(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._run(
                "from models import security_auth as a; a.seed_demo_users(); print(len(a._USERS))",
                {"TRUSTNET_ENV": "production", "TRUSTNET_JWT_SECRET": "x" * 40, "TRUSTNET_DB_PATH": str(Path(tmp) / "p.db")})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "0")


if __name__ == "__main__":
    unittest.main()
