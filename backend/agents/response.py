"""Response agent: decides a response, applies autonomy safeguards, and enforces it in the backend.

Destructive actions (device quarantine) execute automatically only when every safeguard passes;
otherwise they are stored as 'pending_approval' and require a human with approve_incidents.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from typing import Any

from models.database import get_db_connection
from models.device_registry import get_device, set_device_status
from models.incident_store import get_incident, transition_incident
from models.risk_engine import compute_risk
from models.account_restrictions import create_restriction
from models.mfa import require_mfa_for_user
from models.security_auth import get_user_by_id
from agents.common import audit, get_settings, log_activity, new_id, now_iso
from agents.notifier import notify

DESTRUCTIVE_ACTIONS = {"quarantine_device", "temp_block_account"}
HUMAN_ONLY_ACTIONS = {"temp_block_account", "restrict_session"}  # sensitive account actions always need recorded human approval
EXECUTING_TIMEOUT_SECONDS = 300
PRIVILEGED_ROLES = {"admin", "analyst"}
CLOSED = {"resolved", "dismissed"}
APPROVAL_TTL_MINUTES = int(os.getenv("TRUSTNET_APPROVAL_TTL_MINUTES", "60"))


class ResponseError(Exception):
    def __init__(self, message: str, status_code: int = 409):
        super().__init__(message)
        self.status_code = status_code


def assert_not_self_target(incident: dict[str, Any], user: dict[str, Any], action_name: str) -> None:
    """An account must never decide an incident about itself (a compromised analyst could neutralise its own
    incident). Raises ResponseError(403) and writes an audit entry for the denied attempt."""
    if incident.get("user_id") and incident["user_id"] == user["id"]:
        audit("response", "decision_denied", incident=incident, actor=f"user:{user['id']}",
              payload={"reason": f"self-decision attempt ({action_name})"})
        raise ResponseError("You cannot decide an incident that targets your own account.", 403)


def _decode(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["safeguards"] = json.loads(item.get("safeguards") or "[]")
    return item


def get_action(action_id: str) -> dict[str, Any] | None:
    connection = get_db_connection()
    try:
        row = connection.execute("SELECT * FROM response_actions WHERE id = ?", (action_id,)).fetchone()
    finally:
        connection.close()
    return _decode(row) if row else None


def list_actions(incident_id: str) -> list[dict[str, Any]]:
    connection = get_db_connection()
    try:
        rows = connection.execute(
            "SELECT * FROM response_actions WHERE incident_id = ? ORDER BY created_at, rowid", (incident_id,)
        ).fetchall()
    finally:
        connection.close()
    return [_decode(row) for row in rows]


def _save(action: dict[str, Any]) -> None:
    connection = get_db_connection()
    try:
        connection.execute(
            """INSERT INTO response_actions
               (id, incident_id, action, target, target_user_id, mode, status, rationale, safeguards, decided_by,
                created_at, updated_at, executed_at, expires_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET mode=excluded.mode, status=excluded.status, rationale=excluded.rationale,
                 safeguards=excluded.safeguards, decided_by=excluded.decided_by, updated_at=excluded.updated_at,
                 executed_at=excluded.executed_at, expires_at=excluded.expires_at""",
            (action["id"], action["incident_id"], action["action"], action["target"], action["target_user_id"],
             action["mode"], action["status"], action["rationale"], json.dumps(action["safeguards"]),
             action["decided_by"], action["created_at"], action["updated_at"], action["executed_at"], action.get("expires_at")),
        )
        connection.commit()
    finally:
        connection.close()


def decide(incident: dict[str, Any], investigation: dict[str, Any]) -> dict[str, Any]:
    """Choose a response from the Investigator's verdict. No side effects."""
    verdict = investigation["verdict"]
    device_id = incident.get("device_id")
    attack_type = (investigation.get("attack_type") or {}).get("type")
    target_user = get_user_by_id(str(incident.get("user_id") or ""))
    attack_evidence = (investigation.get("attack_type") or {}).get("evidence_summary") or {}
    if (attack_type == "stolen_credentials" and int(attack_evidence.get("successful_logins", 0)) > 0
            and target_user and target_user.get("role") == "viewer"
            and (not device_id or get_device(device_id) is None)):
        return {"action": "require_mfa", "target": incident["user_id"],
                "rationale": "Investigator classified likely stolen credentials for a viewer account and no registered device is available for containment; require step-up MFA before the account can continue protected requests."}
    # Risk-based ladder: preserve the specialised stolen-credential and high-confidence
    # containment paths below, but apply a reversible read-only session restriction to
    # elevated-risk sessions that do not yet meet the malicious verdict threshold.
    try:
        risk_score = max(0, min(100, int(incident.get("risk_score", 0))))
    except (TypeError, ValueError):
        risk_score = 0
    if verdict == "likely_malicious" and device_id:
        return {"action": "quarantine_device", "target": device_id,
                "rationale": f"Investigator confidence {investigation['confidence']:.2f} (rules: {', '.join(investigation['fired_rules'])}); quarantine the device to cut off its sessions."}
    if 31 <= risk_score <= 60 and verdict != "likely_malicious" and incident.get("user_id"):
        return {"action": "require_mfa", "target": incident["user_id"],
                "rationale": f"Risk score {risk_score}/100 is in the 31–60 band; require step-up MFA before protected activity continues."}
    if 61 <= risk_score <= 85 and verdict != "likely_malicious" and incident.get("user_id") and not device_id:
        return {"action": "restrict_session", "target": incident["user_id"],
                "rationale": f"Risk score {risk_score}/100 is in the 61–85 elevated-risk band; propose a temporary read-only session restriction pending human approval."}
    if risk_score >= 86 and verdict != "likely_malicious" and incident.get("user_id") and not device_id:
        return {"action": "temp_block_account", "target": incident["user_id"],
                "rationale": f"Risk score {risk_score}/100 is in the 86–100 critical band; propose a temporary account block pending human approval."}
    if verdict == "likely_malicious" and incident.get("user_id"):
        return {"action": "temp_block_account", "target": incident["user_id"],
                "rationale": f"Investigator confidence {investigation['confidence']:.2f} (rules: {', '.join(investigation['fired_rules'])}); no device is associated, so propose a temporary account block (expires automatically)."}
    if verdict in {"likely_malicious", "suspicious"}:
        return {"action": "notify_analyst", "target": None,
                "rationale": f"Verdict '{verdict}' at confidence {investigation['confidence']:.2f}; analyst review needed."}
    return {"action": "monitor", "target": None,
            "rationale": f"Evidence inconclusive (confidence {investigation['confidence']:.2f}); keep monitoring."}


def evaluate_safeguards(incident: dict[str, Any], investigation: dict[str, Any], decision: dict[str, Any]) -> list[dict[str, Any]]:
    """Every check must pass for the agent to act without a human."""
    settings = get_settings()
    user = get_user_by_id(str(incident.get("user_id") or ""))
    device = get_device(decision["target"]) if decision.get("target") else None
    since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    connection = get_db_connection()
    try:
        recent_auto = connection.execute(
            "SELECT COUNT(*) FROM response_actions WHERE mode = 'auto' AND status = 'executed' AND action IN ('quarantine_device', 'temp_block_account') AND executed_at >= ?",
            (since,)).fetchone()[0]
        rejected_before = connection.execute(
            "SELECT COUNT(*) FROM response_actions WHERE incident_id = ? AND status = 'rejected'", (incident["id"],)).fetchone()[0]
    finally:
        connection.close()
    checks = [
        ("kill_switch_off", not settings["kill_switch"], "Kill switch is off" if not settings["kill_switch"] else "Kill switch is ON"),
        ("autonomy_enabled", settings["autonomy_mode"] == "auto_contain", f"autonomy_mode={settings['autonomy_mode']}"),
        ("confidence_threshold", investigation["confidence"] >= settings["auto_min_confidence"],
         f"confidence {investigation['confidence']:.2f} vs required {settings['auto_min_confidence']:.2f}"),
        ("verdict_malicious", investigation["verdict"] == "likely_malicious", f"verdict={investigation['verdict']}"),
        ("target_not_privileged", not (user and user["role"] in PRIVILEGED_ROLES),
         f"account role={user['role'] if user else 'unknown account'}"),
        ("device_present_and_active", decision["action"] != "quarantine_device" or (bool(device) and not device["quarantined"]),
         "device exists and is not yet quarantined" if device and not device["quarantined"] else ("not applicable" if decision["action"] != "quarantine_device" else "device missing or already quarantined")),
        ("human_approval_not_required", decision["action"] not in HUMAN_ONLY_ACTIONS,
         "sensitive account action requires recorded human approval" if decision["action"] in HUMAN_ONLY_ACTIONS else "action may be automatic"),
        ("hourly_cap", recent_auto < settings["auto_max_per_hour"], f"{recent_auto}/{settings['auto_max_per_hour']} automatic actions in the last hour"),
        ("no_prior_analyst_rejection", rejected_before == 0, f"{rejected_before} rejected response(s) on this incident"),
        ("action_reversible", decision["action"] in {"quarantine_device", "temp_block_account"}, "reversible: device trust or automatic expiry/release"),
    ]
    return [{"name": name, "passed": bool(passed), "detail": detail} for name, passed, detail in checks]


def new_action(incident: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
    ts = now_iso()
    return {
        "id": new_id("RSP"), "incident_id": incident["id"], "action": decision["action"], "target": decision.get("target"),
        "target_user_id": incident.get("user_id"), "mode": "pending", "status": "proposed",
        "rationale": decision["rationale"], "safeguards": [], "decided_by": None,
        "created_at": ts, "updated_at": ts, "executed_at": None, "expires_at": None,
    }


def request_approval(action: dict[str, Any], incident: dict[str, Any], *, actor: str, blocked_by: list[str] | None = None) -> dict[str, Any]:
    """Persist a pending approval with an expiry and audit the request."""
    action.update(status="pending_approval", mode="human", updated_at=now_iso(),
                  expires_at=(datetime.now(timezone.utc) + timedelta(minutes=APPROVAL_TTL_MINUTES)).isoformat())
    _save(action)
    audit("response", "approval_requested", incident=incident, actor=actor,
          payload={"response_id": action["id"], "action": action["action"], "target": action["target"],
                   "blocked_by": blocked_by or [], "expires_at": action["expires_at"]})
    return action


def expire_stale(incident_id: str | None = None) -> int:
    """Mark pending approvals past their expiry as 'expired' (atomic, audited). Returns the count."""
    now = now_iso()
    connection = get_db_connection()
    try:
        query = "SELECT id FROM response_actions WHERE status = 'pending_approval' AND expires_at IS NOT NULL AND expires_at <= ?"
        params: list[Any] = [now]
        if incident_id:
            query += " AND incident_id = ?"
            params.append(incident_id)
        ids = [r["id"] for r in connection.execute(query, params).fetchall()]
        expired = []
        for action_id in ids:
            cursor = connection.execute(
                "UPDATE response_actions SET status = 'expired', updated_at = ? WHERE id = ? AND status = 'pending_approval'",
                (now, action_id))
            if cursor.rowcount == 1:
                expired.append(action_id)
        connection.commit()
    finally:
        connection.close()
    for action_id in expired:
        action = get_action(action_id)
        if action:
            audit("response", "approval_expired", incident=get_incident(action["incident_id"]), actor="system:expiry",
                  payload={"response_id": action_id, "action": action["action"]})
    return len(expired)


def recover_stuck(incident_id: str | None = None) -> int:
    """Safe crash recovery: an approval stuck in 'executing' past the timeout is marked 'failed' (never re-run
    automatically, because the enforcement outcome is unknown) and audited. A human must request it again."""
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=EXECUTING_TIMEOUT_SECONDS)).isoformat()
    connection = get_db_connection()
    try:
        query = "SELECT id FROM response_actions WHERE status = 'executing' AND updated_at <= ?"
        params: list[Any] = [cutoff]
        if incident_id:
            query += " AND incident_id = ?"
            params.append(incident_id)
        ids = [r["id"] for r in connection.execute(query, params).fetchall()]
        recovered = []
        for action_id in ids:
            cur = connection.execute("UPDATE response_actions SET status = 'failed', updated_at = ? WHERE id = ? AND status = 'executing'",
                                     (now_iso(), action_id))
            if cur.rowcount == 1:
                recovered.append(action_id)
        connection.commit()
    finally:
        connection.close()
    for action_id in recovered:
        item = get_action(action_id)
        audit("response", "recovered_stuck_execution", incident=get_incident(item["incident_id"]), actor="system:recovery",
              payload={"response_id": action_id, "action": item["action"], "note": "interrupted execution marked failed; re-request approval"})
    return len(recovered)


def _fail(action: dict[str, Any], incident: dict[str, Any] | None, mode: str, actor: str, status: str, reason: str) -> None:
    action.update(status=status, mode=mode, updated_at=now_iso(), decided_by=actor)
    _save(action)
    audit("response", status, incident=incident, actor=actor,
          payload={"response_id": action["id"], "action": action["action"], "reason": reason})


def execute(action: dict[str, Any], *, actor: str, mode: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Enforce an action in the backend, then audit and notify. mode is 'auto' or 'human'.

    Human execution must come through approve() (which atomically claims a pending approval first).
    Automatic execution rechecks the kill switch and protected-account rule immediately before acting.
    """
    incident = get_incident(action["incident_id"])
    if incident is None:
        raise ResponseError("Incident not found.", 404)
    if mode == "auto" and action["action"] in DESTRUCTIVE_ACTIONS:
        settings = get_settings()
        target_user = get_user_by_id(str(incident.get("user_id") or ""))
        if settings["kill_switch"]:
            raise ResponseError("Kill switch is active; automatic enforcement refused.", 409)
        if settings["autonomy_mode"] != "auto_contain":
            raise ResponseError("Autonomous mode is not enabled; automatic enforcement refused.", 409)
        if target_user and target_user["role"] in PRIVILEGED_ROLES:
            raise ResponseError("Administrator and analyst accounts are never blocked automatically.", 403)
        if action["action"] in HUMAN_ONLY_ACTIONS:
            raise ResponseError("This action requires recorded human approval.", 403)
    if incident["status"] in CLOSED:
        _fail(action, incident, mode, actor, "blocked", f"incident {incident['status']}")
        raise ResponseError(f"Incident is {incident['status']}; action blocked.")
    outcome: dict[str, Any] = {}
    if action["action"] == "quarantine_device":
        before = get_device(action["target"] or "")
        if before is None:
            _fail(action, incident, mode, actor, "failed", "target device no longer exists")
            raise ResponseError("Target device no longer exists.", 404)
        try:
            device = set_device_status(action["target"], "flagged", quarantined=True)
            compute_risk(incident["user_id"])
            transition_incident(incident["id"], "investigating", response_action="device_quarantined")
        except Exception as error:  # enforcement failure must be recorded, never silently reported as success
            _fail(action, incident, mode, actor, "failed", f"enforcement error: {type(error).__name__}")
            raise ResponseError("Enforcement failed; see audit log.", 500) from error
        outcome = {"device_id": device["device_id"], "quarantined": device["quarantined"], "previous_trust_status": before["trust_status"]}
    elif action["action"] == "temp_block_account":
        target = get_user_by_id(str(action["target"] or ""))
        if target is None:
            _fail(action, incident, mode, actor, "failed", "target account no longer exists")
            raise ResponseError("Target account no longer exists.", 404)
        try:
            restriction = create_restriction(target, minutes=None, incident_id=incident["id"], action_id=action["id"],
                                             actor=actor, reason=action["rationale"])
            transition_incident(incident["id"], "investigating", response_action="account_temporarily_blocked")
        except ValueError as refusal:
            _fail(action, incident, mode, actor, "blocked", str(refusal))
            raise ResponseError(str(refusal), 403) from refusal
        except Exception as error:  # enforcement failure must be recorded, never silently reported as success
            _fail(action, incident, mode, actor, "failed", f"enforcement error: {type(error).__name__}")
            raise ResponseError("Enforcement failed; see audit log.", 500) from error
        outcome = {"restriction_id": restriction["id"], "user_id": target["id"], "expires_at": restriction["expires_at"]}
    elif action["action"] == "restrict_session":
        target = get_user_by_id(str(action.get("target_user_id") or action.get("target") or incident.get("user_id") or ""))
        if target is None:
            _fail(action, incident, mode, actor, "failed", "target account no longer exists")
            raise ResponseError("Target account no longer exists.", 404)
        try:
            restriction = create_restriction(target, minutes=30, incident_id=incident["id"], action_id=action["id"],
                                             actor=actor, reason=action["rationale"], mode="read_only")
            transition_incident(incident["id"], "investigating", response_action="session_restricted_read_only")
        except TypeError:
            # Backward-compatible fallback for restriction stores that expose read-only
            # as the default mode rather than a keyword argument.
            restriction = create_restriction(target, minutes=30, incident_id=incident["id"], action_id=action["id"],
                                             actor=actor, reason=action["rationale"])
        except ValueError as refusal:
            _fail(action, incident, mode, actor, "blocked", str(refusal))
            raise ResponseError(str(refusal), 403) from refusal
        except Exception as error:
            _fail(action, incident, mode, actor, "failed", f"enforcement error: {type(error).__name__}")
            raise ResponseError("Session restriction failed; see audit log.", 500) from error
        outcome = {"restriction_id": restriction["id"], "user_id": target["id"], "mode": "read_only", "expires_at": restriction["expires_at"]}
    elif action["action"] == "require_mfa":
        target_user_id = str(action.get("target_user_id") or action.get("target") or incident.get("user_id") or "")
        if not target_user_id:
            _fail(action, incident, mode, actor, "failed", "MFA action has no target user")
            raise ResponseError("MFA action has no target user.", 422)
        try:
            require_mfa_for_user(target_user_id, "account")
        except Exception as error:
            _fail(action, incident, mode, actor, "failed", f"MFA enforcement error: {type(error).__name__}")
            raise ResponseError("Could not require MFA; see audit log.", 500) from error
        outcome = {"user_id": target_user_id, "mfa_required": True, "scope": "account"}
        transition_incident(incident["id"], "investigating", response_action="mfa_step_up_required")
    elif action["action"] == "notify_analyst":
        label = incident.get("incident_label") or incident["id"]
        notify(incident["id"], f"{label}: analyst review needed ({incident['severity']})",
               f"Incident {label} for user {incident['user_id']} at fused risk {incident['risk_score']}.\n{action['rationale']}")
        outcome = {"notified": True}
    elif action["action"] == "monitor":
        outcome = {"monitoring": True}
    else:
        _fail(action, incident, mode, actor, "failed", "unsupported action")
        raise ResponseError(f"Unsupported action {action['action']}", 422)
    action.update(status="executed", mode=mode, decided_by=actor, updated_at=now_iso(), executed_at=now_iso())
    _save(action)
    audit("response", "executed", incident=incident, actor=actor,
          payload={"response_id": action["id"], "action": action["action"], "target": action["target"], "mode": mode, "outcome": outcome,
                   "safeguards": action["safeguards"], **(extra or {})})
    log_activity(incident["id"], "response", "executed", f"{action['action']} executed ({mode}) by {actor}", {"response_id": action["id"], **outcome})
    return action


def _claim(action_id: str, actor: str) -> bool:
    """Atomically move pending_approval -> executing. Exactly one concurrent caller can win."""
    now = now_iso()
    connection = get_db_connection()
    try:
        cursor = connection.execute(
            "UPDATE response_actions SET status = 'executing', mode = 'human', decided_by = ?, updated_at = ? "
            "WHERE id = ? AND status = 'pending_approval' AND (expires_at IS NULL OR expires_at > ?)",
            (actor, now, action_id, now))
        connection.commit()
        return cursor.rowcount == 1
    finally:
        connection.close()


def approve(action_id: str, approver: dict[str, Any]) -> dict[str, Any]:
    """Human approval. 403 unauthorized/self-approval, 404 unknown, 409 already decided or expired."""
    action = get_action(action_id)
    if action is None:
        raise ResponseError("Response action not found.", 404)
    incident = get_incident(action["incident_id"])
    actor = f"user:{approver['id']}"
    if approver.get("role") not in PRIVILEGED_ROLES:
        audit("response", "approval_denied", incident=incident, actor=actor,
              payload={"response_id": action_id, "reason": "insufficient role"})
        raise ResponseError("Only administrators or analysts may approve response actions.", 403)
    if action["target_user_id"] and approver["id"] == action["target_user_id"]:
        audit("response", "approval_denied", incident=incident, actor=actor,
              payload={"response_id": action_id, "reason": "self-approval attempt"})
        raise ResponseError("You cannot approve an action that targets your own account.", 403)
    if action["status"] == "pending_approval" and action.get("expires_at") and action["expires_at"] <= now_iso():
        expire_stale(action["incident_id"])
        raise ResponseError("Approval request has expired; a new request is required.", 409)
    if not _claim(action_id, actor):
        current = get_action(action_id) or action
        raise ResponseError(f"Action is {current['status']}, not pending approval.", 409)
    claimed = get_action(action_id)
    audit("response", "approval_granted", incident=incident, actor=actor,
          payload={"response_id": action_id, "action": claimed["action"], "target": claimed["target"]})
    try:
        return execute(claimed, actor=actor, mode="human")
    except Exception as error:
        # execute() records most failures itself. If it raised before doing so (or hit an unexpected error), the
        # claim would stay in 'executing' until crash recovery; mark it failed now so the outcome is explicit.
        current = get_action(action_id)
        if current and current["status"] == "executing":
            _fail(current, get_incident(current["incident_id"]), "human", actor, "failed",
                  f"execution aborted: {type(error).__name__}")
        raise


def reject(action_id: str, approver: dict[str, Any], reason: str = "") -> dict[str, Any]:
    action = get_action(action_id)
    if action is None:
        raise ResponseError("Response action not found.", 404)
    if approver.get("role") not in PRIVILEGED_ROLES:
        raise ResponseError("Only administrators or analysts may reject response actions.", 403)
    if action["target_user_id"] and approver["id"] == action["target_user_id"]:
        audit("response", "rejection_denied", incident=get_incident(action["incident_id"]), actor=f"user:{approver['id']}",
              payload={"response_id": action_id, "reason": "self-decision attempt (reject)"})
        raise ResponseError("You cannot reject an action that targets your own account.", 403)
    now = now_iso()
    connection = get_db_connection()
    try:
        cursor = connection.execute(
            "UPDATE response_actions SET status = 'rejected', mode = 'human', decided_by = ?, updated_at = ? "
            "WHERE id = ? AND status = 'pending_approval'", (f"user:{approver['id']}", now, action_id))
        connection.commit()
        won = cursor.rowcount == 1
    finally:
        connection.close()
    if not won:
        raise ResponseError(f"Action is {(get_action(action_id) or action)['status']}, not pending approval.", 409)
    action = get_action(action_id)
    incident = get_incident(action["incident_id"])
    audit("response", "rejected", incident=incident, actor=f"user:{approver['id']}",
          payload={"response_id": action["id"], "action": action["action"], "reason": reason[:300]})
    log_activity(action["incident_id"], "response", "rejected", f"{action['action']} rejected by {approver['id']}", {"response_id": action["id"]})
    return action
