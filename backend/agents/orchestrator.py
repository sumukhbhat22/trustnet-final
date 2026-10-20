"""Agent orchestrator wiring Investigator -> Response -> notification/audit, plus analyst feedback."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import os
import threading
from typing import Any

from models.device_registry import get_device
from models.incident_store import get_incident, save_investigation, transition_incident
from models import risk_policy
from models.risk_engine import compute_risk
from agents import investigator, learning, response
from agents.common import audit, log_activity, new_id, now_iso
from agents.notifier import alert_recipients, notify

_log = logging.getLogger(__name__)
_lock = threading.RLock()
CLOSED = {"resolved", "dismissed"}
REPORT_SEVERITIES = {"high", "critical"}
MIN_REINVESTIGATE_SECONDS = 15  # throttle: per-request network events must not flood the audit chain


def _summary(incident: dict[str, Any], investigation: dict[str, Any] | None, action: dict[str, Any] | None, ran: bool) -> dict[str, Any]:
    return {
        "incident_id": incident["id"], "incident_label": incident.get("incident_label"), "ran": ran,
        "verdict": investigation["verdict"] if investigation else None,
        "confidence": investigation["confidence"] if investigation else None,
        "fired_rules": investigation["fired_rules"] if investigation else [],
        "response": {k: action[k] for k in ("id", "action", "target", "mode", "status")} if action else None,
    }


def _report_text(incident: dict[str, Any], investigation: dict[str, Any], action: dict[str, Any] | None, trigger: str) -> tuple[str, str]:
    label = incident.get("incident_label") or incident["id"]
    severity = str(incident.get("severity", "")).upper()
    attack = investigation.get("attack_type") or {}
    evidence = attack.get("evidence_summary") or {}
    failed_checks = [c["name"] for c in (action or {}).get("safeguards", []) if not c.get("passed")]

    if action is None:
        outcome, short = "No automated action was proposed.", "no action"
    elif action["status"] == "executed":
        who = "automatically by the Response agent" if action.get("mode") == "auto" else f"after human approval by {action.get('decided_by')}"
        outcome, short = f"EXECUTED {who} at {action.get('executed_at')}.", "action executed"
    elif action["status"] == "pending_approval":
        why = f" Automatic execution was blocked by: {', '.join(failed_checks)}." if failed_checks else ""
        outcome, short = f"AWAITING HUMAN APPROVAL. Nothing has been enforced yet.{why}", "awaiting approval"
    else:
        outcome, short = f"Status: {action['status']}.", action["status"]

    lines = [
        "TrustNet AI - agentic response report",
        "=" * 40,
        f"Incident:   {label} ({incident['id']})",
        f"Severity:   {severity}      Fused risk score: {incident.get('risk_score')}/100",
        f"Status:     {incident.get('status')}      Triggered by: {trigger}",
        f"User:       {incident.get('user_id')}      Device: {incident.get('device_id') or 'n/a'}",
        f"Opened:     {incident.get('created_at')}",
        "",
        "1. WHAT THE INVESTIGATOR AGENT FOUND",
        f"Verdict:     {investigation['verdict']} (confidence {investigation['confidence']:.2f})",
        f"Attack type: {attack.get('type', 'unknown')} (confidence {attack.get('confidence', 'n/a')})",
        f"Evidence:    {evidence.get('failed_logins', 0)} failed logins, {evidence.get('successful_logins', 0)} successful logins, "
        f"{evidence.get('sensitive_events', 0)} sensitive-resource events, {investigation.get('event_count', 0)} linked events",
        "Rules fired:",
    ]
    fired = [r for r in investigation.get("rules", []) if r.get("fired")]
    lines += [f"  - {r['name']}: {r.get('detail') or 'no detail'}" for r in fired[:8]] or ["  - none"]
    if incident.get("evidence"):
        lines += ["Recorded evidence:"] + [f"  - {item}" for item in incident["evidence"][:6]]

    lines += ["", "2. WHAT THE RESPONSE AGENT DID"]
    if action:
        lines += [
            f"Action:     {action['action']} on {action.get('target')}",
            f"Outcome:    {outcome}",
            f"Rationale:  {action.get('rationale') or 'n/a'}",
        ]
        if action.get("safeguards"):
            lines.append("Safeguards: " + "; ".join(f"{c['name']}={'pass' if c.get('passed') else 'FAIL'}" for c in action["safeguards"]))
    else:
        lines.append(outcome)
    if attack.get("recommended_action"):
        lines.append(f"Investigator recommends: {attack['recommended_action']}")

    dashboard = os.environ.get("TRUSTNET_DASHBOARD_URL", "http://localhost:8080").rstrip("/")
    lines += [
        "",
        "3. WHAT YOU SHOULD DO",
        "Review the incident, approve or reject any pending action, and record a verdict (true/false positive) so the agents can learn.",
        f"Incident Center: {dashboard}/incidents",
        "",
        "Every step above is recorded in the tamper-evident audit chain. This message was generated by TrustNet's deterministic agents, not a language model.",
    ]
    subject = f"{label}: {severity} incident - agent report ({short})"
    return subject, "\n".join(lines)


def send_incident_report(incident: dict[str, Any] | None, investigation: dict[str, Any], action: dict[str, Any] | None, trigger: str) -> None:
    """Email staff a detailed report for high/critical incidents; delivery problems never affect handling."""
    if not incident or str(incident.get("severity", "")).lower() not in REPORT_SEVERITIES:
        return
    try:
        subject, body = _report_text(incident, investigation, action, trigger)
        notify(incident["id"], subject, body, recipients=alert_recipients())
        log_activity(incident["id"], "notifier", "report_sent", subject, {"severity": incident.get("severity")})
    except Exception:  # reporting is best-effort
        _log.exception("Could not send incident report for %s", incident.get("id"))


def process_incident(incident_id: str, trigger: str = "pipeline", *, force: bool = False) -> dict[str, Any] | None:
    """Idempotently investigate an incident and decide/enforce a response."""
    with _lock:
        incident = get_incident(incident_id)
        if incident is None or incident["status"] in CLOSED:
            return None
        previous = incident.get("investigator_findings")
        recent = False
        if previous:
            try:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(previous["investigated_at"])).total_seconds()
                recent = age < MIN_REINVESTIGATE_SECONDS
            except (KeyError, ValueError):
                recent = False
        signature_changed = bool(previous) and previous.get("signature") != investigator.evidence_signature(incident)
        unchanged = previous and not force and not signature_changed and (
            recent or (
                previous.get("event_count") == len(incident.get("event_ids") or [])
                and previous.get("fused_risk_score") == incident.get("risk_score")
            )
        )
        if unchanged:
            actions = response.list_actions(incident_id)
            return _summary(incident, previous, actions[-1] if actions else None, ran=False)

        response.expire_stale(incident_id)
        response.recover_stuck(incident_id)
        investigation = investigator.investigate(incident)
        save_investigation(incident_id, investigation)
        incident = get_incident(incident_id)
        log_activity(incident_id, "investigator", "completed",
                     f"{investigation['verdict']} (confidence {investigation['confidence']:.2f}) via {trigger}",
                     {"fired_rules": investigation["fired_rules"]})
        audit("investigator", "completed", incident=incident, actor="agent:investigator",
              payload={"verdict": investigation["verdict"], "confidence": investigation["confidence"],
                       "fired_rules": investigation["fired_rules"], "trigger": trigger})

        decision = response.decide(incident, investigation)
        existing = [a for a in response.list_actions(incident_id) if a["action"] == decision["action"] and a["status"] in {"pending_approval", "executed"}]
        if existing and existing[-1]["status"] == "executed":
            return _summary(incident, investigation, existing[-1], ran=True)
        action = existing[-1] if existing else response.new_action(incident, decision)
        action["rationale"] = decision["rationale"]
        action["safeguards"] = response.evaluate_safeguards(incident, investigation, decision) if decision["action"] in response.DESTRUCTIVE_ACTIONS else []
        log_activity(incident_id, "response", "decided", f"Proposed {decision['action']}", {"safeguards": action["safeguards"]})

        executed_auto = False
        if decision["action"] not in response.DESTRUCTIVE_ACTIONS:
            action = response.execute(action, actor="agent:response", mode="auto")
            executed_auto = True
        elif all(check["passed"] for check in action["safeguards"]):
            try:
                action = response.execute(action, actor="agent:response", mode="auto")
                executed_auto = True
            except response.ResponseError as refusal:  # last-moment recheck (kill switch etc.) refused: queue for a human
                action["safeguards"].append({"name": "execution_recheck", "passed": False, "detail": str(refusal)})
        if not executed_auto:
            already_pending = action.get("status") == "pending_approval"
            failed = [c["name"] for c in action["safeguards"] if not c["passed"]]
            if already_pending:
                response._save(action)  # refresh rationale/safeguards; keep the original expiry and request
            else:
                response.request_approval(action, incident, actor="agent:response", blocked_by=failed)
                label = incident.get("incident_label") or incident["id"]
                notify(incident_id, f"{label}: approval required for {action['action']}",
                       f"The Response agent proposes {action['action']} on {action['target']} for user {incident['user_id']}.\n"
                       f"{action['rationale']}\nAutomatic execution blocked by: {', '.join(failed)}.")
                log_activity(incident_id, "response", "approval_requested", f"{action['action']} awaiting human approval", {"blocked_by": failed})
        send_incident_report(get_incident(incident_id), investigation, action, trigger)
        return _summary(get_incident(incident_id), investigation, action, ran=True)


def approve_incident(incident_id: str, approver: dict[str, Any]) -> dict[str, Any]:
    """Legacy-compatible POST /incidents/{id}/approve.

    Same safeguards as the response route: no self-approval (403), a real pending approval record is
    required before any enforcement. If the analyst approves an incident that has a device but no pending
    action, an approval request is first recorded (and audited) and then decided atomically.
    """
    with _lock:
        incident = get_incident(incident_id)
        if incident is None:
            raise response.ResponseError("Incident not found.", 404)
        if incident["status"] in CLOSED:
            raise response.ResponseError(f"Cannot approve incident in {incident['status']} status.")
        actor = f"user:{approver['id']}"
        if approver.get("role") not in response.PRIVILEGED_ROLES:
            raise response.ResponseError("Only administrators or analysts may approve incidents.", 403)
        if incident.get("user_id") and approver["id"] == incident["user_id"]:
            audit("response", "approval_denied", incident=incident, actor=actor, payload={"reason": "self-approval attempt (incident approval)"})
            raise response.ResponseError("You cannot approve an incident that targets your own account.", 403)
        response.expire_stale(incident_id)
        pending = [a for a in response.list_actions(incident_id) if a["action"] in {"quarantine_device", "temp_block_account"} and a["status"] == "pending_approval"]
        device = get_device(incident["device_id"]) if incident.get("device_id") else None
        if pending:
            action = response.approve(pending[-1]["id"], approver)
        elif device:
            action = response.new_action(incident, {"action": "quarantine_device", "target": device["device_id"],
                                                    "rationale": "Analyst requested quarantine directly from the incident."})
            response.request_approval(action, incident, actor=actor, blocked_by=["analyst_initiated"])
            action = response.approve(action["id"], approver)
        else:
            action = None
            transition_incident(incident_id, "investigating", response_action="approved_for_manual_review")
            audit("response", "manual_review_approved", incident=incident, actor=actor, payload={})
            log_activity(incident_id, "response", "manual_review", f"Approved for manual review by {approver['id']}")
        return {"incident": get_incident(incident_id), "device": get_device(incident["device_id"]) if device else None, "action": action}


def submit_verdict(incident_id: str, verdict: str, notes: str, analyst: dict[str, Any]) -> dict[str, Any]:
    if verdict not in {"true_positive", "false_positive"}:
        raise response.ResponseError("verdict must be true_positive or false_positive", 422)
    with _lock:
        incident = get_incident(incident_id)
        if incident is None:
            raise response.ResponseError("Incident not found.", 404)
        if analyst.get("role") not in response.PRIVILEGED_ROLES:
            raise response.ResponseError("Only administrators or analysts may label incidents.", 403)
        if incident.get("user_id") and analyst["id"] == incident["user_id"]:
            audit("feedback", "verdict_denied", incident=incident, actor=f"user:{analyst['id']}",
                  payload={"reason": "self-labelling attempt"})
            raise response.ResponseError("You cannot label an incident that targets your own account.", 403)
        existing_feedback = learning.latest_feedback_for_incident(incident_id)
        if learning.is_duplicate_verdict(existing_feedback, verdict):
            # Do not duplicate feedback rows, training evidence, activity, or audit events
            # when a client retries the same verdict. A different verdict remains a correction.
            return {"feedback": existing_feedback, "learning": learning.evaluate(), "duplicate": True,
                    "score_effect": risk_policy.get_verdict_effect(incident_id),
                    "profile_effect": learning.get_behavior_profile(str(get_incident(incident_id).get("user_id") or ""))}
        findings = incident.get("investigator_findings") or investigator.investigate(incident)
        feedback = {
            "id": new_id("FDB"), "incident_id": incident_id, "verdict": verdict, "notes": (notes or "")[:1000],
            "analyst_id": analyst["id"], "rules_fired": findings["fired_rules"],
            "investigator_confidence": findings["confidence"], "created_at": now_iso(),
        }
        learning.record_feedback(feedback)
        # Persist a visible EMA/baseline update for replay and audit. This does not retrain a model.
        profile_effect = learning.update_behavior_profile(incident, verdict)
        score_effect = None
        if incident.get("user_id"):
            target = incident["user_id"]
            score_effect = risk_policy.record_verdict_effect(
                incident_id=incident_id, user_id=target, verdict=verdict, feedback_id=feedback["id"],
                score_before=compute_risk(target)["score"],
                score_after_fn=lambda: compute_risk(target)["score"])
        result = learning.evaluate()
        audit("feedback", "verdict_recorded", incident=incident, actor=f"user:{analyst['id']}",
              payload={"verdict": verdict, "rules_fired": findings["fired_rules"], "learning_status": result["status"],
                       "labeled_incidents": result["labeled_incidents"],
                       "score_before": (score_effect or {}).get("score_before"), "score_after": (score_effect or {}).get("score_after"),
                       "policy_version": (score_effect or {}).get("policy_version")})
        log_activity(incident_id, "feedback", "verdict", f"{analyst['id']} marked {verdict}", {"learning_status": result["status"]})
        return {"feedback": feedback, "learning": result, "duplicate": False, "score_effect": score_effect,
                "profile_effect": profile_effect}


def incident_agent_view(incident_id: str) -> dict[str, Any] | None:
    from agents.common import list_activity
    from agents.notifier import list_notifications
    incident = get_incident(incident_id)
    if incident is None:
        return None
    return {
        "incident_id": incident_id,
        "investigation": incident.get("investigator_findings"),
        "responses": response.list_actions(incident_id),
        "feedback": learning.list_feedback(incident_id),
        "activity": list_activity(50, incident_id),
        "notifications": list_notifications(20, incident_id),
    }
