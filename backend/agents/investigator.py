"""Investigator agent: read-only evidence tools plus five deterministic detection rules.

The Investigator can only SELECT from SQLite (the connection is opened with query_only).
It never changes devices, accounts, or incidents; persistence of its findings is done by the
orchestrator.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import os
import json
from typing import Any

from models.database import get_readonly_connection
from agents.learning import (
    MALICIOUS_THRESHOLD, SUSPICIOUS_THRESHOLD, DEFAULT_WEIGHTS, active_weights, confidence_for,
)

RULES = {
    "credential_attack": "Repeated failed logins before access",
    "untrusted_device": "Activity from a device that is not trusted",
    "multi_ip_activity": "Account used from several IP addresses in a short window",
    "model_consensus": "Supervised classifier and Isolation Forest agree",
    "suspicious_request_pattern": "Burst of flagged or rejected requests",
}


def _parse_ts(value: str | None) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return datetime.now(timezone.utc)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class EvidenceTools:
    """Read-only evidence access. Every method issues SELECT statements only."""

    def __init__(self, incident: dict[str, Any]):
        self.incident = incident
        self.user_id = incident.get("user_id")
        self.device_id = incident.get("device_id")
        self.anchor = _parse_ts(incident.get("updated_at") or incident.get("created_at"))

    def _since(self, minutes: int) -> str:
        return (self.anchor - timedelta(minutes=minutes)).isoformat()

    def _query(self, sql: str, params: tuple) -> list[dict[str, Any]]:
        connection = get_readonly_connection()
        try:
            return [dict(row) for row in connection.execute(sql, params).fetchall()]
        finally:
            connection.close()

    def login_attempts(self, minutes: int = 60) -> list[dict[str, Any]]:
        return self._query(
            "SELECT timestamp, success, ip, device_id, reason FROM login_attempts "
            "WHERE user_id = ? AND timestamp >= ? ORDER BY timestamp", (self.user_id, self._since(minutes)))

    def user_events(self, minutes: int = 60, limit: int = 200) -> list[dict[str, Any]]:
        rows = self._query(
            "SELECT id, timestamp, ip_address, request_path, status_code, event_category, risk_indicators "
            "FROM security_events WHERE user_id = ? AND timestamp >= ? AND event_category != 'agent_action' "
            "ORDER BY timestamp DESC LIMIT ?", (self.user_id, self._since(minutes), limit))
        for row in rows:
            row["risk_indicators"] = json.loads(row["risk_indicators"] or "[]")
        return rows

    def device(self) -> dict[str, Any] | None:
        if not self.device_id:
            return None
        rows = self._query("SELECT device_id, trust_status, quarantined, first_seen, last_seen FROM devices WHERE device_id = ?", (self.device_id,))
        return rows[0] if rows else None


def _rule_credential_attack(tools: EvidenceTools, incident: dict[str, Any]) -> tuple[bool, str, list[str]]:
    attempts = tools.login_attempts(60)
    failures = [a for a in attempts if not a["success"]]
    ips = {a["ip"] for a in failures}
    fired = len(failures) >= 3 or (len(failures) >= 2 and len(ips) >= 2)
    return fired, f"{len(failures)} failed login(s) from {len(ips)} IP(s) in the last hour", [f"failed@{a['timestamp']} from {a['ip']}" for a in failures[:5]]


def _rule_untrusted_device(tools: EvidenceTools, incident: dict[str, Any]) -> tuple[bool, str, list[str]]:
    device = tools.device()
    status = (device or {}).get("trust_status") or incident.get("risk_breakdown", {}).get("device_trust", {}).get("status")
    fired = status in {"unknown", "flagged"}
    return fired, f"Device trust status is '{status or 'missing'}'", [f"device={tools.device_id}"] if tools.device_id else []


def _rule_multi_ip(tools: EvidenceTools, incident: dict[str, Any]) -> tuple[bool, str, list[str]]:
    ips = {a["ip"] for a in tools.login_attempts(60) if a["ip"]} | {e["ip_address"] for e in tools.user_events(60) if e["ip_address"]}
    return len(ips) >= 3, f"{len(ips)} distinct IP address(es) in the last hour", sorted(ips)[:6]


def _rule_model_consensus(tools: EvidenceTools, incident: dict[str, Any]) -> tuple[bool, str, list[str]]:
    breakdown = incident.get("risk_breakdown") or {}
    classifier = breakdown.get("classifier", {})
    forest = breakdown.get("isolation_forest", {})
    label = str(classifier.get("label", "unknown")).lower()
    confidence = float(classifier.get("confidence") or 0)
    anomaly = float(forest.get("score") or 0)
    fired = label not in {"benign", "unknown", ""} and confidence >= 70 and anomaly >= 50
    return fired, f"Classifier '{label}' at {confidence:.0f}% confidence; Isolation Forest anomaly {anomaly:.0f}/100", [f"classifier={label}", f"isolation_forest={anomaly:.0f}"]


def _rule_request_pattern(tools: EvidenceTools, incident: dict[str, Any]) -> tuple[bool, str, list[str]]:
    events = tools.user_events(15)
    flagged = [e for e in events if e["risk_indicators"]]
    rejected = [e for e in events if e["status_code"] in {401, 403, 404, 429}]
    fired = len(flagged) >= 3 or len(rejected) >= 5
    return fired, f"{len(flagged)} flagged and {len(rejected)} rejected request(s) in the last 15 minutes", [f"{e['request_path']} -> {e['status_code']}" for e in (flagged or rejected)[:5]]


_RULE_FUNCS = {
    "credential_attack": _rule_credential_attack,
    "untrusted_device": _rule_untrusted_device,
    "multi_ip_activity": _rule_multi_ip,
    "model_consensus": _rule_model_consensus,
    "suspicious_request_pattern": _rule_request_pattern,
}


def evidence_signature(incident: dict[str, Any]) -> dict[str, Any]:
    """Cheap read-only fingerprint of the login evidence; a change means re-investigation is warranted."""
    tools = EvidenceTools(incident)
    attempts = tools.login_attempts(60)
    device = tools.device() or {}
    return {
        "failed_logins": sum(1 for a in attempts if not a["success"]),
        "login_ips": len({a["ip"] for a in attempts if a["ip"]}),
        "device_trust": device.get("trust_status"),
        "quarantined": bool(device.get("quarantined")),
    }



def classify_attack_type(incident: dict[str, Any], fired_ids: list[str],
                        attempts: list[dict[str, Any]], events: list[dict[str, Any]]) -> dict[str, Any]:
    """Deterministically label the likely attack family from observed evidence.

    This is an explainable demo classifier, not a trained model. It deliberately
    returns ``unknown`` when the evidence does not support a specific label.
    """
    fired = set(fired_ids)
    failed = [row for row in attempts if not row.get("success")]
    succeeded = [row for row in attempts if row.get("success")]
    paths = [str(row.get("request_path") or "").lower() for row in events]
    evidence_text = " ".join(str(item).lower() for item in (incident.get("evidence") or []))
    sensitive_terms = ("export", "download", "admin-db", "finance-db", "hr", "records", "bulk")
    sensitive_events = [row for row, path in zip(events, paths) if any(term in path for term in sensitive_terms)]

    # Timestamps are stored as UTC; evaluate after-hours in the configured
    # organization timezone rather than accidentally treating UTC as local time.
    try:
        business_tz = ZoneInfo(os.getenv("TRUSTNET_BUSINESS_TIMEZONE", "Asia/Kolkata"))
    except ZoneInfoNotFoundError:
        business_tz = timezone.utc
    after_hours_sensitive = any(
        (_parse_ts(row.get("timestamp")).astimezone(business_tz).hour < 6
         or _parse_ts(row.get("timestamp")).astimezone(business_tz).hour >= 20)
        for row in sensitive_events
    )
    if after_hours_sensitive:
        attack_type, confidence, action = "after_hours_insider", 0.82, "step_up_authentication_and_review_access"
    elif sensitive_events or any(term in evidence_text for term in sensitive_terms):
        attack_type, confidence, action = "data_exfiltration", 0.88, "restrict_export_and_require_analyst_review"
    elif "credential_attack" in fired and len(failed) >= 5 and not succeeded:
        attack_type, confidence, action = "brute_force", 0.90, "rate_limit_login_and_require_mfa"
    elif "credential_attack" in fired and (succeeded or "untrusted_device" in fired or "model_consensus" in fired):
        attack_type, confidence, action = "stolen_credentials", 0.82, "require_mfa_and_review_session"
    elif "credential_attack" in fired:
        attack_type, confidence, action = "brute_force", 0.70, "rate_limit_login_and_require_mfa"
    else:
        attack_type, confidence, action = "unknown", 0.35, "monitor_and_request_analyst_review"

    return {"type": attack_type, "confidence": confidence, "recommended_action": action,
            "method": "deterministic_evidence_rules", "evidence_summary": {
                "failed_logins": len(failed), "successful_logins": len(succeeded),
                "sensitive_events": len(sensitive_events), "fired_rules": sorted(fired)}}

def investigate(incident: dict[str, Any]) -> dict[str, Any]:
    """Run all rules against read-only evidence and return a structured, explainable finding."""
    tools = EvidenceTools(incident)
    weights = active_weights()
    results = []
    for rule_id, fn in _RULE_FUNCS.items():
        fired, detail, evidence = fn(tools, incident)
        results.append({
            "rule_id": rule_id, "name": RULES[rule_id], "fired": bool(fired),
            "weight": round(weights.get(rule_id, DEFAULT_WEIGHTS[rule_id]), 4),
            "detail": detail, "evidence": evidence,
        })
    fired_ids = [r["rule_id"] for r in results if r["fired"]]
    confidence = confidence_for(fired_ids, weights)
    verdict = "likely_malicious" if confidence >= MALICIOUS_THRESHOLD else "suspicious" if confidence >= SUSPICIOUS_THRESHOLD else "inconclusive"
    attack_type = classify_attack_type(incident, fired_ids, tools.login_attempts(60), tools.user_events(60))
    return {
        "incident_id": incident["id"], "verdict": verdict, "confidence": confidence,
        "attack_type": attack_type,
        "fired_rules": fired_ids, "rules": results,
        "fused_risk_score": incident.get("risk_score"),
        "event_count": len(incident.get("event_ids") or []),
        "signature": evidence_signature(incident),
        "investigated_at": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
    }
