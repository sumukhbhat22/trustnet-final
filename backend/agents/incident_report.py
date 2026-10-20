"""Detailed incident emails (plain text + HTML) built only from data TrustNet already stores.

Never included: passwords, tokens, MFA codes, or raw request bodies. Every dynamic value is HTML-escaped.
"""

from __future__ import annotations

import html
import json
import logging
import os
from typing import Any

from agents import investigator, response
from agents.common import audit, log_activity
from agents.notifier import alert_recipients, notify
from models.database import get_db_connection
from models.incident_store import get_incident
from models.network_topology import build_network_topology

_log = logging.getLogger(__name__)

REPORT_SEVERITIES = {"high", "critical"}
STAGES = {"initial", "approved", "rejected"}
_SEVERITY_COLOUR = {"critical": "#c0261a", "high": "#d4570f"}
_EFFECT = {
    "quarantine_device": "device {target} flagged and quarantined",
    "temp_block_account": "account {target} blocked until the restriction expires",
    "restrict_session": "account {target} limited to a read-only session",
    "require_mfa": "step-up MFA required for {target}",
    "notify_analyst": "analysts notified",
    "monitor": "monitoring only, nothing enforced",
}

Section = tuple[str, list[tuple[str, str]]]  # title, rows of (key, value); key "" means a bullet line


def _public_url() -> str:
    return (os.environ.get("TRUSTNET_PUBLIC_URL") or os.environ.get("TRUSTNET_DASHBOARD_URL") or "http://localhost:8080").rstrip("/")


def _action_state(action: dict[str, Any]) -> str:
    status = action["status"]
    if status == "executed":
        who = "automatically by the Response agent" if action.get("mode") == "auto" else f"by a human ({action.get('decided_by')})"
        return f"EXECUTED {who} at {action.get('executed_at')}"
    if status == "pending_approval":
        return f"PENDING HUMAN APPROVAL (expires {action.get('expires_at') or 'n/a'})"
    if status == "rejected":
        return f"REJECTED by {action.get('decided_by')}"
    return status.upper()


def _safeguards(action: dict[str, Any]) -> str:
    checks = action.get("safeguards") or []
    if not checks:
        return "none required"
    passed = [c["name"] for c in checks if c.get("passed")]
    failed = [c["name"] for c in checks if not c.get("passed")]
    return "; ".join(part for part in (f"passed: {', '.join(passed)}" if passed else "", f"NOT passed: {', '.join(failed)}" if failed else "") if part)


def _baseline(user_id: str) -> str:
    connection = get_db_connection()
    try:
        row = connection.execute("SELECT geo, normal_login_hour FROM login_baselines WHERE username = ?", (user_id,)).fetchone()
    finally:
        connection.close()
    if row is None:
        return "no baseline recorded yet"
    try:
        geo = json.loads(row["geo"])
        place = ", ".join(str(geo[k]) for k in ("city", "country") if geo.get(k)) or "unknown"
    except (TypeError, ValueError):
        place = "unknown"
    return f"usual location {place}, usual login hour {float(row['normal_login_hour']):.0f}:00"


def _blast_radius(user_id: str) -> list[str]:
    """Protected assets reachable from the user over active graph edges (the Risk Propagation view)."""
    try:
        topology = build_network_topology()
    except Exception:
        return []
    nodes = {node["id"]: node for node in topology["nodes"]}
    start = f"user:{user_id}"
    if start not in nodes:
        return []
    seen, queue = {start}, [start]
    while queue:
        current = queue.pop(0)
        for edge in topology["edges"]:
            if edge["from"] == current and edge.get("active", True) and edge["to"] not in seen:
                seen.add(edge["to"])
                queue.append(edge["to"])
    assets = {item["asset_id"]: item for item in topology.get("assets", [])}
    reach = sorted((nodes[n] for n in seen if n.startswith("asset:")), key=lambda n: -float(n.get("propagationRisk") or 0))
    lines = []
    for node in reach[:8]:
        meta = assets.get(node["id"].split(":", 1)[1], {})
        lines.append(f"{node['label']} (criticality {meta.get('criticality', 'n/a')}, propagation risk {node.get('propagationRisk', 'n/a')}%)")
    if len(reach) > 8:
        lines.append(f"...and {len(reach) - 8} more")
    return lines


def _timeline(incident: dict[str, Any], limit: int = 10) -> tuple[list[str], list[str]]:
    tools = investigator.EvidenceTools(incident)
    items: list[tuple[str, str]] = []
    ips: list[str] = []
    for attempt in tools.login_attempts(1440):
        ips.append(attempt["ip"])
        outcome = "succeeded" if attempt["success"] else "FAILED"
        items.append((attempt["timestamp"], f"Login {outcome} from {attempt['ip']}" + (f" ({attempt['reason']})" if attempt.get("reason") else "")))
    for event in tools.user_events(1440, 50):
        if event.get("ip_address"):
            ips.append(event["ip_address"])
        flags = f" [{', '.join(event['risk_indicators'][:3])}]" if event.get("risk_indicators") else ""
        items.append((event["timestamp"], f"{event['request_path']} -> HTTP {event['status_code']} from {event.get('ip_address') or 'n/a'}{flags}"))
    items.sort(key=lambda item: item[0], reverse=True)
    return [f"{ts}  {text}" for ts, text in items[:limit]], list(dict.fromkeys(ips))[:4]


def _audit_reference(incident: dict[str, Any], stage: str, subject: str) -> str:
    event = audit("notifier", f"report_{stage}", incident=incident, actor="agent:notifier", payload={"stage": stage, "subject": subject[:200]})
    connection = get_db_connection()
    try:
        row = connection.execute("SELECT sequence, event_hash FROM audit_entries WHERE event_id = ?", (event["id"],)).fetchone()
    finally:
        connection.close()
    return f"audit entry #{row['sequence']}, hash {row['event_hash']}" if row else f"audit event {event['id']}"


def _investigator_section(investigation: dict[str, Any] | None) -> Section:
    if not investigation:
        return "What the Investigator found", [("", "Investigation has not completed yet.")]
    attack = investigation.get("attack_type") or {}
    evidence = attack.get("evidence_summary") or {}
    rows = [
        ("Verdict", f"{investigation['verdict']} (confidence {investigation['confidence']:.2f})"),
        ("Attack type", f"{attack.get('type', 'unknown')} (confidence {attack.get('confidence', 'n/a')})"),
        ("Evidence counts", f"{evidence.get('failed_logins', 0)} failed logins, {evidence.get('successful_logins', 0)} successful logins, "
                            f"{evidence.get('sensitive_events', 0)} sensitive-resource events, {investigation.get('event_count', 0)} linked events"),
    ]
    rows += [("", f"Rule fired: {rule['name']} - {rule.get('detail') or 'no detail'}") for rule in investigation.get("rules", []) if rule.get("fired")][:8]
    if attack.get("recommended_action"):
        rows.append(("Recommended next step", str(attack["recommended_action"])))
    return "What the Investigator found", rows


def _build(incident: dict[str, Any], stage: str, changed: dict[str, Any] | None, audit_ref: str) -> tuple[str, list[Section], list[tuple[str, str]]]:
    label = incident.get("incident_label") or incident["id"]
    severity = str(incident.get("severity", "")).upper()
    actions = response.list_actions(incident["id"])
    pending = [a for a in actions if a["status"] == "pending_approval"]
    header = [
        ("Incident", f"{label} ({incident['id']})"),
        ("Severity", severity),
        ("Fused risk score", f"{incident.get('risk_score')}/100"),
        ("Status", str(incident.get("status"))),
        ("Opened", str(incident.get("created_at"))),
    ]
    sections: list[Section] = []

    if stage in {"approved", "rejected"} and changed:
        verb = "approved and executed" if stage == "approved" else "rejected"
        rows = [
            ("Change", f"{changed['action']} on {changed.get('target')} was {verb} by {changed.get('decided_by')}"),
            ("Effect", _EFFECT.get(changed["action"], "see audit log").format(target=changed.get("target")) if stage == "approved" else "nothing was enforced for this action"),
            ("Action state", _action_state(changed)),
        ]
        sections.append(("What changed", rows))
        sections.append(("Still waiting for a person", [("", f"{a['action']} on {a.get('target')} - expires {a.get('expires_at') or 'n/a'}") for a in pending] or [("", "Nothing is pending.")]))
        sections.append(("Audit reference", [("", audit_ref)]))
        return f"{label}: {severity} incident update - {changed['action']} {stage}", sections, header

    ips: list[str] = []
    timeline, ips = _timeline(incident)
    device = investigator.EvidenceTools(incident).device()
    who = [
        ("User", str(incident.get("user_id"))),
        ("Device", f"{incident.get('device_id') or 'n/a'}" + (f" (trust: {device['trust_status']}, quarantined: {bool(device['quarantined'])})" if device else "")),
        ("Source IP(s)", ", ".join(ips) or "none recorded"),
        ("Baseline", _baseline(str(incident.get("user_id")))),
    ]
    breakdown = incident.get("risk_breakdown") or {}
    for key, value in breakdown.items():
        if isinstance(value, (int, float)):
            who.append(("Deviation", f"{key.replace('_', ' ')}: {round(float(value), 2)}"))
    who += [("", f"Reason: {reason}") for reason in (breakdown.get("reasons") or [])[:5] if isinstance(reason, str)]
    sections.append(("Who and where", who))
    sections.append(_investigator_section(incident.get("investigator_findings")))

    if actions:
        rows = []
        for a in actions:
            effect = _EFFECT.get(a["action"], "").format(target=a.get("target")) if a["status"] == "executed" else ""
            rows.append((a["action"], f"{_action_state(a)}" + (f" - effect: {effect}" if effect else "")))
            rows.append(("", f"Safeguards: {_safeguards(a)}"))
            if a.get("rationale"):
                rows.append(("", f"Why: {a['rationale']}"))
    else:
        rows = [("", "No action was proposed.")]
    sections.append(("What the Response agent did", rows))
    sections.append(("Waiting for a person", [("", f"Approve or reject {a['action']} on {a.get('target')} before {a.get('expires_at') or 'it expires'}") for a in pending]
                     or [("", "Nothing is pending. Please record a verdict (true or false positive) so the agents can learn.")]))
    radius = _blast_radius(str(incident.get("user_id")))
    sections.append(("Blast radius (assets reachable in the Risk Propagation graph)", [("", line) for line in radius] or [("", "No protected assets reachable from this user.")]))
    sections.append(("Last events", [("", line) for line in timeline] or [("", "No recent events recorded.")]))
    sections.append(("Audit reference", [("", audit_ref), ("", "Compare this hash with the tamper-evident audit chain in the dashboard.")]))

    if not actions:
        short = "no action"
    elif pending:
        short = "approval needed"
    elif any(a["status"] == "executed" for a in actions):
        short = "action executed"
    else:
        short = actions[-1]["status"]
    return f"{label}: {severity} incident - agent report ({short})", sections, header


def _render_text(subject: str, header: list[tuple[str, str]], sections: list[Section], link: str) -> str:
    lines = ["TrustNet AI - agentic response report", "=" * 40]
    lines += [f"{k + ':':<18}{v}" for k, v in header]
    for title, rows in sections:
        lines += ["", title.upper(), "-" * len(title)]
        lines += [f"{k + ':':<18}{v}" if k else f"  - {v}" for k, v in rows]
    lines += ["", f"Open the incident: {link}", "",
              "Generated by TrustNet's deterministic agents. This message never contains passwords, tokens or MFA codes."]
    return "\n".join(lines)


def _render_html(severity: str, header: list[tuple[str, str]], sections: list[Section], link: str) -> str:
    e = html.escape
    colour = _SEVERITY_COLOUR.get(severity.lower(), "#555555")
    head = "".join(f"<tr><td style='padding:2px 12px 2px 0;color:#666'>{e(k)}</td><td><b>{e(v)}</b></td></tr>" for k, v in header)
    body = []
    for title, rows in sections:
        items = "".join(
            f"<tr><td style='padding:2px 12px 2px 0;color:#666;vertical-align:top;white-space:nowrap'>{e(k)}</td><td>{e(v)}</td></tr>" if k
            else f"<tr><td colspan='2' style='padding:2px 0'>&bull; {e(v)}</td></tr>"
            for k, v in rows)
        body.append(f"<h3 style='margin:20px 0 6px;font-size:14px;color:#222'>{e(title)}</h3><table style='font-size:13px;border-collapse:collapse'>{items}</table>")
    return (
        "<div style='font-family:Segoe UI,Arial,sans-serif;max-width:680px;margin:auto;color:#222'>"
        f"<div style='background:#0b0d13;color:#f2e8d5;padding:14px 18px'><span style='letter-spacing:.3em'>TRUSTNET AI</span> "
        f"<span style='float:right;background:{colour};color:#fff;padding:2px 10px;font-size:12px'>{e(severity)}</span></div>"
        f"<div style='padding:14px 18px;border:1px solid #ddd;border-top:0'><table style='font-size:13px'>{head}</table>{''.join(body)}"
        f"<p style='margin:24px 0'><a href='{e(link, quote=True)}' style='background:#f5a33b;color:#1a0f02;padding:10px 22px;text-decoration:none;font-weight:600'>Open the incident</a></p>"
        "<p style='font-size:11px;color:#888'>Generated by TrustNet's deterministic agents. This message never contains passwords, tokens or MFA codes.</p>"
        "</div></div>")


def build_report(incident_id: str, stage: str = "initial", *, action_id: str | None = None) -> dict[str, str] | None:
    incident = get_incident(incident_id)
    if incident is None or str(incident.get("severity", "")).lower() not in REPORT_SEVERITIES:
        return None
    changed = response.get_action(action_id) if action_id else None
    subject_hint = f"{incident.get('incident_label') or incident['id']} {stage}"
    audit_ref = _audit_reference(incident, stage, subject_hint)
    subject, sections, header = _build(incident, stage, changed, audit_ref)
    link = f"{_public_url()}/incidents"
    return {"subject": subject, "text": _render_text(subject, header, sections, link),
            "html": _render_html(str(incident.get("severity", "")), header, sections, link)}


def send_report(incident_id: str, stage: str = "initial", *, action_id: str | None = None) -> list[dict[str, Any]]:
    """Best-effort: a mail problem must never interfere with incident handling."""
    if stage not in STAGES:
        raise ValueError(f"unknown report stage {stage!r}")
    try:
        report = build_report(incident_id, stage, action_id=action_id)
        if report is None:
            return []
        created = notify(incident_id, report["subject"], report["text"], recipients=alert_recipients(), html_body=report["html"])
        log_activity(incident_id, "notifier", f"report_{stage}", report["subject"], {"recipients": len(created)})
        return created
    except Exception:
        _log.exception("Could not send %s report for %s", stage, incident_id)
        return []
