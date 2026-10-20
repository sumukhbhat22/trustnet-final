"""F-32: incident PDF report. Data assembly is separate from rendering so each is testable."""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any
from xml.sax.saxutils import escape

NA = "Not available"
_MAX_TEXT = 600


def _txt(value: Any, limit: int = _MAX_TEXT) -> str:
    """Render any value safely as text: missing -> N/A, markup-escaped, length-capped."""
    if value is None or value == "" or value == [] or value == {}:
        return NA
    text = str(value)
    if len(text) > limit:
        text = text[:limit] + "...(truncated)"
    return escape(text)


def build_report_data(incident_id: str) -> dict[str, Any] | None:
    """Collect everything known about an incident from persisted state. Never raises on missing parts."""
    from models.incident_store import get_incident, get_incident_events
    incident = get_incident(incident_id)
    if incident is None:
        return None
    agent: dict[str, Any] = {}
    try:
        from agents import orchestrator
        agent = orchestrator.incident_agent_view(incident_id) or {}
    except Exception:  # report must still render if agent tables are unavailable
        agent = {}
    user: dict[str, Any] = {}
    device: dict[str, Any] = {}
    try:
        from models.security_auth import get_user_by_id
        user = get_user_by_id(incident.get("user_id")) or {}
    except Exception:
        pass
    try:
        if incident.get("device_id"):
            from models.device_registry import get_device
            device = get_device(incident["device_id"]) or {}
    except Exception:
        pass
    events = get_incident_events(incident_id)
    assets = sorted({str(e["event_payload"].get("asset_id")) for e in events
                     if isinstance(e.get("event_payload"), dict) and e["event_payload"].get("asset_id")})
    return {"incident": incident, "user": user, "device": device, "assets": assets,
            "events": events, "agent": agent,
            "generated_at": datetime.now(timezone.utc).isoformat()}


def render_pdf(data: dict[str, Any]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    body = styles["BodyText"]
    incident = data.get("incident") or {}
    agent = data.get("agent") or {}
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=15 * mm, bottomMargin=15 * mm,
                            title=f"TrustNet incident {incident.get('id', '')}")
    story: list[Any] = []

    def heading(text: str) -> None:
        story.append(Spacer(1, 6))
        story.append(Paragraph(escape(text), styles["Heading2"]))

    def table(rows: list[list[Any]], widths: list[float] | None = None, header: bool = False) -> None:
        cells = [[Paragraph(_txt(c, 300), body) for c in row] for row in rows]
        t = Table(cells, colWidths=widths, repeatRows=1 if header else 0)
        style = [("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]
        if header:
            style.append(("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey))
        t.setStyle(TableStyle(style))
        story.append(t)

    story.append(Paragraph("TrustNet AI - Incident Report", styles["Title"]))
    story.append(Paragraph("Data in this report comes from the TrustNet database. "
                           "Demo/synthetic events are labelled in their source field.", body))
    heading("Summary")
    table([
        ["Incident ID", incident.get("id")], ["Label", incident.get("incident_label")],
        ["Title", incident.get("title")], ["Severity", incident.get("severity")],
        ["Status", incident.get("status")], ["Risk score", incident.get("risk_score")],
        ["Created", incident.get("created_at")], ["Last updated", incident.get("updated_at")],
        ["Response action recorded", incident.get("response_action")],
        ["Report generated", data.get("generated_at")],
    ], [45 * mm, 135 * mm])

    heading("Affected user, device and assets")
    user, device = data.get("user") or {}, data.get("device") or {}
    table([
        ["User", user.get("email") or incident.get("user_id")], ["User role", user.get("role")],
        ["Device", device.get("label") or incident.get("device_id")],
        ["Device trust status", device.get("trust_status")],
        ["Assets touched", ", ".join(data.get("assets") or [])],
    ], [45 * mm, 135 * mm])

    heading("Risk reasons")
    breakdown = incident.get("risk_breakdown") or {}
    rows = [["Signal", "Detail"]]
    items = (breakdown.get("breakdown") or breakdown).items() if isinstance(breakdown, dict) else []
    for index, reason in enumerate((breakdown.get("reasons") or []) if isinstance(breakdown, dict) else []):
        rows.append([f"Reason {index + 1}", reason])
    for name, info in items:
        if name == "reasons":
            continue
        rows.append([name, info if not isinstance(info, dict) else
                     ", ".join(f"{k}={v}" for k, v in info.items() if v is not None)])
    table(rows if len(rows) > 1 else [["Signal", "Detail"], [NA, NA]], [45 * mm, 135 * mm], header=True)

    heading("Evidence")
    evidence = incident.get("evidence") or []
    table([["#", "Evidence"]] + [[i + 1, e] for i, e in enumerate(evidence)] if evidence
          else [["#", "Evidence"], [NA, NA]], [12 * mm, 168 * mm], header=True)

    heading("Linked events")
    events = data.get("events") or []
    table([["Time", "Category", "Path", "Status"]] + [
        [e.get("timestamp"), e.get("event_category"), e.get("request_path"), e.get("status_code")]
        for e in events[:100]] if events else [["Time", "Category", "Path", "Status"], [NA, NA, NA, NA]],
        [45 * mm, 35 * mm, 75 * mm, 25 * mm], header=True)

    heading("Investigator findings")
    findings = agent.get("investigation") or incident.get("investigator_findings")
    if isinstance(findings, dict) and findings:
        table([[k, v] for k, v in findings.items()], [45 * mm, 135 * mm])
    else:
        story.append(Paragraph(NA, body))

    heading("Response actions and approvals")
    responses = agent.get("responses") or []
    table([["Action", "Mode", "Status", "Decided by", "Executed at"]] + [
        [r.get("action"), r.get("mode"), r.get("status"), r.get("decided_by"), r.get("executed_at")]
        for r in responses] if responses else [["Action", "Mode", "Status", "Decided by", "Executed at"],
                                              [NA] * 5], [35 * mm, 28 * mm, 35 * mm, 42 * mm, 40 * mm], header=True)

    heading("Analyst verdicts")
    feedback = agent.get("feedback") or []
    table([["Verdict", "Notes", "Time"]] + [
        [f.get("verdict"), f.get("notes"), f.get("created_at")] for f in feedback]
        if feedback else [["Verdict", "Notes", "Time"], [NA, NA, NA]], [35 * mm, 100 * mm, 45 * mm], header=True)

    heading("Agent activity")
    activity = list(reversed(agent.get("activity") or []))
    table([["Time", "Agent", "Action", "Summary"]] + [
        [a.get("created_at"), a.get("agent"), a.get("action"), a.get("summary")] for a in activity[:100]]
        if activity else [["Time", "Agent", "Action", "Summary"], [NA] * 4],
        [38 * mm, 22 * mm, 32 * mm, 88 * mm], header=True)

    doc.build(story)
    return buffer.getvalue()


def generate_incident_pdf(incident_id: str) -> bytes | None:
    data = build_report_data(incident_id)
    return None if data is None else render_pdf(data)
