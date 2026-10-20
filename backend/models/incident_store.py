"""SQLite-backed incident lifecycle store for the single-process demo."""

from datetime import datetime, timedelta, timezone
import json
import os
from typing import Any
from uuid import uuid4

from models.database import get_db_connection


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _decode_incident(row: Any) -> dict[str, Any]:
    incident = dict(row)
    incident["evidence"] = json.loads(incident.pop("evidence") or "[]")
    incident["risk_breakdown"] = json.loads(incident.pop("risk_breakdown") or "{}")
    incident["event_ids"] = json.loads(incident.pop("event_ids") or "[]")
    findings = incident.get("investigator_findings")
    incident["investigator_findings"] = json.loads(findings) if findings else None
    number = incident.get("incident_number")
    incident["incident_label"] = f"TN-{int(number):05d}" if number else None
    return incident


def _link_event_ids(connection: Any, incident_id: str, event_ids: list[str]) -> list[str]:
    normalized_ids = list(dict.fromkeys(event_id for event_id in event_ids if event_id))
    connection.executemany(
        "INSERT OR IGNORE INTO incident_events (incident_id, event_id) VALUES (?, ?)",
        [(incident_id, event_id) for event_id in normalized_ids],
    )
    rows = connection.execute(
        "SELECT event_id FROM incident_events WHERE incident_id = ? ORDER BY rowid", (incident_id,)
    ).fetchall()
    return [row["event_id"] for row in rows]


def _correlation_window_minutes() -> int:
    """Return the configured open-incident correlation window (default: 15 minutes)."""
    raw = os.getenv("TRUSTNET_INCIDENT_CORRELATION_MINUTES", "15")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = 15
    # Keep correlation bounded and avoid accidentally disabling it with bad config.
    return max(1, min(value, 24 * 60))


def maybe_create_risk_incident(
    risk: dict[str, Any], *, evidence: list[str] | None = None, event_ids: list[str] | None = None,
) -> dict[str, Any] | None:
    """Create/update one open high-risk incident per user/device within the correlation window.

    A later burst after the window creates a new incident even if an older incident remains open.
    """
    restrict_threshold = float(risk.get("thresholds", {}).get("restrict", 61.0))
    if risk["score"] < restrict_threshold:
        return None
    user_id = risk["user_id"]
    device_id = risk.get("device_id")
    connection = get_db_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=_correlation_window_minutes())).isoformat()
        existing = connection.execute(
            """SELECT * FROM incidents
               WHERE user_id = ? AND device_id IS ?
                 AND status IN ('open', 'investigating')
                 AND created_at >= ?
               ORDER BY created_at DESC LIMIT 1""",
            (user_id, device_id, cutoff),
        ).fetchone()
        if existing:
            incident = _decode_incident(existing)
            incident["risk_score"] = risk["score"]
            incident["severity"] = risk["level"].title()
            incident["evidence"] = list(dict.fromkeys(incident["evidence"] + (evidence or [])))
            incident["risk_breakdown"] = {**risk["breakdown"], **({"reasons": risk["reasons"]} if risk.get("reasons") else {})}
            incident["updated_at"] = _now()
            incident["event_ids"] = _link_event_ids(connection, incident["id"], event_ids or [])
            connection.execute(
                """UPDATE incidents
                   SET risk_score = ?, severity = ?, evidence = ?, risk_breakdown = ?, event_ids = ?, updated_at = ?
                   WHERE id = ?""",
                (
                    incident["risk_score"], incident["severity"],
                    json.dumps(incident["evidence"]), json.dumps(incident["risk_breakdown"]),
                    json.dumps(incident["event_ids"]), incident["updated_at"], incident["id"],
                ),
            )
            connection.commit()
            return incident

        incident = {
            "id": f"INC-{uuid4().hex[:10].upper()}",
            "title": f"High fused risk for {user_id}",
            "severity": risk["level"].title(),
            "user_id": user_id,
            "device_id": device_id,
            "risk_score": risk["score"],
            "status": "open",
            "created_at": _now(),
            "updated_at": _now(),
            "evidence": list(dict.fromkeys(evidence or [])),
            "response_action": None,
            "risk_breakdown": {**risk["breakdown"], **({"reasons": risk["reasons"]} if risk.get("reasons") else {})},
            "event_ids": [],
        }
        incident["event_ids"] = _link_event_ids(connection, incident["id"], event_ids or [])
        incident["incident_number"] = (
            connection.execute("SELECT COALESCE(MAX(incident_number), 0) + 1 FROM incidents").fetchone()[0]
        )
        connection.execute(
            """INSERT INTO incidents
               (id, incident_number, title, severity, user_id, device_id, risk_score, status, created_at,
                updated_at, response_action, evidence, risk_breakdown, event_ids)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                incident["id"], incident["incident_number"], incident["title"], incident["severity"], incident["user_id"],
                incident["device_id"], incident["risk_score"], incident["status"],
                incident["created_at"], incident["updated_at"], incident["response_action"],
                json.dumps(incident["evidence"]), json.dumps(incident["risk_breakdown"]),
                json.dumps(incident["event_ids"]),
            ),
        )
        connection.commit()
        incident["incident_label"] = f"TN-{incident['incident_number']:05d}"
        return incident
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def list_incidents(*, status: str | None = None) -> list[dict[str, Any]]:
    connection = get_db_connection()
    try:
        if status == "active":
            rows = connection.execute(
                "SELECT * FROM incidents WHERE status IN ('open', 'investigating') ORDER BY created_at DESC"
            ).fetchall()
        elif status is None:
            rows = connection.execute("SELECT * FROM incidents ORDER BY created_at DESC").fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM incidents WHERE status = ? ORDER BY created_at DESC", (status,)
            ).fetchall()
        return [_decode_incident(row) for row in rows]
    finally:
        connection.close()


def get_incident(incident_id: str) -> dict[str, Any] | None:
    connection = get_db_connection()
    try:
        row = connection.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return _decode_incident(row) if row else None
    finally:
        connection.close()


def attach_events_to_active_incidents(
    user_id: str, event_ids: list[str], *, device_id: str | None = None,
) -> list[dict[str, Any]]:
    if not event_ids:
        return []
    connection = get_db_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        if device_id is None:
            rows = connection.execute(
                """SELECT * FROM incidents WHERE user_id = ?
                   AND status IN ('open', 'investigating') AND device_id IS NULL""",
                (user_id,),
            ).fetchall()
        else:
            rows = connection.execute(
                """SELECT * FROM incidents WHERE user_id = ? AND device_id = ?
                   AND status IN ('open', 'investigating')""",
                (user_id, device_id),
            ).fetchall()
        updated = []
        for row in rows:
            incident = _decode_incident(row)
            incident["event_ids"] = _link_event_ids(connection, incident["id"], event_ids)
            incident["updated_at"] = _now()
            connection.execute(
                "UPDATE incidents SET event_ids = ?, updated_at = ? WHERE id = ?",
                (json.dumps(incident["event_ids"]), incident["updated_at"], incident["id"]),
            )
            updated.append(incident)
        connection.commit()
        return updated
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_incident_events(incident_id: str) -> list[dict[str, Any]]:
    connection = get_db_connection()
    try:
        rows = connection.execute(
            """SELECT events.* FROM security_events AS events
               JOIN incident_events AS links ON links.event_id = events.id
               WHERE links.incident_id = ? ORDER BY events.timestamp""",
            (incident_id,),
        ).fetchall()
        events = []
        for row in rows:
            event = dict(row)
            event["risk_indicators"] = json.loads(event["risk_indicators"] or "[]")
            event["event_payload"] = json.loads(event["event_payload"] or "{}")
            events.append(event)
        return events
    finally:
        connection.close()


def transition_incident(incident_id: str, status: str, response_action: str | None = None) -> dict[str, Any] | None:
    if status not in {"open", "investigating", "resolved", "dismissed"}:
        raise ValueError("Unsupported incident status")
    connection = get_db_connection()
    try:
        incident = get_incident(incident_id)
        if incident is None:
            return None
        incident["status"] = status
        incident["updated_at"] = _now()
        if response_action is not None:
            incident["response_action"] = response_action
        connection.execute(
            "UPDATE incidents SET status = ?, updated_at = ?, response_action = ? WHERE id = ?",
            (incident["status"], incident["updated_at"], incident["response_action"], incident_id),
        )
        connection.commit()
        return incident
    finally:
        connection.close()


def reset_incidents() -> None:
    connection = get_db_connection()
    try:
        connection.execute("DELETE FROM incident_events")
        connection.execute("DELETE FROM incidents")
        connection.commit()
    finally:
        connection.close()


def save_investigation(incident_id: str, findings: dict[str, Any]) -> None:
    """Persist Investigator output on the incident without touching its lifecycle status."""
    connection = get_db_connection()
    try:
        connection.execute(
            "UPDATE incidents SET investigator_findings = ?, updated_at = ? WHERE id = ?",
            (json.dumps(findings), _now(), incident_id),
        )
        connection.commit()
    finally:
        connection.close()
