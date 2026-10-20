"""Shared helpers for the agent layer: settings, activity feed, and audit-chain logging."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any
from uuid import uuid4

from models.database import get_db_connection
from models.security_events import persist_security_event

AUTONOMY_MODES = {"off", "recommend", "auto_contain"}
_SETTING_DEFAULTS = {
    "autonomy_mode": "recommend",
    "kill_switch": "0",
    "auto_max_per_hour": "3",
    "auto_min_confidence": "0.85",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12].upper()}"


def get_settings() -> dict[str, Any]:
    connection = get_db_connection()
    try:
        rows = {r["key"]: r["value"] for r in connection.execute("SELECT key, value FROM agent_settings")}
    finally:
        connection.close()
    merged = {**_SETTING_DEFAULTS, **rows}
    return {
        "autonomy_mode": merged["autonomy_mode"] if merged["autonomy_mode"] in AUTONOMY_MODES else "recommend",
        "kill_switch": merged["kill_switch"] == "1",
        "auto_max_per_hour": int(merged["auto_max_per_hour"]),
        "auto_min_confidence": float(merged["auto_min_confidence"]),
    }


def update_settings(changes: dict[str, Any]) -> dict[str, Any]:
    """Validate and persist autonomy settings. Raises ValueError on bad input."""
    allowed = {"autonomy_mode", "kill_switch", "auto_max_per_hour", "auto_min_confidence"}
    unknown = set(changes) - allowed
    if unknown:
        raise ValueError(f"Unknown setting(s): {sorted(unknown)}")
    clean: dict[str, str] = {}
    if "autonomy_mode" in changes:
        if changes["autonomy_mode"] not in AUTONOMY_MODES:
            raise ValueError(f"autonomy_mode must be one of {sorted(AUTONOMY_MODES)}")
        clean["autonomy_mode"] = changes["autonomy_mode"]
    if "kill_switch" in changes:
        if not isinstance(changes["kill_switch"], bool):
            raise ValueError("kill_switch must be a boolean")
        clean["kill_switch"] = "1" if changes["kill_switch"] else "0"
    if "auto_max_per_hour" in changes:
        value = changes["auto_max_per_hour"]
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 20:
            raise ValueError("auto_max_per_hour must be an integer between 0 and 20")
        clean["auto_max_per_hour"] = str(value)
    if "auto_min_confidence" in changes:
        value = changes["auto_min_confidence"]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0.5 <= float(value) <= 1.0:
            raise ValueError("auto_min_confidence must be a number between 0.5 and 1.0")
        clean["auto_min_confidence"] = str(float(value))
    connection = get_db_connection()
    try:
        for key, value in clean.items():
            connection.execute(
                "INSERT INTO agent_settings (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                (key, value, now_iso()),
            )
        connection.commit()
    finally:
        connection.close()
    return get_settings()


def log_activity(incident_id: str | None, agent: str, action: str, summary: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    """Append an entry to the agent activity feed shown in the UI."""
    entry = {
        "id": new_id("ACT"), "incident_id": incident_id, "agent": agent, "action": action,
        "summary": summary, "details": details or {}, "created_at": now_iso(),
    }
    connection = get_db_connection()
    try:
        connection.execute(
            "INSERT INTO agent_activity (id, incident_id, agent, action, summary, details, created_at) VALUES (?,?,?,?,?,?,?)",
            (entry["id"], incident_id, agent, action, summary, json.dumps(entry["details"], default=str), entry["created_at"]),
        )
        connection.commit()
    finally:
        connection.close()
    return entry


def list_activity(limit: int = 50, incident_id: str | None = None) -> list[dict[str, Any]]:
    connection = get_db_connection()
    try:
        if incident_id:
            rows = connection.execute(
                "SELECT * FROM agent_activity WHERE incident_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (incident_id, limit),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM agent_activity ORDER BY created_at DESC, rowid DESC LIMIT ?", (limit,)
            ).fetchall()
    finally:
        connection.close()
    result = []
    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item["details"] or "{}")
        result.append(item)
    return result


def audit(agent: str, action: str, *, incident: dict[str, Any] | None, actor: str | None, payload: dict[str, Any]) -> dict[str, Any]:
    """Record an agent or human action in the tamper-evident audit chain."""
    return persist_security_event({
        "user_id": (incident or {}).get("user_id"),
        "request_path": f"/agents/{agent}/{action}",
        "http_method": "POST",
        "event_category": "agent_action",
        "risk_indicators": [f"agent:{agent}", f"action:{action}"],
        "event_payload": {"incident_id": (incident or {}).get("id"), "actor": actor or f"agent:{agent}", **payload},
    })


def reset_agent_state() -> None:
    """Test/demo helper: clear agent tables and restore default settings."""
    connection = get_db_connection()
    try:
        for table in ("agent_activity", "response_actions", "analyst_feedback", "notifications", "agent_settings"):
            connection.execute(f"DELETE FROM {table}")
        for key, value in _SETTING_DEFAULTS.items():
            connection.execute("INSERT INTO agent_settings (key, value, updated_at) VALUES (?,?,?)", (key, value, now_iso()))
        connection.commit()
    finally:
        connection.close()
    from models.account_restrictions import reset_restrictions
    reset_restrictions()
