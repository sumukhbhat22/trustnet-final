"""Security event validation and persistence helpers.

These functions validate event payloads and persist them to the SQLite database
for the project's demo deployment. The public interfaces intentionally mirror
existing usage patterns while storing durable records.
"""

from __future__ import annotations

import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from typing import Any
from uuid import uuid4

from models import audit_anchor
from models import database as database_module
from models.database import get_db_connection, initialize_database

_RETENTION_DAYS = 90
_GENESIS_HASH = "0" * 64
_AUDIT_BOOTSTRAPPED_PATH: str | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _audit_hash(event_id: str, timestamp: str, payload_json: str, previous_hash: str) -> str:
    digest_input = _canonical_json({
        "event_id": event_id,
        "timestamp": timestamp,
        "payload_json": payload_json,
        "previous_hash": previous_hash,
    })
    return hashlib.sha256(digest_input.encode("utf-8")).hexdigest()


def _decode_legacy_value(value: str | None, default: Any) -> Any:
    if value is None:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        try:
            return ast.literal_eval(value)
        except (SyntaxError, ValueError):
            return value


def initialize_audit_chain() -> None:
    """Chain pre-existing event rows once before accepting new audited events."""
    global _AUDIT_BOOTSTRAPPED_PATH
    active_path = database_module._DB_PATH
    if _AUDIT_BOOTSTRAPPED_PATH == active_path:
        return
    initialize_database()
    connection = get_db_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        initialized = connection.execute(
            "SELECT value FROM audit_metadata WHERE key = 'chain_initialized'"
        ).fetchone()
        if initialized:
            _AUDIT_BOOTSTRAPPED_PATH = active_path
            connection.commit()
            return

        connection.execute("DROP TRIGGER IF EXISTS audit_entries_no_update")
        connection.execute("DROP TRIGGER IF EXISTS audit_entries_no_delete")
        connection.execute("DELETE FROM audit_entries")
        previous_hash = _GENESIS_HASH
        events = connection.execute(
            "SELECT * FROM security_events ORDER BY timestamp, id"
        ).fetchall()
        for row in events:
            payload = {
                key: row[key]
                for key in (
                    "id", "timestamp", "user_id", "ip_address", "device_fingerprint_hash",
                    "request_path", "http_method", "status_code", "session_id", "event_category",
                )
            }
            payload["risk_indicators"] = _decode_legacy_value(row["risk_indicators"], [])
            payload["event_payload"] = _decode_legacy_value(row["event_payload"], {})
            risk_json = _canonical_json(payload["risk_indicators"])
            event_json = _canonical_json(payload["event_payload"])
            payload_json = _canonical_json(payload)
            event_hash = _audit_hash(payload["id"], payload["timestamp"], payload_json, previous_hash)
            connection.execute(
                "UPDATE security_events SET risk_indicators = ?, event_payload = ? WHERE id = ?",
                (risk_json, event_json, payload["id"]),
            )
            connection.execute(
                """INSERT INTO audit_entries
                   (event_id, timestamp, payload_json, previous_hash, event_hash)
                   VALUES (?, ?, ?, ?, ?)""",
                (payload["id"], payload["timestamp"], payload_json, previous_hash, event_hash),
            )
            previous_hash = event_hash

        connection.execute(
            "INSERT INTO audit_metadata (key, value) VALUES ('chain_initialized', '1')"
        )
        connection.execute(
            """CREATE TRIGGER audit_entries_no_update BEFORE UPDATE ON audit_entries
               BEGIN SELECT RAISE(ABORT, 'audit entries are append-only'); END"""
        )
        connection.execute(
            """CREATE TRIGGER audit_entries_no_delete BEFORE DELETE ON audit_entries
               BEGIN SELECT RAISE(ABORT, 'audit entries are append-only'); END"""
        )
        connection.commit()
        _AUDIT_BOOTSTRAPPED_PATH = active_path
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


SENSITIVE_PATH_PREFIXES = (
    "/api/protected-assets/admin-db", "/api/protected-assets/finance-db", "/api/protected-assets/hr-records",
    "/api/protected-assets/file-export-log", "/api/protected-assets/asset-identity-vault",
    "/api/audit", "/api/baselines/reset",
)


def is_sensitive_path(path: str) -> bool:
    """True when a request path targets a protected resource or a security-control endpoint (F-16)."""
    normalized = (path or "").split("?", 1)[0].rstrip("/")
    return any(normalized == prefix or normalized.startswith(prefix + "/") for prefix in SENSITIVE_PATH_PREFIXES)


def validate_security_event(event: dict[str, Any]) -> dict[str, Any]:
    """Validate a security event before storing it.

    Strict validation keeps the log safe and compact. Passwords, tokens and other
    secrets are never accepted or persisted.
    """
    if not isinstance(event, dict):
        raise ValueError("Event payload must be a dictionary.")

    request_path = str(event.get("request_path") or "").strip()
    http_method = str(event.get("http_method") or "").strip().upper()
    if not request_path or not request_path.startswith("/"):
        raise ValueError("request_path must be a non-empty path beginning with '/'.")
    if http_method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
        raise ValueError("http_method is invalid.")

    user_id = event.get("user_id")
    if user_id is not None and not isinstance(user_id, str):
        raise ValueError("user_id must be a string when provided.")

    ip_address = event.get("ip_address")
    if ip_address is not None and not isinstance(ip_address, str):
        raise ValueError("ip_address must be a string when provided.")

    fingerprint_hash = event.get("device_fingerprint_hash")
    if fingerprint_hash is not None and not isinstance(fingerprint_hash, str):
        raise ValueError("device_fingerprint_hash must be a string when provided.")

    session_id = event.get("session_id")
    if session_id is not None and not isinstance(session_id, str):
        raise ValueError("session_id must be a string when provided.")

    event_category = str(event.get("event_category") or "").strip()
    if not event_category:
        raise ValueError("event_category is required.")

    risk_indicators = event.get("risk_indicators") or []
    if not isinstance(risk_indicators, list):
        raise ValueError("risk_indicators must be a list.")
    risk_indicators = [str(item) for item in risk_indicators if item is not None]

    status_code = event.get("status_code")
    if status_code is not None:
        try:
            status_code = int(status_code)
        except (TypeError, ValueError) as exc:
            raise ValueError("status_code must be an integer when present.") from exc
        if status_code < 100 or status_code > 599:
            raise ValueError("status_code must be between 100 and 599.")

    if is_sensitive_path(request_path) and "sensitive_path" not in risk_indicators:
        risk_indicators = [*risk_indicators, "sensitive_path"]

    result = {
        "id": str(event.get("id") or f"EVT-{uuid4().hex[:12].upper()}"),
        "timestamp": str(event.get("timestamp") or _utc_now()),
        "user_id": user_id,
        "ip_address": ip_address,
        "device_fingerprint_hash": fingerprint_hash,
        "request_path": request_path,
        "http_method": http_method,
        "status_code": status_code,
        "session_id": session_id,
        "event_category": event_category,
        "risk_indicators": risk_indicators,
        "event_payload": event.get("event_payload") or {},
    }
    return {"valid": True, "event": result}


def persist_security_event(event: dict[str, Any]) -> dict[str, Any]:
    """Persist a validated security event and append its integrity record."""
    initialize_audit_chain()
    validate_result = validate_security_event(event)
    payload = validate_result["event"]
    payload_json = _canonical_json(payload)
    connection = get_db_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        previous = connection.execute(
            "SELECT event_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else _GENESIS_HASH
        event_hash = _audit_hash(payload["id"], payload["timestamp"], payload_json, previous_hash)
        connection.execute(
            """
            INSERT INTO security_events (
                id, timestamp, user_id, ip_address, device_fingerprint_hash,
                request_path, http_method, status_code, session_id,
                event_category, risk_indicators, event_payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload["id"],
                payload["timestamp"],
                payload["user_id"],
                payload["ip_address"],
                payload["device_fingerprint_hash"],
                payload["request_path"],
                payload["http_method"],
                payload["status_code"],
                payload["session_id"],
                payload["event_category"],
                _canonical_json(payload["risk_indicators"]),
                _canonical_json(payload["event_payload"]),
            ),
        )
        connection.execute(
            """INSERT INTO audit_entries
               (event_id, timestamp, payload_json, previous_hash, event_hash)
               VALUES (?, ?, ?, ?, ?)""",
            (payload["id"], payload["timestamp"], payload_json, previous_hash, event_hash),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
    _maybe_write_anchor()
    return payload


def list_authentication_events(limit: int = 100) -> list[dict[str, Any]]:
    """List persisted live authentication events without mixing seeded history."""
    connection = get_db_connection()
    try:
        rows = connection.execute(
            """SELECT id, timestamp, ip_address, status_code, event_payload
               FROM security_events
               WHERE event_category = 'authentication_attempt'
               ORDER BY timestamp DESC, id DESC
               LIMIT ?""",
            (max(1, min(limit * 10, 10000)),),
        ).fetchall()
    finally:
        connection.close()

    events = []
    for row in rows:
        payload = _decode_legacy_value(row["event_payload"], {})
        if not isinstance(payload, dict) or payload.get("event_source") not in {"LIVE", "LIVE_TEST"}:
            continue
        if payload.get("event_type") != "authentication_attempt":
            continue
        events.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "event_type": payload["event_type"],
            "outcome": payload.get("outcome"),
            "username": payload.get("username"),
            "source_ip": row["ip_address"],
            "reason": payload.get("reason"),
            "event_source": payload["event_source"],
            "status_code": row["status_code"],
        })
        if len(events) >= limit:
            break
    return events


def verify_audit_chain() -> dict[str, Any]:
    """Verify the append-only event chain and report the first invalid entry."""
    initialize_audit_chain()
    connection = get_db_connection()
    try:
        rows = connection.execute("SELECT * FROM audit_entries ORDER BY sequence").fetchall()
        security_event_count = connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        audited_event_count = connection.execute("SELECT COUNT(*) FROM audit_entries").fetchone()[0]
        untracked_event_count = security_event_count - audited_event_count
        operational_events = {
            row["id"]: dict(row)
            for row in connection.execute("SELECT * FROM security_events").fetchall()
        }
    finally:
        connection.close()

    previous_hash = _GENESIS_HASH
    for checked, row in enumerate(rows, start=1):
        if row["previous_hash"] != previous_hash:
            return {
                "valid": False,
                "checked": checked,
                "broken_event_id": row["event_id"],
                "reason": "previous_hash_mismatch",
            }
        expected_hash = _audit_hash(
            row["event_id"], row["timestamp"], row["payload_json"], previous_hash
        )
        if row["event_hash"] != expected_hash:
            return {
                "valid": False,
                "checked": checked,
                "broken_event_id": row["event_id"],
                "reason": "event_hash_mismatch",
            }
        operational_event = operational_events.get(row["event_id"])
        if operational_event is None:
            return {
                "valid": False,
                "checked": checked,
                "broken_event_id": row["event_id"],
                "reason": "event_missing",
            }
        operational_payload = {
            key: operational_event[key]
            for key in (
                "id", "timestamp", "user_id", "ip_address", "device_fingerprint_hash",
                "request_path", "http_method", "status_code", "session_id", "event_category",
            )
        }
        operational_payload["risk_indicators"] = json.loads(operational_event["risk_indicators"] or "[]")
        operational_payload["event_payload"] = json.loads(operational_event["event_payload"] or "{}")
        if _canonical_json(operational_payload) != row["payload_json"]:
            return {
                "valid": False,
                "checked": checked,
                "broken_event_id": row["event_id"],
                "reason": "event_record_mismatch",
            }
        previous_hash = row["event_hash"]
    if untracked_event_count:
        return {
            "valid": False,
            "checked": len(rows),
            "broken_event_id": None,
            "reason": "untracked_events",
            "untracked_event_count": untracked_event_count,
        }
    return {
        "valid": True,
        "checked": len(rows),
        "untracked_event_count": 0,
        "broken_event_id": None,
        "head_hash": previous_hash,
    }


def list_security_events(*, user_id: str | None = None, ip_address: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    initialize_database()
    query = "SELECT * FROM security_events WHERE 1=1"
    params: list[Any] = []
    if user_id:
        query += " AND user_id = ?"
        params.append(user_id)
    if ip_address:
        query += " AND ip_address = ?"
        params.append(ip_address)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    connection = get_db_connection()
    try:
        rows = connection.execute(query, params).fetchall()
    finally:
        connection.close()
    events = []
    for row in rows:
        event = dict(row)
        event["risk_indicators"] = json.loads(event["risk_indicators"] or "[]")
        event["event_payload"] = json.loads(event["event_payload"] or "{}")
        events.append(event)
    return events


def get_event_retention_days() -> int:
    return int(os.environ.get("TRUSTNET_EVENT_RETENTION_DAYS", str(_RETENTION_DAYS)))


def prune_old_events() -> int:
    """Delete expired events that are NOT covered by the audit chain, returning the number of removed rows.

    Audited events are append-only evidence: deleting one would make verify_audit_chain() report 'event_missing'
    forever, so they are retained regardless of age. (Every event written by persist_security_event is audited,
    so in practice this only removes legacy rows that pre-date the chain.)"""
    days = get_event_retention_days()
    cutoff = (datetime.now(timezone.utc).timestamp() - (days * 86400))
    connection = get_db_connection()
    try:
        cursor = connection.execute(
            "DELETE FROM security_events WHERE datetime(timestamp) < datetime(?, 'unixepoch') "
            "AND id NOT IN (SELECT event_id FROM audit_entries)",
            (cutoff,),
        )
        connection.commit()
        return cursor.rowcount
    finally:
        connection.close()


# ---- external signed checkpoints (models/audit_anchor.py) -------------------------------------
def _anchor_key() -> bytes | None:
    return audit_anchor.key_from_env(os.environ.get("TRUSTNET_AUDIT_CHECKPOINT_KEY"))


def anchor_path() -> str:
    default = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "audit-checkpoints.jsonl")
    return os.environ.get("TRUSTNET_AUDIT_CHECKPOINT_FILE", default)


def _anchor_every() -> int:
    try:
        return int(os.environ.get("TRUSTNET_AUDIT_CHECKPOINT_EVERY", "50"))
    except ValueError:
        return 50


def _maybe_write_anchor() -> None:
    """Write a signed checkpoint every N entries. Never raises: anchoring must not break event intake."""
    key = _anchor_key()
    if key is None:
        return
    try:
        connection = get_db_connection()
        try:
            count = connection.execute("SELECT COUNT(*) FROM audit_entries").fetchone()[0]
            head = connection.execute("SELECT event_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1").fetchone()
        finally:
            connection.close()
        records = audit_anchor.read_checkpoints(anchor_path())
        last = next((r.get("count") for r in reversed(records) if isinstance(r.get("count"), int)), None)
        if head and audit_anchor.should_checkpoint(count, last, _anchor_every()):
            audit_anchor.write_checkpoint(anchor_path(), key, count, head["event_hash"])
    except Exception:  # noqa: BLE001 - deliberate: see docstring
        return


def write_anchor_now() -> dict[str, Any]:
    """Force a checkpoint (used by an admin action and by tests). Raises if the key is not configured."""
    initialize_audit_chain()
    connection = get_db_connection()
    try:
        count = connection.execute("SELECT COUNT(*) FROM audit_entries").fetchone()[0]
        head = connection.execute("SELECT event_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1").fetchone()
    finally:
        connection.close()
    return audit_anchor.write_checkpoint(anchor_path(), _anchor_key(), count, head["event_hash"] if head else _GENESIS_HASH)


def verify_audit_anchors() -> dict[str, Any]:
    initialize_audit_chain()
    connection = get_db_connection()
    try:
        total = connection.execute("SELECT COUNT(*) FROM audit_entries").fetchone()[0]

        def head_at(n: int) -> str | None:
            row = connection.execute("SELECT event_hash FROM audit_entries ORDER BY sequence LIMIT 1 OFFSET ?", (n - 1,)).fetchone()
            return row["event_hash"] if row else None

        return audit_anchor.verify_checkpoints(anchor_path(), _anchor_key(), head_at, total)
    finally:
        connection.close()
