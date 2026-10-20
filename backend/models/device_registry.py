"""SQLite-backed device trust registry used by the demo backend."""

from datetime import datetime, timezone
import hashlib
from typing import Any

from models import database as database_module
from models.database import get_db_connection, initialize_database
from models.login_detector import hash_fingerprint

_INITIALIZED_DATABASE_PATH: str | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_database() -> None:
    global _INITIALIZED_DATABASE_PATH
    active_path = database_module._DB_PATH
    if _INITIALIZED_DATABASE_PATH != active_path:
        initialize_database()
        _INITIALIZED_DATABASE_PATH = active_path


def _label(fingerprint: dict[str, Any]) -> str:
    platform = str(fingerprint.get("platform") or "Unknown platform")
    user_agent = str(fingerprint.get("userAgent") or "")
    browser = "Browser"
    for marker, name in (("Edg/", "Edge"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"), ("Safari/", "Safari")):
        if marker in user_agent:
            browser = name
            break
    return f"{browser} on {platform}"


def register_login_device(user_id: str, fingerprint: dict[str, Any], *, first_login: bool = False) -> dict[str, Any]:
    """Record a fingerprint on login without automatically trusting new devices."""
    now = _utc_now()
    fingerprint_hash = hash_fingerprint(fingerprint)
    device_id = "dev-" + hashlib.sha256(f"{user_id}:{fingerprint_hash}".encode()).hexdigest()[:16]
    _ensure_database()
    connection = get_db_connection()
    try:
        connection.execute(
            """INSERT INTO devices
               (device_id, user_id, fingerprint_hash, first_seen, last_seen, trust_status,
                label, last_login_first_for_user, quarantined)
               VALUES (?, ?, ?, ?, ?, 'unknown', ?, ?, 0)
               ON CONFLICT(device_id) DO UPDATE SET
                 last_seen = excluded.last_seen,
                 label = excluded.label,
                 last_login_first_for_user = excluded.last_login_first_for_user""",
            (device_id, user_id, fingerprint_hash, now, now, _label(fingerprint), int(first_login)),
        )
        connection.commit()
        row = connection.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
        return _decode_device(row)
    finally:
        connection.close()


def _decode_device(row: Any) -> dict[str, Any]:
    device = dict(row)
    device["last_login_first_for_user"] = bool(device["last_login_first_for_user"])
    device["quarantined"] = bool(device["quarantined"])
    return device


def list_devices(user_id: str | None = None) -> list[dict[str, Any]]:
    _ensure_database()
    connection = get_db_connection()
    try:
        if user_id is None:
            rows = connection.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM devices WHERE user_id = ? ORDER BY last_seen DESC", (user_id,)
            ).fetchall()
        return [_decode_device(row) for row in rows]
    finally:
        connection.close()


def get_device(device_id: str) -> dict[str, Any] | None:
    _ensure_database()
    connection = get_db_connection()
    try:
        row = connection.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
        return _decode_device(row) if row else None
    finally:
        connection.close()


def set_device_status(device_id: str, trust_status: str, *, quarantined: bool | None = None) -> dict[str, Any] | None:
    if trust_status not in {"trusted", "unknown", "flagged", "revoked"}:
        raise ValueError("trust_status must be trusted, unknown, flagged, or revoked")
    device = get_device(device_id)
    if device is None:
        return None
    is_quarantined = (trust_status == "revoked") if quarantined is None and trust_status == "revoked" else (device["quarantined"] if quarantined is None else quarantined)
    connection = get_db_connection()
    try:
        connection.execute(
            "UPDATE devices SET trust_status = ?, quarantined = ? WHERE device_id = ?",
            (trust_status, int(is_quarantined), device_id),
        )
        connection.commit()
        return get_device(device_id)
    finally:
        connection.close()


def reset_devices() -> None:
    _ensure_database()
    connection = get_db_connection()
    try:
        connection.execute("DELETE FROM devices")
        connection.commit()
    finally:
        connection.close()


def reset_user_devices(user_id: str) -> None:
    _ensure_database()
    connection = get_db_connection()
    try:
        connection.execute("DELETE FROM devices WHERE user_id = ?", (user_id,))
        connection.commit()
    finally:
        connection.close()
