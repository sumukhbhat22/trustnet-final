"""Expiring, human-approved account restrictions (temporary blocks), enforced in the backend.

A restriction is never permanent: it always has an expiry (default 30 min, hard cap 24 h) and can be released early
by an authorized human. Administrator and analyst accounts can never be restricted by this mechanism.
Expiry is enforced at read time (no background job needed, so it survives restarts) and recorded in the audit chain.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
import sqlite3
from typing import Any
from uuid import uuid4

from models.database import get_db_connection
from models.security_events import persist_security_event

DEFAULT_MINUTES = int(os.getenv("TRUSTNET_TEMP_BLOCK_MINUTES", "30"))
MAX_MINUTES = 24 * 60
PROTECTED_ROLES = {"admin", "analyst"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _audit(action: str, restriction: dict[str, Any], actor: str, extra: dict[str, Any] | None = None) -> None:
    persist_security_event({
        "user_id": restriction["user_id"],
        "request_path": f"/accounts/restriction/{action}",
        "http_method": "POST",
        "event_category": "agent_action",
        "risk_indicators": ["account_restriction", f"action:{action}"],
        "event_payload": {"restriction_id": restriction["id"], "incident_id": restriction.get("incident_id"),
                          "actor": actor, "expires_at": restriction["expires_at"], "mode": restriction.get("mode", "block"), **(extra or {})},
    })


def _ensure_table() -> None:
    connection = get_db_connection()
    try:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS account_restrictions (
                id TEXT PRIMARY KEY, user_id TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL,
                incident_id TEXT, action_id TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL, released_by TEXT, released_at TEXT, reason TEXT,
                mode TEXT NOT NULL DEFAULT 'block' CHECK (mode IN ('block','read_only')))""")
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(account_restrictions)")}
        if "mode" not in columns:
            connection.execute("ALTER TABLE account_restrictions ADD COLUMN mode TEXT NOT NULL DEFAULT 'block'")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_restrictions_user ON account_restrictions(user_id, status)")
        # Legacy databases may hold duplicate active rows (created before this index existed): keep the newest.
        connection.execute(
            "UPDATE account_restrictions SET status = 'released', released_by = 'system:dedupe', released_at = ? "
            "WHERE status = 'active' AND rowid NOT IN "
            "(SELECT MAX(rowid) FROM account_restrictions WHERE status = 'active' GROUP BY user_id)",
            (datetime.now(timezone.utc).isoformat(),))
        # Database-level guarantee: at most one ACTIVE restriction per account, even under concurrent creation.
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_restrictions_one_active ON account_restrictions(user_id) WHERE status = 'active'")
        connection.commit()
    finally:
        connection.close()


def _row(row: Any) -> dict[str, Any]:
    return dict(row)


def expire_due() -> int:
    """Mark active restrictions past their expiry as expired and audit each. Returns how many expired."""
    _ensure_table()
    now = _now().isoformat()
    connection = get_db_connection()
    try:
        due = [_row(r) for r in connection.execute(
            "SELECT * FROM account_restrictions WHERE status = 'active' AND expires_at <= ?", (now,)).fetchall()]
        done = []
        for item in due:
            cur = connection.execute(
                "UPDATE account_restrictions SET status = 'expired', released_at = ? WHERE id = ? AND status = 'active'",
                (now, item["id"]))
            if cur.rowcount == 1:
                done.append(item)
        connection.commit()
    finally:
        connection.close()
    for item in done:
        _audit("expired", item, "system:expiry")
    return len(done)


def active_restriction(user_id: str) -> dict[str, Any] | None:
    """Return the user's currently enforced restriction, or None. Expired ones are never returned."""
    _ensure_table()
    expire_due()
    connection = get_db_connection()
    try:
        row = connection.execute(
            "SELECT * FROM account_restrictions WHERE user_id = ? AND status = 'active' AND expires_at > ? "
            "ORDER BY expires_at DESC LIMIT 1", (user_id, _now().isoformat())).fetchone()
    finally:
        connection.close()
    return _row(row) if row else None


def create_restriction(user: dict[str, Any], *, minutes: int | None, incident_id: str | None, action_id: str | None,
                       actor: str, reason: str = "", mode: str = "block") -> dict[str, Any]:
    """Create an expiring restriction. mode is block or read_only."""
    if user["role"] in PROTECTED_ROLES:
        raise ValueError("Administrator and analyst accounts cannot be restricted automatically.")
    if mode not in {"block", "read_only"}:
        raise ValueError("Restriction mode must be block or read_only.")
    minutes = DEFAULT_MINUTES if minutes is None else minutes
    if isinstance(minutes, bool) or not isinstance(minutes, int) or not 1 <= minutes <= MAX_MINUTES:
        raise ValueError(f"Block duration must be 1-{MAX_MINUTES} minutes; permanent blocks are not supported.")
    _ensure_table()
    existing = active_restriction(user["id"])
    if existing:
        return existing  # idempotent: one active restriction per account
    now = _now()
    item = {"id": f"RST-{uuid4().hex[:12].upper()}", "user_id": user["id"], "kind": "temp_block", "status": "active",
            "incident_id": incident_id, "action_id": action_id, "created_by": actor, "created_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=minutes)).isoformat(), "released_by": None, "released_at": None,
            "reason": reason[:300], "mode": mode}
    connection = get_db_connection()
    try:
        connection.execute(
            "INSERT INTO account_restrictions (id,user_id,kind,status,incident_id,action_id,created_by,created_at,expires_at,"
            "released_by,released_at,reason,mode) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            tuple(item[k] for k in ("id", "user_id", "kind", "status", "incident_id", "action_id", "created_by",
                                    "created_at", "expires_at", "released_by", "released_at", "reason", "mode")))
        connection.commit()
    except sqlite3.IntegrityError:
        # A concurrent request created the active restriction first: return that one (idempotent).
        connection.rollback()
        winner = active_restriction(user["id"])
        if winner:
            return winner
        raise
    finally:
        connection.close()
    _audit("enforced", item, actor, {"minutes": minutes})
    return item


def release_restriction(restriction_id: str, actor: str) -> dict[str, Any] | None:
    """Early release by a human. Returns the updated record, or None if it is not active."""
    _ensure_table()
    now = _now().isoformat()
    connection = get_db_connection()
    try:
        cur = connection.execute(
            "UPDATE account_restrictions SET status = 'released', released_by = ?, released_at = ? "
            "WHERE id = ? AND status = 'active'", (actor, now, restriction_id))
        connection.commit()
        if cur.rowcount != 1:
            return None
        row = connection.execute("SELECT * FROM account_restrictions WHERE id = ?", (restriction_id,)).fetchone()
    finally:
        connection.close()
    item = _row(row)
    _audit("released", item, actor)
    return item


def list_restrictions(user_id: str | None = None) -> list[dict[str, Any]]:
    _ensure_table()
    expire_due()
    connection = get_db_connection()
    try:
        if user_id:
            rows = connection.execute("SELECT * FROM account_restrictions WHERE user_id = ? ORDER BY created_at DESC", (user_id,)).fetchall()
        else:
            rows = connection.execute("SELECT * FROM account_restrictions ORDER BY created_at DESC LIMIT 200").fetchall()
    finally:
        connection.close()
    return [_row(r) for r in rows]


def reset_restrictions() -> None:
    _ensure_table()
    connection = get_db_connection()
    try:
        connection.execute("DELETE FROM account_restrictions")
        connection.commit()
    finally:
        connection.close()
