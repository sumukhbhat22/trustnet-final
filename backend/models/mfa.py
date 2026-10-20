"""Database-backed step-up MFA challenges for the TrustNet demonstration.

Codes are stored only as salted scrypt digests, expire after five minutes, and are
single-use. The demo intentionally uses an explicit development code transport;
production delivery must be configured by the deployment owner.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import secrets
from typing import Any

from fastapi import HTTPException
from models.database import get_db_connection

CHALLENGE_SECONDS = 300
REQUIRED_SECONDS = 30 * 60
MAX_ATTEMPTS = 5


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_table() -> None:
    conn = get_db_connection()
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS mfa_state (
            user_id TEXT NOT NULL, device_id TEXT NOT NULL, required_until TEXT,
            verified_at TEXT, attempts INTEGER NOT NULL DEFAULT 0,
            challenge_hash TEXT, challenge_salt TEXT, challenge_expires_at TEXT,
            locked_until TEXT, updated_at TEXT NOT NULL,
            PRIMARY KEY(user_id, device_id))""")
        conn.commit()
    finally:
        conn.close()


def _digest(code: str, salt: bytes) -> bytes:
    return hashlib.scrypt(code.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)


def require_mfa_for_user(user_id: str, device_id: str = "account") -> None:
    _ensure_table()
    now = _now()
    conn = get_db_connection()
    try:
        conn.execute("""INSERT INTO mfa_state(user_id,device_id,required_until,verified_at,attempts,updated_at)
            VALUES(?,?,?,NULL,0,?) ON CONFLICT(user_id,device_id) DO UPDATE SET
            required_until=excluded.required_until, verified_at=NULL, attempts=0,
            challenge_hash=NULL, challenge_salt=NULL, challenge_expires_at=NULL, locked_until=NULL,
            updated_at=excluded.updated_at""",
            (user_id, device_id, (now + timedelta(seconds=REQUIRED_SECONDS)).isoformat(), now.isoformat()))
        conn.commit()
    finally:
        conn.close()


def enforce_mfa(user_id: str, device_id: str = "account") -> None:
    _ensure_table()
    now = _now().isoformat()
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM mfa_state WHERE user_id=? AND device_id=?", (user_id, device_id)).fetchone()
        # Account-wide requirements apply to every device unless a device-specific
        # row exists. Tokens without an explicit requirement are unaffected.
        if row is None and device_id != "account":
            row = conn.execute("SELECT * FROM mfa_state WHERE user_id=? AND device_id='account'", (user_id,)).fetchone()
        if row is None:
            return
        if row["locked_until"] and row["locked_until"] > now:
            raise HTTPException(status_code=403, detail={"code": "MFA_LOCKED", "locked_until": row["locked_until"]})
        if row["required_until"] and row["required_until"] > now and not row["verified_at"]:
            raise HTTPException(status_code=403, detail={"code": "MFA_REQUIRED", "message": "Step-up authentication is required."})
    finally:
        conn.close()


def create_mfa_challenge(user_id: str, device_id: str = "account") -> dict[str, Any]:
    _ensure_table()
    now = _now()
    code = f"{secrets.randbelow(1_000_000):06d}"
    salt = secrets.token_bytes(16)
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT required_until,locked_until FROM mfa_state WHERE user_id=? AND device_id=?", (user_id, device_id)).fetchone()
        if row and row["locked_until"] and row["locked_until"] > now.isoformat():
            raise ValueError("MFA is temporarily locked after repeated failed attempts")
        conn.execute("""INSERT INTO mfa_state(user_id,device_id,required_until,verified_at,attempts,challenge_hash,challenge_salt,challenge_expires_at,locked_until,updated_at)
            VALUES(?,?,?,NULL,0,?,?,?,?,?) ON CONFLICT(user_id,device_id) DO UPDATE SET
            verified_at=NULL,attempts=0,challenge_hash=excluded.challenge_hash,challenge_salt=excluded.challenge_salt,
            challenge_expires_at=excluded.challenge_expires_at,locked_until=NULL,updated_at=excluded.updated_at""",
            (user_id, device_id, (now + timedelta(seconds=REQUIRED_SECONDS)).isoformat(), _digest(code, salt).hex(), salt.hex(), (now + timedelta(seconds=CHALLENGE_SECONDS)).isoformat(), None, now.isoformat()))
        conn.commit()
    finally:
        conn.close()
    # Code is returned only to the caller so a configured notifier can deliver it.
    # The API exposes it solely in DEMO_MODE + non-production for local testing.
    return {"code": code, "expires_at": (now + timedelta(seconds=CHALLENGE_SECONDS)).isoformat()}


def verify_mfa_challenge(user_id: str, device_id: str, code: str) -> dict[str, str]:
    _ensure_table()
    now = _now()
    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM mfa_state WHERE user_id=? AND device_id=?", (user_id, device_id)).fetchone()
        if row is None or not row["challenge_hash"] or not row["challenge_salt"]:
            raise ValueError("No active MFA challenge. Request a new code.")
        if row["locked_until"] and row["locked_until"] > now.isoformat():
            raise ValueError("MFA is temporarily locked after repeated failed attempts")
        if not row["challenge_expires_at"] or row["challenge_expires_at"] <= now.isoformat():
            conn.execute("UPDATE mfa_state SET challenge_hash=NULL,challenge_salt=NULL,challenge_expires_at=NULL,updated_at=? WHERE user_id=? AND device_id=?", (now.isoformat(), user_id, device_id))
            conn.commit()
            raise ValueError("MFA code expired. Request a new code.")
        expected = bytes.fromhex(row["challenge_hash"])
        actual = _digest(code, bytes.fromhex(row["challenge_salt"]))
        if not hmac.compare_digest(expected, actual):
            attempts = int(row["attempts"] or 0) + 1
            locked_until = (now + timedelta(minutes=15)).isoformat() if attempts > MAX_ATTEMPTS else None
            conn.execute("UPDATE mfa_state SET attempts=?,locked_until=?,updated_at=? WHERE user_id=? AND device_id=?", (attempts, locked_until, now.isoformat(), user_id, device_id))
            conn.commit()
            raise ValueError("Too many failed attempts; MFA is locked for 15 minutes" if locked_until else "Invalid MFA code")
        verified = now.isoformat()
        conn.execute("UPDATE mfa_state SET verified_at=?,challenge_hash=NULL,challenge_salt=NULL,challenge_expires_at=NULL,attempts=0,updated_at=? WHERE user_id=? AND device_id=?", (verified, verified, user_id, device_id))
        conn.commit()
        return {"verified_at": verified}
    finally:
        conn.close()


def mark_mfa_verified(user_id: str, device_id: str = "account") -> str:
    """Record a successful second factor (e.g. TOTP) against an existing step-up requirement."""
    _ensure_table()
    verified = _now().isoformat()
    conn = get_db_connection()
    try:
        conn.execute("""UPDATE mfa_state SET verified_at=?,challenge_hash=NULL,challenge_salt=NULL,challenge_expires_at=NULL,
            attempts=0,locked_until=NULL,updated_at=? WHERE user_id=? AND device_id=?""", (verified, verified, user_id, device_id))
        conn.commit()
    finally:
        conn.close()
    return verified


def clear_mfa_state(user_id: str | None = None) -> None:
    _ensure_table()
    conn = get_db_connection()
    try:
        if user_id:
            conn.execute("DELETE FROM mfa_state WHERE user_id=?", (user_id,))
        else:
            conn.execute("DELETE FROM mfa_state")
        conn.commit()
    finally:
        conn.close()
