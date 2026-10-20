"""Database-backed TOTP enrolment and verification (wraps the pure functions in models/totp.py).

- Secrets are encrypted at rest with Fernet (key derived from TRUSTNET_TOTP_KEY, >= 32 characters).
  If the key is not set, enrolment is refused (fail closed), never stored in the clear.
- A used code's time-step counter is stored, so a code cannot be replayed.
- Five wrong codes lock TOTP for the user for 15 minutes (same policy as email-code MFA).
- Backup codes are stored only as salted hashes and are single use.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone

from models import totp
from models.database import get_db_connection

MAX_ATTEMPTS = 5
LOCK_MINUTES = 15


class TotpError(Exception):
    def __init__(self, code: str, message: str, status: int = 403):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def _key() -> bytes:
    try:
        return totp.encryption_key_from_env(os.environ.get("TRUSTNET_TOTP_KEY"))
    except ValueError as error:
        raise TotpError("TOTP_NOT_CONFIGURED", str(error), 503) from error


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_table() -> None:
    conn = get_db_connection()
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS totp_credentials (
            user_id TEXT PRIMARY KEY, secret_enc TEXT NOT NULL, confirmed_at TEXT,
            last_counter INTEGER, backup_json TEXT NOT NULL DEFAULT '[]',
            failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until TEXT, updated_at TEXT NOT NULL)""")
        conn.commit()
    finally:
        conn.close()


def _row(user_id: str):
    conn = get_db_connection()
    try:
        return conn.execute("SELECT * FROM totp_credentials WHERE user_id=?", (user_id,)).fetchone()
    finally:
        conn.close()


def status(user_id: str) -> dict:
    _ensure_table()
    row = _row(user_id)
    return {
        "enrolled": bool(row and row["confirmed_at"]),
        "pending_confirmation": bool(row and not row["confirmed_at"]),
        "backup_codes_remaining": len(json.loads(row["backup_json"])) if row and row["confirmed_at"] else 0,
    }


def begin_enrolment(user_id: str, account_label: str) -> dict:
    """Create (or replace an unconfirmed) secret. Refuses to overwrite a confirmed credential."""
    key = _key()
    _ensure_table()
    row = _row(user_id)
    if row and row["confirmed_at"]:
        raise TotpError("TOTP_ALREADY_ENROLLED", "TOTP is already enrolled for this account", 409)
    secret = totp.generate_secret()
    conn = get_db_connection()
    try:
        conn.execute("""INSERT INTO totp_credentials(user_id,secret_enc,confirmed_at,last_counter,backup_json,failed_attempts,locked_until,updated_at)
            VALUES(?,?,NULL,NULL,'[]',0,NULL,?) ON CONFLICT(user_id) DO UPDATE SET secret_enc=excluded.secret_enc,
            confirmed_at=NULL,last_counter=NULL,backup_json='[]',failed_attempts=0,locked_until=NULL,updated_at=excluded.updated_at""",
                     (user_id, totp.encrypt_secret(secret, key), _now().isoformat()))
        conn.commit()
    finally:
        conn.close()
    # The secret is shown to its owner once, for the authenticator app. It is not logged or audited.
    return {"secret": secret, "otpauth_uri": totp.provisioning_uri(secret, account_label)}


def _check_lock(row) -> None:
    if row["locked_until"] and row["locked_until"] > _now().isoformat():
        raise TotpError("TOTP_LOCKED", "Too many failed attempts; TOTP is locked for 15 minutes", 423)


def _fail(user_id: str, row) -> None:
    attempts = int(row["failed_attempts"] or 0) + 1
    locked = (_now() + timedelta(minutes=LOCK_MINUTES)).isoformat() if attempts >= MAX_ATTEMPTS else None
    conn = get_db_connection()
    try:
        conn.execute("UPDATE totp_credentials SET failed_attempts=?, locked_until=?, updated_at=? WHERE user_id=?",
                     (0 if locked else attempts, locked, _now().isoformat(), user_id))
        conn.commit()
    finally:
        conn.close()
    if locked:
        raise TotpError("TOTP_LOCKED", "Too many failed attempts; TOTP is locked for 15 minutes", 423)
    raise TotpError("TOTP_INVALID", "Invalid code")


def _check_code(user_id: str, row, code: str, timestamp: float | None) -> int:
    secret = totp.decrypt_secret(row["secret_enc"], _key())
    if secret is None:
        raise TotpError("TOTP_UNREADABLE", "Stored TOTP secret cannot be decrypted with the configured key", 503)
    ok, counter = totp.verify(secret, code, timestamp if timestamp is not None else time.time(), row["last_counter"])
    if not ok:
        _fail(user_id, row)
    return int(counter)


def confirm_enrolment(user_id: str, code: str, timestamp: float | None = None) -> dict:
    """Confirm with a first valid code; returns the plain backup codes exactly once."""
    _ensure_table()
    row = _row(user_id)
    if row is None or row["confirmed_at"]:
        raise TotpError("TOTP_NOT_PENDING", "No pending TOTP enrolment", 409)
    _check_lock(row)
    counter = _check_code(user_id, row, code, timestamp)
    plain, records = totp.generate_backup_codes()
    conn = get_db_connection()
    try:
        conn.execute("UPDATE totp_credentials SET confirmed_at=?, last_counter=?, backup_json=?, failed_attempts=0, updated_at=? WHERE user_id=?",
                     (_now().isoformat(), counter, json.dumps(records), _now().isoformat(), user_id))
        conn.commit()
    finally:
        conn.close()
    return {"backup_codes": plain}


def verify_second_factor(user_id: str, code: str, timestamp: float | None = None) -> dict:
    """Verify a TOTP code or a backup code. Returns {"method": "totp"|"backup", "backup_codes_remaining": n}."""
    _ensure_table()
    row = _row(user_id)
    if row is None or not row["confirmed_at"]:
        raise TotpError("TOTP_NOT_ENROLLED", "TOTP is not enrolled for this account", 409)
    _check_lock(row)
    cleaned = str(code or "").strip()
    if len(cleaned.replace(" ", "")) == totp.DIGITS and cleaned.replace(" ", "").isdigit():
        counter = _check_code(user_id, row, cleaned, timestamp)
        conn = get_db_connection()
        try:
            conn.execute("UPDATE totp_credentials SET last_counter=?, failed_attempts=0, updated_at=? WHERE user_id=?", (counter, _now().isoformat(), user_id))
            conn.commit()
        finally:
            conn.close()
        return {"method": "totp", "backup_codes_remaining": len(json.loads(row["backup_json"]))}
    remaining = totp.consume_backup_code(json.loads(row["backup_json"]), cleaned)
    if remaining is None:
        _fail(user_id, row)
    conn = get_db_connection()
    try:
        conn.execute("UPDATE totp_credentials SET backup_json=?, failed_attempts=0, updated_at=? WHERE user_id=?", (json.dumps(remaining), _now().isoformat(), user_id))
        conn.commit()
    finally:
        conn.close()
    return {"method": "backup", "backup_codes_remaining": len(remaining)}


def disable(user_id: str) -> None:
    _ensure_table()
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM totp_credentials WHERE user_id=?", (user_id,))
        conn.commit()
    finally:
        conn.close()
