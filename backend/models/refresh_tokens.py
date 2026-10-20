"""Database-backed rotating refresh tokens with reuse detection."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import hashlib, secrets
from uuid import uuid4
from models.database import get_db_connection, initialize_database

REFRESH_DAYS = 7

def _now(): return datetime.now(timezone.utc)
def _hash(raw: str) -> str: return hashlib.sha256(raw.encode("utf-8")).hexdigest()
def _iso(value): return value.isoformat()

def issue_refresh_token(user_id: str, device_id: str | None = None, family_id: str | None = None) -> tuple[str, str]:
    initialize_database()
    raw = secrets.token_urlsafe(48)
    token_hash = _hash(raw)
    family = family_id or uuid4().hex
    now = _now()
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO refresh_sessions(token_hash,family_id,user_id,device_id,created_at,expires_at) VALUES(?,?,?,?,?,?)",
                     (token_hash, family, user_id, device_id, _iso(now), _iso(now + timedelta(days=REFRESH_DAYS))))
        conn.commit()
    finally: conn.close()
    return raw, family

def rotate_refresh_token(raw: str) -> dict | None:
    """Atomically rotate a token. Reuse of a consumed token revokes its whole family."""
    if not raw: return None
    initialize_database(); token_hash = _hash(raw); now = _now()
    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM refresh_sessions WHERE token_hash=?", (token_hash,)).fetchone()
        if row is None:
            conn.rollback(); return None
        row = dict(row)
        if row["revoked_at"] is not None:
            conn.execute("UPDATE refresh_sessions SET revoked_at=? WHERE family_id=? AND revoked_at IS NULL", (_iso(now), row["family_id"]))
            conn.commit()
            return {"reuse_detected": True, "family_id": row["family_id"], "user_id": row["user_id"]}
        if datetime.fromisoformat(row["expires_at"]) <= now:
            conn.execute("UPDATE refresh_sessions SET revoked_at=? WHERE token_hash=?", (_iso(now), token_hash)); conn.commit(); return None
        new_raw = secrets.token_urlsafe(48); new_hash = _hash(new_raw)
        conn.execute("INSERT INTO refresh_sessions(token_hash,family_id,user_id,device_id,created_at,expires_at) VALUES(?,?,?,?,?,?)",
                     (new_hash,row["family_id"],row["user_id"],row["device_id"],_iso(now),_iso(now+timedelta(days=REFRESH_DAYS))))
        changed = conn.execute("UPDATE refresh_sessions SET revoked_at=?, replaced_by_hash=? WHERE token_hash=? AND revoked_at IS NULL",
                               (_iso(now),new_hash,token_hash)).rowcount
        if changed != 1:
            conn.execute("UPDATE refresh_sessions SET revoked_at=? WHERE family_id=? AND revoked_at IS NULL", (_iso(now),row["family_id"]))
            conn.commit(); return {"reuse_detected":True,"family_id":row["family_id"],"user_id":row["user_id"]}
        conn.commit()
        return {"token":new_raw,"family_id":row["family_id"],"user_id":row["user_id"],"device_id":row["device_id"]}
    except Exception:
        conn.rollback(); raise
    finally: conn.close()

def revoke_refresh_token(raw: str | None) -> None:
    if not raw: return
    initialize_database(); now=_iso(_now()); conn=get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row=conn.execute("SELECT family_id FROM refresh_sessions WHERE token_hash=?",(_hash(raw),)).fetchone()
        if row: conn.execute("UPDATE refresh_sessions SET revoked_at=? WHERE family_id=? AND revoked_at IS NULL",(now,row["family_id"]))
        conn.commit()
    finally: conn.close()
