"""Notification outbox with optional SMTP delivery.

Every notification is persisted. Email is only attempted when TRUSTNET_SMTP_HOST is set;
otherwise the row is stored as 'skipped' (visible in-app) rather than pretending it was sent.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
import json
import os
import smtplib
import threading
from typing import Any, Callable

from models.database import get_db_connection
from agents.common import new_id, now_iso

# Tests can replace this with a fake transport: fn(message: EmailMessage) -> None
_transport_override: Callable[[EmailMessage], None] | None = None


def set_transport_override(fn: Callable[[EmailMessage], None] | None) -> None:
    global _transport_override
    _transport_override = fn


def _clean_header(value: str, limit: int = 200) -> str:
    # Strip CR/LF to prevent header injection.
    return " ".join(str(value).replace("\r", " ").replace("\n", " ").split())[:limit]


def smtp_configured() -> bool:
    return bool(os.environ.get("TRUSTNET_SMTP_HOST")) or _transport_override is not None


def _deliver(message: EmailMessage) -> None:
    if _transport_override is not None:
        _transport_override(message)
        return
    host = os.environ["TRUSTNET_SMTP_HOST"]
    port = int(os.environ.get("TRUSTNET_SMTP_PORT", "587"))
    user = os.environ.get("TRUSTNET_SMTP_USER")
    password = os.environ.get("TRUSTNET_SMTP_PASSWORD")
    with smtplib.SMTP(host, port, timeout=10) as smtp:
        if os.environ.get("TRUSTNET_SMTP_STARTTLS", "1") != "0":
            smtp.starttls()
        if user and password:
            smtp.login(user, password)
        smtp.send_message(message)


def _mark(notification_id: str, status: str, error: str | None = None) -> None:
    connection = get_db_connection()
    try:
        connection.execute(
            "UPDATE notifications SET status = ?, error = ?, sent_at = ? WHERE id = ?",
            (status, error, now_iso() if status == "sent" else None, notification_id),
        )
        connection.commit()
    finally:
        connection.close()


def _send_and_mark(notification_id: str, message: EmailMessage) -> None:
    try:
        _deliver(message)
        _mark(notification_id, "sent")
    except Exception as error:  # delivery failures must never break incident handling
        detail = str(error)
        for secret in (os.environ.get("TRUSTNET_SMTP_PASSWORD"), os.environ.get("TRUSTNET_SMTP_USER")):
            if secret:
                detail = detail.replace(secret, "[redacted]")
        _mark(notification_id, "failed", f"{type(error).__name__}: {detail[:200]}")


def staff_recipients() -> list[str]:
    connection = get_db_connection()
    try:
        rows = connection.execute(
            "SELECT email FROM users WHERE is_active = 1 AND role IN ('admin', 'analyst') ORDER BY email"
        ).fetchall()
    finally:
        connection.close()
    return [row["email"] for row in rows]


_NON_ROUTABLE_SUFFIXES = (".local", ".localhost", ".invalid")


def _is_routable(address: str) -> bool:
    """Seeded demo accounts use .local addresses that no mail server can deliver to."""
    domain = address.rsplit("@", 1)[-1].lower()
    return "@" in address and not domain.endswith(_NON_ROUTABLE_SUFFIXES)


def send_incident_report(incident_id: str, stage: str = "initial", *, action_id: str | None = None) -> list[dict[str, Any]]:
    """Email the detailed agent report (stage 'initial') or a short follow-up ('approved' / 'rejected')."""
    from agents.incident_report import send_report  # lazy: the report builder imports the response agent
    return send_report(incident_id, stage, action_id=action_id)


def alert_recipients() -> list[str]:
    """Active admins/analysts plus any real mailboxes listed in TRUSTNET_ALERT_EMAILS (comma separated)."""
    raw = ",".join(os.environ.get(name, "") for name in ("TRUSTNET_ALERT_EMAILS", "TRUSTNET_ALERT_RECIPIENTS"))
    extra = [item.strip() for item in raw.split(",") if "@" in item]
    return list(dict.fromkeys([*staff_recipients(), *extra]))


COOLDOWN_MINUTES = int(os.environ.get("TRUSTNET_NOTIFY_COOLDOWN_MINUTES", "15"))
# Serialises the dedup check + insert so concurrent callers cannot both store the same notification.
_notify_lock = threading.Lock()


def _dedup_key(incident_id: str | None, subject: str, recipient: str) -> str:
    import hashlib
    return hashlib.sha256(f"{incident_id}|{subject}|{recipient}".encode()).hexdigest()[:32]


def unread_count(recipient: str) -> int:
    connection = get_db_connection()
    try:
        return connection.execute("SELECT COUNT(*) FROM notifications WHERE recipient = ? AND read_at IS NULL", (recipient,)).fetchone()[0]
    finally:
        connection.close()


def mark_read(recipient: str, notification_id: str | None = None) -> int:
    """Mark one (or all) of the recipient's own notifications read. Returns rows changed."""
    connection = get_db_connection()
    try:
        if notification_id:
            cur = connection.execute("UPDATE notifications SET read_at = ? WHERE id = ? AND recipient = ? AND read_at IS NULL",
                                     (now_iso(), notification_id, recipient))
        else:
            cur = connection.execute("UPDATE notifications SET read_at = ? WHERE recipient = ? AND read_at IS NULL", (now_iso(), recipient))
        connection.commit()
        return cur.rowcount
    finally:
        connection.close()


def send_mfa_code(recipient: str, code: str) -> None:
    """Deliver a short-lived MFA code synchronously; fail closed if SMTP is absent."""
    if not smtp_configured():
        raise RuntimeError("MFA delivery is not configured; set TRUSTNET_SMTP_HOST or enable local DEMO_MODE.")
    message = EmailMessage()
    message["Subject"] = "TrustNet AI step-up verification code"
    message["From"] = _clean_header(os.environ.get("TRUSTNET_SMTP_FROM", "trustnet@localhost"))
    message["To"] = _clean_header(recipient)
    message.set_content(f"Your TrustNet AI verification code is {code}. It expires in five minutes. If you did not request this code, contact your security administrator.")
    _deliver(message)


def notify(incident_id: str | None, subject: str, body: str, *, recipients: list[str] | None = None, wait: bool = False,
           html_body: str | None = None) -> list[dict[str, Any]]:
    """Persist one notification per recipient and attempt email delivery when configured."""
    targets = recipients if recipients is not None else staff_recipients()
    subject = _clean_header(subject)
    created: list[dict[str, Any]] = []
    threads: list[threading.Thread] = []
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=COOLDOWN_MINUTES)).isoformat()
    for recipient in targets:
        recipient = _clean_header(recipient)
        key = _dedup_key(incident_id, subject, recipient)
        routable = _is_routable(recipient)
        row = {
            "id": new_id("NTF"), "incident_id": incident_id, "channel": "email", "recipient": recipient,
            "subject": subject, "body": body[:8000], "created_at": now_iso(),
            "status": "queued" if smtp_configured() and routable else "skipped",
            "error": None if smtp_configured() and routable else (
                "SMTP not configured; notification stored in-app only" if not smtp_configured()
                else "Non-routable demo address; notification stored in-app only"),
        }
        with _notify_lock:  # persistent dedup: same incident+subject+recipient inside the cooldown is stored/e-mailed once
            connection = get_db_connection()
            try:
                duplicate = connection.execute(
                    "SELECT 1 FROM notifications WHERE dedup_key = ? AND created_at >= ? LIMIT 1", (key, cutoff)).fetchone()
                if duplicate:
                    continue
                connection.execute(
                    "INSERT INTO notifications (id, incident_id, channel, recipient, subject, body, status, error, created_at, dedup_key) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (row["id"], incident_id, row["channel"], recipient, subject, row["body"], row["status"], row["error"], row["created_at"], key),
                )
                connection.commit()
            finally:
                connection.close()
        if row["status"] == "queued":
            message = EmailMessage()
            message["Subject"] = f"[TrustNet] {subject}"
            message["From"] = _clean_header(os.environ.get("TRUSTNET_SMTP_FROM", "trustnet@localhost"))
            message["To"] = recipient
            message.set_content(row["body"])
            if html_body:
                message.add_alternative(html_body, subtype="html")
            thread = threading.Thread(target=_send_and_mark, args=(row["id"], message), daemon=True)
            thread.start()
            threads.append(thread)
        created.append(row)
    if wait:
        for thread in threads:
            thread.join(timeout=15)
    return created


def list_notifications(
    limit: int = 50,
    incident_id: str | None = None,
    recipient: str | None = None,
) -> list[dict[str, Any]]:
    """List notifications, optionally scoped to a recipient.

    API routes must always provide ``recipient`` so a dashboard user cannot read
    another staff member's notification body or incident metadata. Omitting it is
    retained for trusted internal diagnostics and existing unit-test helpers only.
    """
    connection = get_db_connection()
    try:
        clauses: list[str] = []
        params: list[Any] = []
        if recipient is not None:
            clauses.append("recipient = ?")
            params.append(recipient)
        if incident_id is not None:
            clauses.append("incident_id = ?")
            params.append(incident_id)
        query = "SELECT * FROM notifications"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC, rowid DESC LIMIT ?"
        params.append(max(1, min(int(limit), 200)))
        rows = connection.execute(query, params).fetchall()
    finally:
        connection.close()
    return [dict(row) for row in rows]
