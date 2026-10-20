"""Bounded in-memory API request logging and explainable anomaly rules."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import json
from typing import Any
from uuid import uuid4

from models import database as database_module
from models.database import get_db_connection, initialize_database
from models.security_events import persist_security_event

MAX_EVENTS = 5000
RATE_LIMIT_PER_MINUTE = 60
REPEATED_SENSITIVE_LIMIT = 10
CREDENTIAL_STUFFING_USERS = 5
WINDOW = timedelta(minutes=1)
SENSITIVE_PATHS = {"/api/auth/login", "/api/login", "/api/auth/register", "/api/baselines/reset", "/api/devices"}

_EVENTS: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)
_REQUESTS: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
_SENSITIVE_REQUESTS: dict[tuple[str, str, str], deque[datetime]] = defaultdict(deque)
_IPS_BY_USER: dict[str, set[str]] = defaultdict(set)
_FAILED_AUTH_BY_IP: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)
_ACTIVITY_DATABASE_PATH: str | None = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _prune(queue: deque, cutoff: datetime) -> None:
    while queue:
        first = queue[0][0] if isinstance(queue[0], tuple) else queue[0]
        if first >= cutoff:
            break
        queue.popleft()


def _decode_persisted_event(row: Any) -> dict[str, Any]:
    payload = json.loads(row["event_payload"] or "{}")
    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "source_ip": row["ip_address"],
        "user_id": row["user_id"],
        "endpoint": row["request_path"],
        "method": row["http_method"],
        "status_code": row["status_code"],
        "response_time_ms": payload.get("response_time_ms"),
        "anomaly_types": json.loads(row["risk_indicators"] or "[]"),
        "evidence": payload.get("evidence"),
        "affected_users": payload.get("affected_users", []),
    }


def _ensure_recent_activity_loaded() -> None:
    global _ACTIVITY_DATABASE_PATH
    active_path = database_module._DB_PATH
    if _ACTIVITY_DATABASE_PATH == active_path:
        return
    initialize_database()
    recent_cutoff = _now() - WINDOW
    connection = get_db_connection()
    try:
        event_rows = connection.execute(
            """SELECT * FROM security_events
               WHERE event_category IN ('request_activity', 'security_anomaly')
               ORDER BY timestamp DESC LIMIT ?""",
            (MAX_EVENTS,),
        ).fetchall()
        failed_attempts = connection.execute(
            """SELECT user_id, timestamp, ip FROM login_attempts
               WHERE success = 0 AND timestamp >= ? ORDER BY timestamp""",
            (recent_cutoff.isoformat(),),
        ).fetchall()
    finally:
        connection.close()

    _EVENTS.clear()
    _REQUESTS.clear()
    _SENSITIVE_REQUESTS.clear()
    _IPS_BY_USER.clear()
    _FAILED_AUTH_BY_IP.clear()
    for row in reversed(event_rows):
        event = _decode_persisted_event(row)
        _EVENTS.append(event)
        event_time = datetime.fromisoformat(event["timestamp"])
        if event_time < recent_cutoff or row["event_category"] != "request_activity":
            continue
        identity = event["user_id"] or "anonymous"
        _REQUESTS[(event["source_ip"], identity)].append(event_time)
        endpoint = event["endpoint"]
        sensitive = endpoint in SENSITIVE_PATHS or endpoint.startswith("/api/devices/") or (
            endpoint.startswith("/api/incidents/")
            and endpoint.rsplit("/", 1)[-1] in {"approve", "dismiss", "resolve", "escalate"}
        )
        if sensitive:
            key = "/api/devices/*" if endpoint.startswith("/api/devices/") else endpoint
            _SENSITIVE_REQUESTS[(event["source_ip"], identity, key)].append(event_time)
        if event["user_id"]:
            _IPS_BY_USER[event["user_id"]].add(event["source_ip"])
    for attempt in failed_attempts:
        _FAILED_AUTH_BY_IP[attempt["ip"]].append(
            (datetime.fromisoformat(attempt["timestamp"]), attempt["user_id"])
        )
    _ACTIVITY_DATABASE_PATH = active_path


def record_auth_failure(ip: str, user_id: str) -> dict[str, Any] | None:
    _ensure_recent_activity_loaded()
    now = _now()
    attempts = _FAILED_AUTH_BY_IP[ip]
    _prune(attempts, now - WINDOW)
    users_before = {attempt_user for _, attempt_user in attempts}
    attempts.append((now, user_id))
    distinct_users = {attempt_user for _, attempt_user in attempts}
    if len(distinct_users) < CREDENTIAL_STUFFING_USERS or len(users_before) >= CREDENTIAL_STUFFING_USERS:
        return None
    event = _append_anomaly(
        "credential_stuffing_pattern", ip=ip, user_id=None,
        endpoint="/api/auth/login", method="POST",
        evidence=f"Failed authentication attempts targeted {len(distinct_users)} distinct users within one minute.",
        affected_users=sorted(distinct_users),
    )
    return event


def _append_anomaly(
    kind: str, *, ip: str, user_id: str | None, endpoint: str, method: str,
    evidence: str, affected_users: list[str] | None = None,
) -> dict[str, Any]:
    event = {
        "id": f"NET-{uuid4().hex[:10].upper()}",
        "timestamp": _now().isoformat(),
        "source_ip": ip,
        "user_id": user_id,
        "endpoint": endpoint,
        "method": method,
        "status_code": None,
        "response_time_ms": None,
        "anomaly_types": [kind],
        "evidence": evidence,
        "affected_users": affected_users or [],
    }
    try:
        persist_security_event({
            "id": event["id"],
            "timestamp": event["timestamp"],
            "user_id": user_id,
            "ip_address": ip,
            "request_path": endpoint,
            "http_method": method,
            "status_code": None,
            "session_id": None,
            "event_category": "security_anomaly",
            "risk_indicators": [kind],
            "event_payload": {"evidence": evidence, "affected_users": affected_users or []},
        })
    except Exception:
        pass
    _EVENTS.append(event)
    return dict(event)


def record_request(*, ip: str, user_id: str | None, endpoint: str, method: str, status_code: int, response_time_ms: float) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    _ensure_recent_activity_loaded()
    now = _now()
    identity = user_id or "anonymous"
    flags: list[dict[str, Any]] = []
    request_window = _REQUESTS[(ip, identity)]
    _prune(request_window, now - WINDOW)
    request_window.append(now)
    if len(request_window) == RATE_LIMIT_PER_MINUTE + 1:
        flags.append(_append_anomaly(
            "rate_anomaly", ip=ip, user_id=user_id, endpoint=endpoint, method=method,
            evidence=f"{len(request_window)} requests from this IP/user pair in one minute (threshold {RATE_LIMIT_PER_MINUTE}).",
        ))

    sensitive = endpoint in SENSITIVE_PATHS or endpoint.startswith("/api/devices/") or (
        endpoint.startswith("/api/incidents/") and endpoint.rsplit("/", 1)[-1] in {"approve", "dismiss", "resolve", "escalate"}
    )
    sensitive_key = "/api/devices/*" if endpoint.startswith("/api/devices/") else endpoint
    if sensitive:
        sensitive_window = _SENSITIVE_REQUESTS[(ip, identity, sensitive_key)]
        _prune(sensitive_window, now - WINDOW)
        sensitive_window.append(now)
        if len(sensitive_window) == REPEATED_SENSITIVE_LIMIT:
            flags.append(_append_anomaly(
                "repeated_requests", ip=ip, user_id=user_id, endpoint=endpoint, method=method,
                evidence=f"Repeated sensitive endpoint accessed {len(sensitive_window)} times in one minute.",
            ))

    if user_id:
        known_ips = _IPS_BY_USER[user_id]
        if known_ips and ip not in known_ips:
            flags.append(_append_anomaly(
                "new_ip_for_user", ip=ip, user_id=user_id, endpoint=endpoint, method=method,
                evidence="Authenticated user request came from an IP address not previously observed for that user.",
            ))
        known_ips.add(ip)

    event = {
        "id": f"NET-{uuid4().hex[:10].upper()}",
        "timestamp": now.isoformat(),
        "source_ip": ip,
        "user_id": user_id,
        "endpoint": endpoint,
        "method": method,
        "status_code": status_code,
        "response_time_ms": round(response_time_ms, 2),
        "anomaly_types": [flag["anomaly_types"][0] for flag in flags],
        "evidence": "; ".join(flag["evidence"] for flag in flags) or None,
    }
    try:
        persist_security_event({
            "id": event["id"],
            "timestamp": event["timestamp"],
            "user_id": user_id,
            "ip_address": ip,
            "request_path": endpoint,
            "http_method": method,
            "status_code": status_code,
            "event_category": "request_activity",
            "risk_indicators": event["anomaly_types"],
            "event_payload": {"response_time_ms": round(response_time_ms, 2), "evidence": event["evidence"]},
        })
    except Exception:
        pass
    _EVENTS.append(event)
    return dict(event), flags


def list_network_events(*, ip: str | None = None, user_id: str | None = None, anomalies_only: bool = False, limit: int = 200) -> list[dict[str, Any]]:
    _ensure_recent_activity_loaded()
    connection = get_db_connection()
    try:
        rows = connection.execute(
            """SELECT * FROM security_events
               WHERE event_category IN ('request_activity', 'security_anomaly')
               ORDER BY timestamp DESC LIMIT ?""",
            (MAX_EVENTS,),
        ).fetchall()
    finally:
        connection.close()
    items_by_id = {row["id"]: _decode_persisted_event(row) for row in rows}
    items_by_id.update({event["id"]: dict(event) for event in _EVENTS})
    items = sorted(items_by_id.values(), key=lambda item: item["timestamp"])
    if ip:
        items = [item for item in items if item["source_ip"] == ip]
    if user_id:
        items = [item for item in items if item["user_id"] == user_id or user_id in item.get("affected_users", [])]
    if anomalies_only:
        items = [item for item in items if item.get("anomaly_types")]
    return [dict(item) for item in reversed(items[-max(1, min(limit, 1000)):])]


def network_score_for_user(user_id: str) -> float:
    _ensure_recent_activity_loaded()
    recent_cutoff = _now() - timedelta(minutes=15)
    counts: dict[str, int] = defaultdict(int)
    for event in _EVENTS:
        if (event.get("user_id") != user_id and user_id not in event.get("affected_users", [])) or not event.get("anomaly_types"):
            continue
        try:
            event_time = datetime.fromisoformat(event["timestamp"])
        except (TypeError, ValueError):
            continue
        if event_time >= recent_cutoff:
            for anomaly_type in event["anomaly_types"]:
                counts[anomaly_type] += 1
    score = 0.0
    score += min(40.0, counts["rate_anomaly"] * 20.0)
    score += min(30.0, counts["repeated_requests"] * 30.0)
    score += min(30.0, counts["new_ip_for_user"] * 30.0)
    score += min(40.0, counts["credential_stuffing_pattern"] * 40.0)
    return min(100.0, score)


def network_anomaly_count() -> int:
    _ensure_recent_activity_loaded()
    cutoff = (_now() - timedelta(minutes=15)).isoformat()
    connection = get_db_connection()
    try:
        rows = connection.execute(
            """SELECT risk_indicators FROM security_events
               WHERE event_category IN ('request_activity', 'security_anomaly')
                 AND timestamp >= ? AND risk_indicators IS NOT NULL AND risk_indicators != '[]'""",
            (cutoff,),
        ).fetchall()
        persisted_count = sum(bool(json.loads(row["risk_indicators"])) for row in rows)
    finally:
        connection.close()
    persisted_ids = {event["id"] for event in _EVENTS}
    fallback_count = sum(
        bool(event.get("anomaly_types")) and event["id"] not in persisted_ids for event in _EVENTS
    )
    return persisted_count + fallback_count


def reset_network_state() -> None:
    global _ACTIVITY_DATABASE_PATH
    _EVENTS.clear()
    _REQUESTS.clear()
    _SENSITIVE_REQUESTS.clear()
    _IPS_BY_USER.clear()
    _FAILED_AUTH_BY_IP.clear()
    _ACTIVITY_DATABASE_PATH = database_module._DB_PATH
