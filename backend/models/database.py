"""SQLite-backed persistence helpers for TrustNet demo data.

This intentionally uses the smallest local durable store that fits the project:
SQLite. It keeps the backend portable, requires no external service, and is
compatible with the in-memory architecture already in place.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Iterable

_DB_PATH = os.environ.get("TRUSTNET_DB_PATH") or str(Path(__file__).resolve().parents[1] / "data" / "trustnet.db")

def _ensure_parent_dir() -> None:
    Path(_DB_PATH).parent.mkdir(parents=True, exist_ok=True)


def get_db_connection() -> sqlite3.Connection:
    _ensure_parent_dir()
    connection = sqlite3.connect(_DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def get_readonly_connection() -> sqlite3.Connection:
    """Connection that cannot write: used for the Investigator's evidence tools."""
    _ensure_parent_dir()
    connection = sqlite3.connect(_DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def initialize_database() -> None:
    """Create the minimal tables required for durable event and risk data."""
    connection = get_db_connection()
    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                user_id TEXT,
                ip_address TEXT,
                device_fingerprint_hash TEXT,
                request_path TEXT NOT NULL,
                http_method TEXT NOT NULL,
                status_code INTEGER,
                session_id TEXT,
                event_category TEXT NOT NULL,
                risk_indicators TEXT,
                event_payload TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_security_events_user_time
                ON security_events(user_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_security_events_ip_time
                ON security_events(ip_address, timestamp);
            CREATE INDEX IF NOT EXISTS idx_security_events_category
                ON security_events(event_category);

            CREATE TABLE IF NOT EXISTS audit_entries (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            );

            CREATE TRIGGER IF NOT EXISTS audit_entries_no_update
            BEFORE UPDATE ON audit_entries
            BEGIN
                SELECT RAISE(ABORT, 'audit entries are append-only');
            END;

            CREATE TRIGGER IF NOT EXISTS audit_entries_no_delete
            BEFORE DELETE ON audit_entries
            BEGIN
                SELECT RAISE(ABORT, 'audit entries are append-only');
            END;

            CREATE TABLE IF NOT EXISTS audit_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_login_at TEXT
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
                attempt_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                success INTEGER NOT NULL,
                ip TEXT NOT NULL,
                device_id TEXT,
                reason TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_login_attempts_user_time
                ON login_attempts(user_id, timestamp);

            CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti TEXT PRIMARY KEY,
                expires_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS refresh_sessions (
                token_hash TEXT PRIMARY KEY,
                family_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                device_id TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                replaced_by_hash TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_refresh_sessions_family ON refresh_sessions(family_id);
            CREATE INDEX IF NOT EXISTS idx_refresh_sessions_user ON refresh_sessions(user_id);

            CREATE TABLE IF NOT EXISTS policy_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            INSERT OR IGNORE INTO policy_settings (key, value, updated_at)
                VALUES ('restrict_threshold', '61', CURRENT_TIMESTAMP);
            UPDATE policy_settings SET value = '61', updated_at = CURRENT_TIMESTAMP
                WHERE key = 'restrict_threshold' AND value = '60';

            CREATE TABLE IF NOT EXISTS risk_assessments (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                score REAL NOT NULL,
                tier TEXT NOT NULL,
                source TEXT NOT NULL,
                normalized_inputs TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_risk_assessments_user
                ON risk_assessments(user_id, created_at);

            CREATE TABLE IF NOT EXISTS risk_signals (
                user_id TEXT PRIMARY KEY,
                behavioral_score REAL NOT NULL,
                anomaly_score REAL NOT NULL,
                classifier_label TEXT NOT NULL,
                classifier_confidence REAL NOT NULL,
                device_id TEXT,
                device_trust_status TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS login_baselines (
                username TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                fingerprint_hash TEXT NOT NULL,
                geo TEXT NOT NULL,
                normal_login_hour REAL NOT NULL,
                normal_session_duration REAL NOT NULL,
                normal_data_volume REAL NOT NULL,
                normal_api_calls REAL NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS graph_entities (
                id TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                label TEXT NOT NULL,
                criticality INTEGER NOT NULL DEFAULT 1,
                risk_score REAL NOT NULL DEFAULT 0,
                metadata TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS graph_edges (
                id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                weight REAL NOT NULL,
                relation_type TEXT NOT NULL,
                reason TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(source_id) REFERENCES graph_entities(id),
                FOREIGN KEY(target_id) REFERENCES graph_entities(id)
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                user_id TEXT,
                device_id TEXT,
                ip_address TEXT,
                risk_score REAL NOT NULL,
                status TEXT NOT NULL,
                reason TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                investigator_findings TEXT,
                response_action TEXT,
                approval_status TEXT,
                analyst_verdict TEXT,
                event_ids TEXT,
                evidence TEXT,
                risk_breakdown TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_incidents_status_time
                ON incidents(status, created_at);

            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                fingerprint_hash TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                trust_status TEXT NOT NULL,
                label TEXT NOT NULL,
                last_login_first_for_user INTEGER NOT NULL DEFAULT 0,
                quarantined INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_devices_user_last_seen
                ON devices(user_id, last_seen);

            CREATE TABLE IF NOT EXISTS protected_assets (
                asset_id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                asset_type TEXT NOT NULL,
                criticality INTEGER NOT NULL CHECK (criticality BETWEEN 1 AND 5),
                classification TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS asset_policies (
                role TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                action TEXT NOT NULL,
                allowed INTEGER NOT NULL CHECK (allowed IN (0, 1)),
                PRIMARY KEY (role, asset_id, action),
                FOREIGN KEY(asset_id) REFERENCES protected_assets(asset_id)
            );

            CREATE TABLE IF NOT EXISTS incident_events (
                incident_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                PRIMARY KEY (incident_id, event_id)
            );

            CREATE TABLE IF NOT EXISTS agent_activity (
                id TEXT PRIMARY KEY,
                incident_id TEXT,
                agent TEXT NOT NULL,
                action TEXT NOT NULL,
                summary TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_agent_activity_time ON agent_activity(created_at);
            CREATE INDEX IF NOT EXISTS idx_agent_activity_incident ON agent_activity(incident_id);

            CREATE TABLE IF NOT EXISTS response_actions (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                target_user_id TEXT,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                rationale TEXT,
                safeguards TEXT,
                decided_by TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                executed_at TEXT,
                expires_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_response_actions_incident ON response_actions(incident_id);

            CREATE TABLE IF NOT EXISTS analyst_feedback (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                verdict TEXT NOT NULL CHECK (verdict IN ('true_positive', 'false_positive')),
                notes TEXT,
                analyst_id TEXT,
                rules_fired TEXT NOT NULL,
                investigator_confidence REAL NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_analyst_feedback_incident ON analyst_feedback(incident_id, created_at);

            CREATE TABLE IF NOT EXISTS notifications (
                id TEXT PRIMARY KEY,
                incident_id TEXT,
                channel TEXT NOT NULL,
                recipient TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                status TEXT NOT NULL,
                error TEXT,
                created_at TEXT NOT NULL,
                sent_at TEXT,
                read_at TEXT,
                dedup_key TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_notifications_time ON notifications(created_at);

            CREATE TABLE IF NOT EXISTS agent_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            INSERT OR IGNORE INTO agent_settings (key, value, updated_at) VALUES
                ('autonomy_mode', 'recommend', CURRENT_TIMESTAMP),
                ('kill_switch', '0', CURRENT_TIMESTAMP),
                ('auto_max_per_hour', '3', CURRENT_TIMESTAMP),
                ('auto_min_confidence', '0.85', CURRENT_TIMESTAMP);
            """
        )
        incident_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(incidents)")
        }
        for column in ("evidence", "risk_breakdown"):
            if column not in incident_columns:
                connection.execute(f"ALTER TABLE incidents ADD COLUMN {column} TEXT")
        response_columns = {row["name"] for row in connection.execute("PRAGMA table_info(response_actions)")}
        if "expires_at" not in response_columns:
            connection.execute("ALTER TABLE response_actions ADD COLUMN expires_at TEXT")
        notification_columns = {row["name"] for row in connection.execute("PRAGMA table_info(notifications)")}
        for column in ("read_at", "dedup_key"):
            if column not in notification_columns:
                connection.execute(f"ALTER TABLE notifications ADD COLUMN {column} TEXT")
        if "incident_number" not in incident_columns:
            connection.execute("ALTER TABLE incidents ADD COLUMN incident_number INTEGER")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_number ON incidents(incident_number) WHERE incident_number IS NOT NULL"
        )
        connection.commit()
    finally:
        connection.close()


def _sqlite_value(value: Any) -> str:
    return json.dumps(value, separators=(",", ":")) if value is not None else None


def _json_decode(value: Any) -> Any:
    if value is None:
        return None
    return json.loads(value)


def persist_rows(table: str, rows: Iterable[dict[str, Any]]) -> None:
    rows = list(rows)
    if not rows:
        return
    keys = list(rows[0].keys())
    connection = get_db_connection()
    try:
        placeholders = ", ".join("?" for _ in keys)
        assignments = ", ".join(f"{key} = excluded.{key}" for key in keys)
        insert_sql = f"INSERT INTO {table} ({', '.join(keys)}) VALUES ({placeholders}) ON CONFLICT(id) DO UPDATE SET {assignments}"
        connection.executemany(insert_sql, [tuple(row.get(key) for key in keys) for row in rows])
        connection.commit()
    finally:
        connection.close()
