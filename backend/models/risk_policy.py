"""Saved, versioned risk policy and analyst-verdict score adjustments.

One policy row (JSON in ``policy_settings``) is read by the single risk engine on every
evaluation. Every change bumps ``version`` so a score can be traced to the policy that made it.
Verdict feedback is a bounded, per-user additive adjustment (a controlled, versioned rule
adjustment). It is NOT online model training and is labelled as such in API responses.
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from typing import Any

from models.database import get_db_connection, initialize_database

POLICY_KEY = "risk_policy"
WEIGHT_KEYS = ("behavioral", "anomaly", "classifier", "device_trust", "network", "geo")
DEFAULT_POLICY: dict[str, Any] = {
    "version": 1,
    "weights": {"behavioral": 0.30, "anomaly": 0.20, "classifier": 0.10, "device_trust": 0.20, "network": 0.20, "geo": 0.0},
    "sensitivity": 1.0,          # multiplier on the fused score, 0.5 - 1.5
    "device_trust_enabled": True,
    "geo_enabled": True,
    "learning_rate": 0.25,       # verdict adjustment = learning_rate * 20 points, capped
}
SENSITIVITY_RANGE = (0.5, 1.5)
LEARNING_RATE_RANGE = (0.0, 0.5)
MAX_USER_ADJUSTMENT = 15.0
VERDICT_POINTS = 20.0
MAX_WEIGHT_SUM = 1.5


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure(connection: Any) -> None:
    connection.execute(
        """CREATE TABLE IF NOT EXISTS user_risk_feedback (
               incident_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, delta REAL NOT NULL,
               verdict TEXT NOT NULL, feedback_id TEXT, policy_version INTEGER NOT NULL,
               score_before REAL, score_after REAL, updated_at TEXT NOT NULL)"""
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_user_risk_feedback_user ON user_risk_feedback(user_id)")


def get_policy() -> dict[str, Any]:
    initialize_database()
    connection = get_db_connection()
    try:
        row = connection.execute("SELECT value FROM policy_settings WHERE key = ?", (POLICY_KEY,)).fetchone()
    finally:
        connection.close()
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    if row:
        stored = json.loads(row["value"])
        policy.update({k: v for k, v in stored.items() if k != "weights"})
        policy["weights"].update(stored.get("weights", {}))
    return policy


def validate_policy_update(update: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(update, dict):
        raise ValueError("Policy update must be an object.")
    allowed = {"weights", "sensitivity", "device_trust_enabled", "geo_enabled", "learning_rate"}
    unknown = set(update) - allowed
    if unknown:
        raise ValueError(f"Unknown policy field(s): {', '.join(sorted(unknown))}.")
    merged = json.loads(json.dumps(current))
    if "weights" in update:
        weights = update["weights"]
        if not isinstance(weights, dict) or set(weights) - set(WEIGHT_KEYS):
            raise ValueError(f"weights must only contain: {', '.join(WEIGHT_KEYS)}.")
        for key, value in weights.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError(f"weight '{key}' must be a number between 0 and 1.")
            merged["weights"][key] = round(float(value), 4)
        if sum(merged["weights"].values()) > MAX_WEIGHT_SUM:
            raise ValueError(f"weights may not sum to more than {MAX_WEIGHT_SUM}.")
    for key, (low, high) in (("sensitivity", SENSITIVITY_RANGE), ("learning_rate", LEARNING_RATE_RANGE)):
        if key in update:
            value = update[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not low <= value <= high:
                raise ValueError(f"{key} must be a number between {low} and {high}.")
            merged[key] = round(float(value), 4)
    for key in ("device_trust_enabled", "geo_enabled"):
        if key in update:
            if not isinstance(update[key], bool):
                raise ValueError(f"{key} must be true or false.")
            merged[key] = update[key]
    return merged


def update_policy(update: dict[str, Any]) -> dict[str, Any]:
    current = get_policy()
    merged = validate_policy_update(update, current)
    changed = {k: merged[k] for k in ("weights", "sensitivity", "device_trust_enabled", "geo_enabled", "learning_rate") if merged[k] != current[k]}
    if not changed:
        return current
    merged["version"] = int(current["version"]) + 1
    connection = get_db_connection()
    try:
        connection.execute(
            """INSERT INTO policy_settings (key, value, updated_at) VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at""",
            (POLICY_KEY, json.dumps(merged), _now()),
        )
        connection.commit()
    finally:
        connection.close()
    return merged


def user_adjustment(user_id: str) -> float:
    connection = get_db_connection()
    try:
        _ensure(connection)
        row = connection.execute("SELECT COALESCE(SUM(delta), 0) AS total FROM user_risk_feedback WHERE user_id = ?", (user_id,)).fetchone()
    finally:
        connection.close()
    return round(max(-MAX_USER_ADJUSTMENT, min(MAX_USER_ADJUSTMENT, float(row["total"]))), 2)


def record_verdict_effect(*, incident_id: str, user_id: str, verdict: str, feedback_id: str,
                          score_before: float, score_after_fn: Any) -> dict[str, Any]:
    """Store/replace this incident's adjustment, then report before/after. A corrected verdict replaces the old one."""
    policy = get_policy()
    delta = policy["learning_rate"] * VERDICT_POINTS * (1 if verdict == "true_positive" else -1)
    connection = get_db_connection()
    try:
        _ensure(connection)
        connection.execute(
            """INSERT INTO user_risk_feedback (incident_id, user_id, delta, verdict, feedback_id, policy_version, score_before, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(incident_id) DO UPDATE SET delta = excluded.delta, verdict = excluded.verdict,
                 feedback_id = excluded.feedback_id, policy_version = excluded.policy_version,
                 score_before = excluded.score_before, updated_at = excluded.updated_at""",
            (incident_id, user_id, round(delta, 4), verdict, feedback_id, policy["version"], score_before, _now()),
        )
        connection.commit()
    finally:
        connection.close()
    score_after = score_after_fn()
    connection = get_db_connection()
    try:
        connection.execute("UPDATE user_risk_feedback SET score_after = ? WHERE incident_id = ?", (score_after, incident_id))
        connection.commit()
    finally:
        connection.close()
    return {
        "incident_id": incident_id, "user_id": user_id, "verdict": verdict, "score_before": score_before,
        "score_after": score_after, "user_adjustment": user_adjustment(user_id), "policy_version": policy["version"],
        "mechanism": "bounded per-user score adjustment (controlled rule adjustment); no ML model is retrained",
    }


def get_verdict_effect(incident_id: str) -> dict[str, Any] | None:
    connection = get_db_connection()
    try:
        _ensure(connection)
        row = connection.execute("SELECT * FROM user_risk_feedback WHERE incident_id = ?", (incident_id,)).fetchone()
    finally:
        connection.close()
    return dict(row) if row else None


def reset_feedback() -> None:
    connection = get_db_connection()
    try:
        _ensure(connection)
        connection.execute("DELETE FROM user_risk_feedback")
        connection.commit()
    finally:
        connection.close()
