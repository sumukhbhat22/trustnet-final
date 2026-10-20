"""Explainable fusion of the security signals currently collected by the demo."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from models import database as database_module
from models.database import get_db_connection, initialize_database
from models.device_registry import list_devices
from models.network_monitor import network_score_for_user
from models import risk_policy
from models.asset_criticality import exposure_points

# Weighted, bounded, and explicitly documented. Physical telemetry remains a stub.
WEIGHTS = {
    "behavioral": 0.30,
    "anomaly": 0.20,
    "classifier": 0.10,
    "device_trust": 0.20,
    "network": 0.20,
}
DEVICE_PENALTY = {"trusted": 0.0, "unknown": 50.0, "flagged": 100.0}
RESTRICT_THRESHOLD = 61.0
HIGH_RISK_THRESHOLD = RESTRICT_THRESHOLD
BLOCK_THRESHOLD = 85.0
_POLICY_DATABASE_PATH: str | None = None
_restrict_threshold = RESTRICT_THRESHOLD

_latest_signals: dict[str, dict[str, Any]] = {}
_SIGNALS_DATABASE_PATH: str | None = None


def _ensure_signals_loaded() -> None:
    global _SIGNALS_DATABASE_PATH
    active_path = database_module._DB_PATH
    if _SIGNALS_DATABASE_PATH == active_path:
        return
    initialize_database()
    connection = get_db_connection()
    try:
        for migration in (
            "ALTER TABLE risk_signals ADD COLUMN geo_score REAL NOT NULL DEFAULT 0",
            "ALTER TABLE risk_signals ADD COLUMN ip_address TEXT",
        ):
            try:
                connection.execute(migration)
                connection.commit()
            except Exception:  # column already exists
                pass
        rows = connection.execute("SELECT * FROM risk_signals").fetchall()
    finally:
        connection.close()
    _latest_signals.clear()
    for row in rows:
        _latest_signals[row["user_id"]] = {
            "behavioral_score": row["behavioral_score"],
            "anomaly_score": row["anomaly_score"],
            "classifier_label": row["classifier_label"],
            "classifier_confidence": row["classifier_confidence"],
            "device_id": row["device_id"],
            "device_trust_status": row["device_trust_status"],
            "geo_score": row["geo_score"],
            "ip_address": row["ip_address"] if "ip_address" in row.keys() else None,
        }
    _SIGNALS_DATABASE_PATH = active_path


def _persist_signals(user_id: str, signals: dict[str, Any]) -> None:
    connection = get_db_connection()
    try:
        connection.execute(
            """INSERT INTO risk_signals
               (user_id, behavioral_score, anomaly_score, classifier_label,
                classifier_confidence, device_id, device_trust_status, geo_score, ip_address, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(user_id) DO UPDATE SET
                 behavioral_score = excluded.behavioral_score,
                 anomaly_score = excluded.anomaly_score,
                 classifier_label = excluded.classifier_label,
                 classifier_confidence = excluded.classifier_confidence,
                 device_id = excluded.device_id,
                 device_trust_status = excluded.device_trust_status,
                 geo_score = excluded.geo_score,
                 ip_address = excluded.ip_address,
                 updated_at = excluded.updated_at""",
            (
                user_id, signals["behavioral_score"], signals["anomaly_score"],
                signals["classifier_label"], signals["classifier_confidence"],
                signals["device_id"], signals["device_trust_status"], signals.get("geo_score", 0.0),
                signals.get("ip_address"), datetime.now(timezone.utc).isoformat(),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def get_restrict_threshold() -> float:
    global _POLICY_DATABASE_PATH, _restrict_threshold
    active_path = database_module._DB_PATH
    if _POLICY_DATABASE_PATH != active_path:
        initialize_database()
        connection = get_db_connection()
        try:
            row = connection.execute(
                "SELECT value FROM policy_settings WHERE key = 'restrict_threshold'"
            ).fetchone()
        finally:
            connection.close()
        _restrict_threshold = float(row["value"]) if row else RESTRICT_THRESHOLD
        _POLICY_DATABASE_PATH = active_path
    return _restrict_threshold


def set_restrict_threshold(value: float) -> float:
    global _POLICY_DATABASE_PATH, _restrict_threshold
    try:
        threshold = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError("Restrict threshold must be numeric.") from error
    if not math.isfinite(threshold) or threshold < 50 or threshold > BLOCK_THRESHOLD:
        raise ValueError("Restrict threshold must be between 50 and 85.")
    threshold = round(threshold, 2)
    initialize_database()
    connection = get_db_connection()
    try:
        connection.execute(
            """INSERT INTO policy_settings (key, value, updated_at)
               VALUES ('restrict_threshold', ?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at""",
            (str(threshold), datetime.now(timezone.utc).isoformat()),
        )
        connection.commit()
    finally:
        connection.close()
    _restrict_threshold = threshold
    _POLICY_DATABASE_PATH = database_module._DB_PATH
    return threshold


def _clamp(value: float) -> float:
    return max(0.0, min(100.0, float(value)))


def _normalize(value: Any, *, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if number != number or number in (float("inf"), float("-inf")):
        return default
    return max(0.0, min(1.0, number))


def calculate_centralized_risk(features: dict[str, Any]) -> float:
    """Compute the centralized risk formula required by the project spec."""
    if not isinstance(features, dict):
        raise ValueError("Risk features must be a dictionary.")
    csf = _normalize(features.get("csf"), default=0.0)
    network = _normalize(features.get("network"), default=0.0)
    device_untrusted = _normalize(features.get("deviceUntrusted"), default=0.0)
    geo_flag = _normalize(features.get("geoFlag"), default=0.0)
    score = 100.0 * (
        0.50 * csf + 0.20 * network + 0.20 * device_untrusted + 0.10 * geo_flag
    )
    return round(max(0.0, min(100.0, score)), 2)


def risk_tier_for_score(score: float) -> str:
    """Map risk score to the monitoring tier specified by the project."""
    normalized = max(0.0, min(100.0, float(score)))
    if normalized <= 30:
        return "Monitor"
    restrict_threshold = get_restrict_threshold()
    if normalized < restrict_threshold:
        return "MFA"
    if normalized <= BLOCK_THRESHOLD:
        return "Restrict"
    return "Block"


def explain_centralized_risk(features: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        "csf": _normalize(features.get("csf"), default=0.0),
        "network": _normalize(features.get("network"), default=0.0),
        "deviceUntrusted": _normalize(features.get("deviceUntrusted"), default=0.0),
        "geoFlag": _normalize(features.get("geoFlag"), default=0.0),
    }
    risk_score = calculate_centralized_risk(normalized)
    return {
        "inputs": normalized,
        "risk_score": risk_score,
        "tier": risk_tier_for_score(risk_score),
        "meaning": {
            "csf": "Behavioral/control signal severity normalized to 0-1.",
            "network": "Network anomaly risk normalized to 0-1.",
            "deviceUntrusted": "Device trust penalty for unrecognized or flagged devices normalized to 0-1.",
            "geoFlag": "Geo-location anomaly signal normalized to 0-1.",
        },
    }


def record_signals(
    user_id: str,
    *,
    behavioral_score: float,
    anomaly_score: float,
    classifier_label: str,
    classifier_confidence: float,
    device_id: str | None,
    device_trust_status: str,
    geo_score: float = 0.0,
    ip_address: str | None = None,
) -> dict[str, Any]:
    """Store the latest observed signals and compute their fused risk result."""
    _ensure_signals_loaded()
    signals = {
        "behavioral_score": _clamp(behavioral_score),
        "anomaly_score": _clamp(anomaly_score),
        "classifier_label": str(classifier_label),
        "classifier_confidence": _clamp(classifier_confidence),
        "device_id": device_id,
        "device_trust_status": device_trust_status,
        "geo_score": _clamp(geo_score),
        "ip_address": ip_address.strip() if isinstance(ip_address, str) and ip_address.strip() else None,
    }
    _latest_signals[user_id] = signals
    _persist_signals(user_id, signals)
    return compute_risk(user_id)


_REASON_TEXT = {
    "behavioral": "Behaviour differs from this user's normal pattern",
    "anomaly": "Isolation Forest flagged the activity as statistically unusual",
    "classifier": "A rule-based attack detection matched the activity",
    "device_trust": "The device is not trusted",
    "network": "Suspicious request patterns were seen in the last 15 minutes",
    "geo": "The login location looks unusual",
}


def explain_reasons(contributions: dict[str, float], exposure: dict[str, Any], score: float) -> list[str]:
    """Plain-language top reasons (max 3) for a score, built only from real contributions (F-19)."""
    items = [(value, key) for key, value in contributions.items() if value > 0]
    items.sort(reverse=True)
    reasons = [f"{_REASON_TEXT[key]} (+{value:.1f} points)" for value, key in items[:3]]
    if exposure.get("points", 0) > 0 and len(reasons) < 3:
        reasons.append(f"Denied access to protected asset {exposure['asset_id']} "
                       f"(criticality {exposure['criticality']}) (+{exposure['points']:.1f} points)")
    return reasons or [f"No risk signals above zero; score {score:.1f} reflects a quiet baseline"]


def compute_risk(user_id: str) -> dict[str, Any]:
    """Compute score, level, and signal-by-signal contributions for a user."""
    _ensure_signals_loaded()
    signals = _latest_signals.get(user_id, {})
    devices = list_devices(user_id)
    selected_device = next((item for item in devices if item["device_id"] == signals.get("device_id")), None)
    trust_status = selected_device["trust_status"] if selected_device else signals.get("device_trust_status", "unknown")
    # Analyst-confirmed bad device indicators feed the live scoring path.
    # Import lazily to avoid a module cycle between agents and the risk engine.
    known_bad_device = False
    device_id = signals.get("device_id")
    if device_id:
        try:
            from agents.learning import is_known_bad_indicator
            known_bad_device = is_known_bad_indicator("device", str(device_id))
        except Exception:
            # Fail closed on scoring enhancement only: keep the ordinary trust status.
            known_bad_device = False
    if known_bad_device:
        trust_status = "flagged"
    known_bad_ip = False
    ip_address = signals.get("ip_address")
    if ip_address:
        try:
            from agents.learning import is_known_bad_indicator
            known_bad_ip = is_known_bad_indicator("ip", str(ip_address))
        except Exception:
            known_bad_ip = False

    policy = risk_policy.get_policy()
    weights = policy["weights"]
    behavioral = _clamp(signals.get("behavioral_score", 0.0))
    anomaly = _clamp(signals.get("anomaly_score", 0.0))
    label = signals.get("classifier_label", "unknown")
    confidence = _clamp(signals.get("classifier_confidence", 0.0))
    classifier_signal = confidence if label.lower() not in {"benign", "unknown", ""} else 0.0
    device_penalty = DEVICE_PENALTY.get(trust_status, DEVICE_PENALTY["unknown"]) if policy["device_trust_enabled"] else 0.0
    geo_score = _clamp(signals.get("geo_score", 0.0)) if policy["geo_enabled"] else 0.0
    network = network_score_for_user(user_id)
    restrict_threshold = get_restrict_threshold()

    contributions = {
        "behavioral": round(behavioral * weights["behavioral"], 2),
        "anomaly": round(anomaly * weights["anomaly"], 2),
        "classifier": round(classifier_signal * weights["classifier"], 2),
        "device_trust": round(device_penalty * weights["device_trust"], 2),
        "network": round(network * weights["network"], 2),
        "geo": round(geo_score * weights["geo"], 2),
    }
    base_score = sum(contributions.values())
    sensitivity = policy["sensitivity"]
    adjustment = risk_policy.user_adjustment(user_id)
    exposure = exposure_points(user_id)
    # A confirmed malicious source IP adds a bounded, explicit 25-point signal.
    # It is additive after weighted fusion so default zero geo/network weights do not hide it.
    known_bad_ip_points = 25.0 if known_bad_ip else 0.0
    score = round(_clamp(base_score * sensitivity + adjustment + exposure["points"] + known_bad_ip_points), 2)
    level = "low" if score < 30 else "medium" if score < restrict_threshold else "high" if score <= BLOCK_THRESHOLD else "critical"

    return {
        "user_id": user_id,
        "score": score,
        "level": level,
        "thresholds": {"restrict": restrict_threshold, "block": BLOCK_THRESHOLD},
        "policy": {"version": policy["version"], "sensitivity": sensitivity, "device_trust_enabled": policy["device_trust_enabled"],
                   "geo_enabled": policy["geo_enabled"], "learning_rate": policy["learning_rate"]},
        "adjustments": {"base_score": round(base_score, 2), "sensitivity_multiplier": sensitivity, "analyst_feedback_points": adjustment,
                        "asset_criticality_points": exposure["points"], "asset_criticality_source": exposure["asset_id"],
                        "known_bad_ip_points": known_bad_ip_points},
        "reasons": (
            (["Device is on the analyst-confirmed known-bad indicator list"] if known_bad_device else [])
            + ([f"Source IP {ip_address} is on the analyst-confirmed known-bad list (+25 points)"] if known_bad_ip else [])
            + explain_reasons(contributions, exposure, score)
        )[:3],
        "known_bad_indicators": {"device_flagged": known_bad_device, "ip_flagged": known_bad_ip},
        "computed_at": datetime.now(timezone.utc).isoformat(),
        "breakdown": {
            "behavioral": {"score": behavioral, "weight": weights["behavioral"], "contribution": contributions["behavioral"]},
            "isolation_forest": {"score": anomaly, "weight": weights["anomaly"], "contribution": contributions["anomaly"]},
            "classifier": {"label": label, "confidence": confidence, "risk_score": classifier_signal, "weight": weights["classifier"], "contribution": contributions["classifier"]},
            "device_trust": {"status": trust_status, "penalty": device_penalty, "weight": weights["device_trust"], "contribution": contributions["device_trust"], "enabled": policy["device_trust_enabled"]},
            "network": {"score": network, "weight": weights["network"], "contribution": contributions["network"], "note": "Based on flagged request patterns observed in the last 15 minutes."},
            "geo": {"score": geo_score, "weight": weights["geo"], "contribution": contributions["geo"], "enabled": policy["geo_enabled"], "note": "Uses geo_score from ingested events; weight defaults to 0 until an admin raises it."},
            "physical": {"score": None, "weight": 0.0, "contribution": 0.0, "note": "Physical RF/CSI monitoring signal is not implemented."},
        },
        "device_id": signals.get("device_id"),
        "ip_address": signals.get("ip_address"),
    }


def get_signals(user_id: str) -> dict[str, Any]:
    _ensure_signals_loaded()
    return dict(_latest_signals.get(user_id, {}))


def list_known_users() -> list[str]:
    _ensure_signals_loaded()
    return sorted(_latest_signals)


def reset_risk_state() -> None:
    _ensure_signals_loaded()
    _latest_signals.clear()
    connection = get_db_connection()
    try:
        connection.execute("DELETE FROM risk_signals")
        connection.commit()
        risk_policy.reset_feedback()
    finally:
        connection.close()


def reset_user_risk(user_id: str) -> None:
    _ensure_signals_loaded()
    _latest_signals.pop(user_id, None)
    connection = get_db_connection()
    try:
        connection.execute("DELETE FROM risk_signals WHERE user_id = ?", (user_id,))
        connection.commit()
    finally:
        connection.close()
