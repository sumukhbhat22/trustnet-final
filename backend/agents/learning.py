"""Analyst-feedback learning with a measured, leave-one-out evaluation.

Learning only adjusts the Investigator's rule weights. It never changes enforcement
thresholds or autonomy settings. Learned weights are applied only when:
  * at least MIN_LABELS analyst verdicts exist, and
  * leave-one-out accuracy of the learned weights is not worse than the default weights.
Otherwise the default weights stay in force and the report says why.
"""

from __future__ import annotations

import json
import ipaddress
from typing import Any

from models.database import get_db_connection

DEFAULT_WEIGHTS: dict[str, float] = {
    "credential_attack": 0.30,
    "untrusted_device": 0.20,
    "multi_ip_activity": 0.15,
    "model_consensus": 0.25,
    "suspicious_request_pattern": 0.10,
}
MALICIOUS_THRESHOLD = 0.5
SUSPICIOUS_THRESHOLD = 0.25
MIN_LABELS = 10
MIN_RULE_OBSERVATIONS = 3


def _normalize_indicator_value(indicator_type: str, value: Any) -> str:
    """Normalize IP indicators so equivalent IPv4/IPv6 spellings match safely."""
    normalized = str(value).strip() if value is not None else ""
    if indicator_type != "ip" or not normalized:
        return normalized
    # Accept a bracketed IPv6 literal (without a port); do not guess at host:port.
    candidate = normalized
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        address = ipaddress.ip_address(candidate)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            return str(address.ipv4_mapped)
        return address.compressed.lower()
    except ValueError:
        # Keep legacy/non-IP indicators unchanged; invalid values will not match a
        # differently formatted valid address.
        return normalized


def latest_labels() -> list[dict[str, Any]]:
    """Most recent analyst verdict per incident."""
    connection = get_db_connection()
    try:
        rows = connection.execute(
            """SELECT f.* FROM analyst_feedback f
               WHERE f.rowid = (SELECT MAX(rowid) FROM analyst_feedback WHERE incident_id = f.incident_id)
               ORDER BY f.created_at"""
        ).fetchall()
    finally:
        connection.close()
    labels = []
    for row in rows:
        item = dict(row)
        item["rules_fired"] = json.loads(item["rules_fired"] or "[]")
        labels.append(item)
    return labels


def _weights_from(labels: list[dict[str, Any]]) -> dict[str, float]:
    adjusted = dict(DEFAULT_WEIGHTS)
    for rule_id in DEFAULT_WEIGHTS:
        tp = sum(1 for l in labels if rule_id in l["rules_fired"] and l["verdict"] == "true_positive")
        fp = sum(1 for l in labels if rule_id in l["rules_fired"] and l["verdict"] == "false_positive")
        if tp + fp < MIN_RULE_OBSERVATIONS:
            continue
        precision = (tp + 1) / (tp + fp + 2)
        adjusted[rule_id] = DEFAULT_WEIGHTS[rule_id] * min(2.0, max(0.25, precision / 0.5))
    total = sum(adjusted.values())
    return {key: value / total for key, value in adjusted.items()}


def confidence_for(fired: list[str], weights: dict[str, float]) -> float:
    return round(sum(weights.get(rule_id, 0.0) for rule_id in set(fired)), 4)


def _accuracy(labels: list[dict[str, Any]], weights_for: Any) -> float:
    correct = 0
    for index, label in enumerate(labels):
        weights = weights_for(index)
        predicted_malicious = confidence_for(label["rules_fired"], weights) >= SUSPICIOUS_THRESHOLD
        correct += predicted_malicious == (label["verdict"] == "true_positive")
    return correct / len(labels)


def evaluate() -> dict[str, Any]:
    """Return the measured learning result (leave-one-out accuracy, default vs learned weights)."""
    labels = latest_labels()
    n = len(labels)
    positives = sum(1 for l in labels if l["verdict"] == "true_positive")
    report: dict[str, Any] = {
        "labeled_incidents": n, "true_positives": positives, "false_positives": n - positives,
        "min_labels_required": MIN_LABELS, "default_weights": DEFAULT_WEIGHTS,
        "learned_weights": None, "active_weights": dict(DEFAULT_WEIGHTS),
        "default_accuracy": None, "learned_accuracy": None, "accuracy_delta": None,
        "applied": False, "status": "insufficient_data",
        "method": "leave-one-out over analyst-labeled incidents; prediction is 'malicious' when confidence >= suspicious threshold",
    }
    if n == 0:
        report["note"] = "No analyst verdicts yet."
        return report
    default_acc = _accuracy(labels, lambda _i: DEFAULT_WEIGHTS)
    report["default_accuracy"] = round(default_acc, 4)
    if n < MIN_LABELS:
        report["note"] = f"{n}/{MIN_LABELS} verdicts; default weights remain active."
        return report
    learned_acc = _accuracy(labels, lambda i: _weights_from(labels[:i] + labels[i + 1:]))
    full = _weights_from(labels)
    report.update({
        "learned_weights": {k: round(v, 4) for k, v in full.items()},
        "learned_accuracy": round(learned_acc, 4),
        "accuracy_delta": round(learned_acc - default_acc, 4),
    })
    if learned_acc >= default_acc:
        report.update({"applied": True, "status": "applied", "active_weights": report["learned_weights"],
                       "note": "Learned weights are not worse than defaults on leave-one-out evaluation."})
    else:
        report.update({"status": "rejected",
                       "note": "Learned weights scored worse than defaults on leave-one-out evaluation; defaults kept."})
    return report


def active_weights() -> dict[str, float]:
    return evaluate()["active_weights"]



def update_behavior_profile(incident: dict[str, Any], verdict: str, *, alpha: float = 0.2) -> dict[str, Any]:
    """Persist a transparent EMA profile and analyst-confirmed bad indicators.

    This is a demo profile update, not a trained ML model. Only explicit true-positive
    labels add device/IP indicators; false-positive labels do not automatically trust a device.
    """
    if verdict not in {"true_positive", "false_positive"}:
        raise ValueError("Unsupported verdict")
    if not 0 < alpha <= 1:
        raise ValueError("alpha must be in (0, 1]")
    connection = get_db_connection()
    try:
        connection.execute("""CREATE TABLE IF NOT EXISTS behavior_profiles (
            user_id TEXT PRIMARY KEY, risk_ema REAL NOT NULL DEFAULT 0,
            baseline_version INTEGER NOT NULL DEFAULT 1, sample_count INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL)""")
        connection.execute("""CREATE TABLE IF NOT EXISTS known_bad_indicators (
            indicator_type TEXT NOT NULL, indicator_value TEXT NOT NULL, incident_id TEXT NOT NULL,
            created_at TEXT NOT NULL, PRIMARY KEY(indicator_type, indicator_value))""")
        user_id = str(incident.get("user_id") or "")
        score = max(0.0, min(100.0, float(incident.get("risk_score") or 0)))
        now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
        profile = None
        if user_id:
            old = connection.execute("SELECT * FROM behavior_profiles WHERE user_id=?", (user_id,)).fetchone()
            old_ema = float(old["risk_ema"]) if old else score
            new_ema = (1 - alpha) * old_ema + alpha * (score if verdict == "true_positive" else 0.0)
            version = int(old["baseline_version"]) + 1 if old else 1
            count = int(old["sample_count"]) + 1 if old else 1
            connection.execute("""INSERT INTO behavior_profiles(user_id,risk_ema,baseline_version,sample_count,updated_at)
                VALUES(?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET risk_ema=excluded.risk_ema,
                baseline_version=excluded.baseline_version,sample_count=excluded.sample_count,updated_at=excluded.updated_at""",
                (user_id, new_ema, version, count, now))
            profile = {"user_id": user_id, "risk_ema_before": round(old_ema, 2),
                       "risk_ema_after": round(new_ema, 2), "baseline_version": version,
                       "sample_count": count, "alpha": alpha,
                       "effect": "lowered" if new_ema < old_ema else ("raised" if new_ema > old_ema else "unchanged")}
        indicators = []
        if verdict == "true_positive":
            for kind, value in (("device", incident.get("device_id")), ("ip", incident.get("ip_address"))):
                if value:
                    canonical_value = _normalize_indicator_value(kind, value)
                    connection.execute("INSERT OR IGNORE INTO known_bad_indicators(indicator_type,indicator_value,incident_id,created_at) VALUES(?,?,?,?)",
                                       (kind, canonical_value, str(incident.get("id") or "unknown"), now))
                    indicators.append({"type": kind, "value": canonical_value})
        connection.commit()
        return {"profile": profile, "known_bad_added": indicators,
                "note": "EMA profile and indicators are demo learning signals; no ML model was retrained."}
    finally:
        connection.close()


def get_behavior_profile(user_id: str) -> dict[str, Any] | None:
    connection = get_db_connection()
    try:
        connection.execute("""CREATE TABLE IF NOT EXISTS behavior_profiles (
            user_id TEXT PRIMARY KEY, risk_ema REAL NOT NULL DEFAULT 0,
            baseline_version INTEGER NOT NULL DEFAULT 1, sample_count INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL)""")
        row = connection.execute("SELECT * FROM behavior_profiles WHERE user_id=?", (user_id,)).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def latest_feedback_for_incident(incident_id: str) -> dict[str, Any] | None:
    """Return the most recent persisted verdict for an incident, if any."""
    items = list_feedback(incident_id)
    return items[-1] if items else None


def is_duplicate_verdict(existing: dict[str, Any] | None, verdict: str) -> bool:
    """A repeated identical verdict is idempotent; a different verdict can correct it."""
    return bool(existing and existing.get("verdict") == verdict)


def record_feedback(feedback: dict[str, Any]) -> None:
    connection = get_db_connection()
    try:
        connection.execute(
            "INSERT INTO analyst_feedback (id, incident_id, verdict, notes, analyst_id, rules_fired, investigator_confidence, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (feedback["id"], feedback["incident_id"], feedback["verdict"], feedback["notes"], feedback["analyst_id"],
             json.dumps(feedback["rules_fired"]), feedback["investigator_confidence"], feedback["created_at"]),
        )
        connection.commit()
    finally:
        connection.close()


def list_feedback(incident_id: str) -> list[dict[str, Any]]:
    connection = get_db_connection()
    try:
        rows = connection.execute(
            "SELECT * FROM analyst_feedback WHERE incident_id = ? ORDER BY created_at, rowid", (incident_id,)
        ).fetchall()
    finally:
        connection.close()
    items = []
    for row in rows:
        item = dict(row)
        item["rules_fired"] = json.loads(item["rules_fired"] or "[]")
        items.append(item)
    return items


def known_bad_indicators(*, indicator_type: str | None = None) -> list[dict[str, Any]]:
    """Return analyst-confirmed indicators for risk scoring and investigation.

    Values are compared exactly; callers should not pass raw untrusted SQL fragments.
    """
    connection = get_db_connection()
    try:
        connection.execute("""CREATE TABLE IF NOT EXISTS known_bad_indicators (
            indicator_type TEXT NOT NULL, indicator_value TEXT NOT NULL, incident_id TEXT NOT NULL,
            created_at TEXT NOT NULL, PRIMARY KEY(indicator_type, indicator_value))""")
        if indicator_type:
            rows = connection.execute(
                "SELECT indicator_type, indicator_value, incident_id, created_at FROM known_bad_indicators WHERE indicator_type=? ORDER BY created_at DESC",
                (indicator_type,),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT indicator_type, indicator_value, incident_id, created_at FROM known_bad_indicators ORDER BY created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def is_known_bad_indicator(indicator_type: str, value: Any) -> bool:
    """True only for a non-empty exact indicator previously confirmed by an analyst."""
    if value is None or not str(value).strip():
        return False
    canonical_value = _normalize_indicator_value(indicator_type, value)
    connection = get_db_connection()
    try:
        connection.execute("""CREATE TABLE IF NOT EXISTS known_bad_indicators (
            indicator_type TEXT NOT NULL, indicator_value TEXT NOT NULL, incident_id TEXT NOT NULL,
            created_at TEXT NOT NULL, PRIMARY KEY(indicator_type, indicator_value))""")
        row = connection.execute(
            "SELECT 1 FROM known_bad_indicators WHERE indicator_type=? AND indicator_value=? LIMIT 1",
            (indicator_type, canonical_value),
        ).fetchone()
        return row is not None
    finally:
        connection.close()


def build_incident_replay(incident_id: str, incident: dict[str, Any] | None,
                         score_effect: dict[str, Any] | None,
                         profile: dict[str, Any] | None) -> dict[str, Any]:
    """Build a transparent before/after feedback replay for the analyst UI/API.

    Scores are reported only when recorded by the verdict workflow; this helper does not
    invent a counterfactual or claim that a model was retrained.
    """
    if not incident:
        raise ValueError("Incident not found")
    if not score_effect:
        return {
            "incident_id": incident_id, "status": "no_feedback_effect",
            "incident_score": incident.get("risk_score"),
            "verdict": None, "score_before": None, "score_after": None,
            "score_delta": None, "policy_version": None,
            "profile": profile,
            "message": "No persisted verdict score comparison exists for this incident yet.",
            "learning_type": "bounded rule adjustment; no ML model retraining",
        }
    before = score_effect.get("score_before")
    after = score_effect.get("score_after")
    delta = None if before is None or after is None else round(float(after) - float(before), 2)
    return {
        "incident_id": incident_id, "status": "recorded",
        "incident_score": incident.get("risk_score"),
        "verdict": score_effect.get("verdict"),
        "score_before": before, "score_after": after, "score_delta": delta,
        "policy_version": score_effect.get("policy_version"),
        "user_adjustment": score_effect.get("delta"),
        "profile": profile,
        "message": "Before/after scores are persisted workflow observations, not proof of model retraining or causal accuracy improvement.",
        "learning_type": "bounded rule adjustment; no ML model retraining",
    }
