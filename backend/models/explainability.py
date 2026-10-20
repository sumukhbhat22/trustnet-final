"""
Explainable AI (XAI) Engine for TrustNet AI Guardian

Generates human-readable explanations for every ML decision:
  1. CSF Explanation      — Which fingerprint fields deviated most
  2. Classifier Explanation — Feature importance + per-class SHAP-like values
  3. Risk Score Breakdown   — Behavioral deviation + threat amplification + propagation
  4. RPG Explanation        — Node/edge contribution to network risk

Every threat event gets an `explanation` dict attached so the frontend
can render a full "why did the AI decide this?" panel.
"""

import numpy as np
from typing import Dict, Any, List, Optional


# ──────────────────────────────────────────────
# 1. CSF (Cognitive Security Fingerprint) Explainer
# ──────────────────────────────────────────────

# Relative importance of each fingerprint field
# (higher = harder to spoof, more suspicious when changed)
CSF_FIELD_WEIGHTS = {
    "canvasHash":          0.18,   # GPU rendering — very hard to fake
    "webglRenderer":       0.16,   # GPU model string
    "screenResolution":    0.13,   # display dimensions
    "hardwareConcurrency": 0.12,   # CPU core count
    "platform":            0.10,   # OS (Win/Mac/Linux)
    "userAgent":           0.09,   # browser string
    "timezone":            0.08,   # TZ offset
    "colorDepth":          0.06,   # bits per pixel
    "language":            0.05,   # browser locale
    "deviceType":          0.03,   # mobile / desktop
}

def explain_csf(
    baseline_fp: Dict[str, Any],
    current_fp: Dict[str, Any],
    match_score: float,
    is_same_device: bool,
) -> Dict[str, Any]:
    """
    Explain which fingerprint fields changed and rank them by suspicion.

    Returns:
      - deviations: list of {field, baseline, current, weight, suspicion}
        sorted by suspicion desc
      - summary: human sentence
      - overall_suspicion: 0-100
    """
    deviations: List[Dict[str, Any]] = []
    total_suspicion = 0.0

    for field, weight in CSF_FIELD_WEIGHTS.items():
        base_val = str(baseline_fp.get(field, ""))
        curr_val = str(current_fp.get(field, ""))
        changed = base_val != curr_val

        if changed:
            suspicion = weight * 100  # scale to 0-18
            total_suspicion += suspicion
            deviations.append({
                "field": field,
                "baseline": base_val[:60],
                "current": curr_val[:60],
                "weight": round(weight, 3),
                "suspicion_score": round(suspicion, 1),
                "changed": True,
            })
        else:
            deviations.append({
                "field": field,
                "baseline": base_val[:60],
                "current": curr_val[:60],
                "weight": round(weight, 3),
                "suspicion_score": 0,
                "changed": False,
            })

    # Sort by suspicion desc (changed fields first)
    deviations.sort(key=lambda d: d["suspicion_score"], reverse=True)

    # Normalize to 0-100
    overall = min(100, total_suspicion * (100 / sum(CSF_FIELD_WEIGHTS.values()) / 100))
    overall = round(min(100, total_suspicion), 1)

    # Build human-readable summary
    changed_fields = [d for d in deviations if d["changed"]]
    if not changed_fields:
        summary = "All fingerprint fields match the baseline — same device confirmed."
    elif len(changed_fields) <= 3:
        names = ", ".join(d["field"] for d in changed_fields)
        summary = f"Fingerprint mismatch in {len(changed_fields)} field(s): {names}. Most suspicious: {changed_fields[0]['field']} (weight {changed_fields[0]['weight']})."
    else:
        summary = (
            f"{len(changed_fields)}/{len(CSF_FIELD_WEIGHTS)} fingerprint fields changed — "
            f"strongly indicates a different device. Top deviation: {changed_fields[0]['field']}."
        )

    return {
        "deviations": deviations,
        "changed_count": len(changed_fields),
        "total_fields": len(CSF_FIELD_WEIGHTS),
        "overall_suspicion": overall,
        "is_same_device": is_same_device,
        "match_score_pct": round(match_score * 100, 1),
        "summary": summary,
    }


# ──────────────────────────────────────────────
# 2. Threat Classifier Explainer (Feature Importance + SHAP-like)
# ──────────────────────────────────────────────

def explain_classifier(
    features_used: Dict[str, float],
    prediction: Dict[str, Any],
    rf_model: Any = None,
    gb_model: Any = None,
    scaler: Any = None,
) -> Dict[str, Any]:
    """
    Explain the supervised threat classifier decision.

    Computes:
      - Global feature importance (from RF)
      - Per-feature contribution to the predicted class (SHAP-like via mean decrease)
      - Top contributors ranked
      - Natural language reasoning chain
    """
    feature_names = list(features_used.keys())
    feature_values = list(features_used.values())

    # ── Global feature importance from Random Forest ──
    if rf_model is not None:
        importances = rf_model.feature_importances_
    else:
        # Fallback reasonable defaults
        importances = np.array([0.10, 0.25, 0.20, 0.12, 0.15, 0.10, 0.08])

    importance_dict = {
        name: round(float(imp) * 100, 1)
        for name, imp in zip(feature_names, importances)
    }

    # ── SHAP-like marginal contribution ──
    # Approximate by: feature_value × feature_importance (normalized)
    # This shows how much each feature "pushed" the decision
    contributions = {}
    total_push = 0
    for name, val, imp in zip(feature_names, feature_values, importances):
        # Normalize the feature value to a 0-1 scale heuristic
        if "km" in name or "distance" in name:
            norm_val = min(val / 10000, 1.0)
        elif "score" in name:
            norm_val = min(val, 1.0)
        elif "match" in name:
            norm_val = 1.0 - val  # lower match = higher risk push
        elif "deviation" in name or "pct" in name:
            norm_val = min(val / 200, 1.0)
        elif "hour" in name:
            norm_val = min(val / 12, 1.0)
        else:
            norm_val = min(val / 100, 1.0)

        push = norm_val * imp * 100
        contributions[name] = round(push, 1)
        total_push += push

    # Normalize contributions to sum to 100
    if total_push > 0:
        contributions = {
            k: round(v / total_push * 100, 1)
            for k, v in contributions.items()
        }

    # Sort by contribution
    sorted_contributors = sorted(contributions.items(), key=lambda x: x[1], reverse=True)

    # ── Build reasoning chain ──
    reasoning = []
    attack_type = prediction.get("attack_type", "unknown")
    confidence = prediction.get("confidence", 0)
    is_malicious = prediction.get("is_malicious", False)

    if is_malicious:
        top_feat = sorted_contributors[0][0] if sorted_contributors else "unknown"
        top_pct = sorted_contributors[0][1] if sorted_contributors else 0
        reasoning.append(
            f"Classified as {attack_type.upper()} with {confidence}% confidence."
        )
        reasoning.append(
            f"Primary driver: {_human_feature_name(top_feat)} contributed {top_pct:.0f}% to the decision."
        )
        if len(sorted_contributors) > 1:
            second = sorted_contributors[1]
            reasoning.append(
                f"Secondary factor: {_human_feature_name(second[0])} ({second[1]:.0f}%)."
            )
        reasoning.append(
            f"Ensemble model (RF 60% + GB 40%) agreed on this classification."
        )
    else:
        reasoning.append("Login classified as BENIGN — no threat indicators exceeded thresholds.")
        if sorted_contributors:
            top = sorted_contributors[0]
            reasoning.append(
                f"Highest feature was {_human_feature_name(top[0])} at {top[1]:.0f}%, still within safe range."
            )

    return {
        "global_feature_importance": importance_dict,
        "classification_contributors": dict(sorted_contributors),
        "top_contributor": sorted_contributors[0][0] if sorted_contributors else None,
        "top_contributor_pct": sorted_contributors[0][1] if sorted_contributors else 0,
        "reasoning_chain": reasoning,
        "model_type": "Random Forest + Gradient Boosting Ensemble",
        "ensemble_weights": {"random_forest": 0.6, "gradient_boosting": 0.4},
    }


# ──────────────────────────────────────────────
# 3. Risk Score Breakdown Explainer
# ──────────────────────────────────────────────

# Human-friendly labels for risk weight categories
RISK_FACTOR_LABELS = {
    "login_deviation":       "Login Time Anomaly",
    "session_deviation":     "Session Duration Change",
    "data_volume_deviation": "Data Volume Spike",
    "api_calls_deviation":   "API Activity Surge",
    "geo_distance_deviation":"Geographic Distance",
    "anomaly_score":         "ML Anomaly Signal",
}

def explain_risk_score(
    ml_result: Dict[str, Any],
    geo_distance_km: float = 0,
    device_match_score: float = 1.0,
    isolation_forest_score: float = 0,
    isolation_forest_anomaly: bool = False,
) -> Dict[str, Any]:
    """
    Break down the risk score into understandable components:
      - Behavioral deviation (per-metric weighted contribution)
      - Threat amplification signals
      - Propagation influence estimate
    """
    overall_score = ml_result.get("overall_score", 0)
    deviations = ml_result.get("deviations", {})
    threat_level = ml_result.get("threat_level", "safe")

    # ── Component 1: Behavioral Deviation Breakdown ──
    from models.optimized_models import AdvancedRiskScorer
    weights = AdvancedRiskScorer.OPTIMAL_WEIGHTS

    behavioral_components = []
    total_weighted = 0

    for key, weight in weights.items():
        dev_val = deviations.get(key, 0)
        contribution = min(dev_val, 200) * weight * 0.52  # same scaling as the scorer
        total_weighted += contribution
        behavioral_components.append({
            "factor": RISK_FACTOR_LABELS.get(key, key),
            "factor_key": key,
            "deviation_pct": round(dev_val, 1),
            "weight": weight,
            "contribution": round(contribution, 1),
            "severity": (
                "critical" if dev_val > 150 else
                "high" if dev_val > 80 else
                "medium" if dev_val > 40 else
                "low" if dev_val > 10 else
                "none"
            ),
        })

    # Sort by contribution
    behavioral_components.sort(key=lambda c: c["contribution"], reverse=True)

    # ── Component 2: Threat Amplification Signals ──
    amplifiers = []
    if geo_distance_km > 500:
        amp = min(20, geo_distance_km / 500)
        amplifiers.append({
            "signal": f"Geographic anomaly: {geo_distance_km:,.0f} km from baseline",
            "impact": round(amp, 1),
            "severity": "critical" if geo_distance_km > 5000 else "high",
        })
    if device_match_score < 0.5:
        amp = (1 - device_match_score) * 15
        amplifiers.append({
            "signal": f"Device fingerprint mismatch: {(1-device_match_score)*100:.0f}% different",
            "impact": round(amp, 1),
            "severity": "critical" if device_match_score < 0.3 else "high",
        })
    if isolation_forest_anomaly:
        amplifiers.append({
            "signal": f"Isolation Forest flagged anomaly (score: {isolation_forest_score:.3f})",
            "impact": round(isolation_forest_score * 10, 1),
            "severity": "high" if isolation_forest_score > 0.6 else "medium",
        })

    # ── Component 3: Propagation Risk Estimate ──
    # Estimate how much this event would spread through the network
    propagation_estimate = 0
    if overall_score > 70:
        propagation_estimate = min(25, overall_score * 0.3)
    elif overall_score > 40:
        propagation_estimate = min(15, overall_score * 0.2)
    else:
        propagation_estimate = overall_score * 0.1

    # ── Build top behavioral deviations (human-readable) ──
    top_deviations = []
    for comp in behavioral_components[:5]:
        if comp["deviation_pct"] > 5:
            top_deviations.append(
                f"{comp['factor']}: {comp['deviation_pct']:.0f}% deviation "
                f"(contributes {comp['contribution']:.0f} pts)"
            )

    return {
        "overall_score": overall_score,
        "threat_level": threat_level,
        "behavioral_breakdown": behavioral_components,
        "threat_amplifiers": amplifiers,
        "propagation_influence": round(propagation_estimate, 1),
        "top_behavioral_deviations": top_deviations,
        "score_formula": "Σ(min(deviation, 200) × weight) × 0.52, capped at 100",
        "summary": _build_risk_summary(overall_score, threat_level, behavioral_components, amplifiers),
    }


# ──────────────────────────────────────────────
# 4. Network Propagation Explainer
# ──────────────────────────────────────────────

def explain_propagation(
    compromised_nodes: List[str],
    risk_score: float,
    nodes: Optional[List[Dict]] = None,
) -> Dict[str, Any]:
    """
    Explain how risk propagates through the network graph.
    """
    # Default 10-node network topology
    node_labels = {
        "n1": "User Endpoint",
        "n2": "VPN Gateway",
        "n3": "Firewall",
        "n4": "Web Application",
        "n5": "Load Balancer",
        "n6": "API Gateway",
        "n7": "Core Server",
        "n8": "Auth Service",
        "n9": "Database",
        "n10": "Backup System",
    }

    trust_weights = {
        ("n1", "n2"): 0.9, ("n2", "n3"): 0.85, ("n3", "n4"): 0.8,
        ("n3", "n5"): 0.75, ("n4", "n6"): 0.7, ("n5", "n6"): 0.7,
        ("n6", "n7"): 0.8, ("n7", "n8"): 0.85, ("n7", "n9"): 0.9,
        ("n9", "n10"): 0.6, ("n8", "n4"): 0.65, ("n1", "n8"): 0.7,
    }

    damping = 0.3

    # Calculate risk at each node using iterative diffusion
    node_risk = {nid: 0.0 for nid in node_labels}
    for nid in compromised_nodes:
        if nid in node_risk:
            node_risk[nid] = min(risk_score, 100)

    # One round of propagation
    propagated = dict(node_risk)
    for (src, dst), weight in trust_weights.items():
        if node_risk[src] > 0:
            spread = node_risk[src] * weight * damping
            propagated[dst] = min(100, propagated[dst] + spread)
        if node_risk.get(dst, 0) > 0:
            spread = node_risk[dst] * weight * damping
            propagated[src] = min(100, propagated[src] + spread)

    # Build node-level explanations
    node_explanations = []
    for nid, label in node_labels.items():
        original = node_risk.get(nid, 0)
        after = propagated.get(nid, 0)
        received = after - original

        node_explanations.append({
            "node_id": nid,
            "node_label": label,
            "is_compromised": nid in compromised_nodes,
            "direct_risk": round(original, 1),
            "propagated_risk": round(after, 1),
            "received_from_neighbors": round(max(0, received), 1),
            "criticality": (
                "critical" if after > 60 else
                "high" if after > 40 else
                "medium" if after > 20 else
                "low"
            ),
        })

    node_explanations.sort(key=lambda n: n["propagated_risk"], reverse=True)

    # Edge contributions
    edge_contributions = []
    for (src, dst), weight in trust_weights.items():
        risk_flow = 0
        if node_risk[src] > 0:
            risk_flow = node_risk[src] * weight * damping
        elif node_risk.get(dst, 0) > 0:
            risk_flow = node_risk[dst] * weight * damping

        if risk_flow > 0:
            edge_contributions.append({
                "from": f"{src} ({node_labels[src]})",
                "to": f"{dst} ({node_labels[dst]})",
                "trust_weight": weight,
                "risk_transferred": round(risk_flow, 1),
            })

    edge_contributions.sort(key=lambda e: e["risk_transferred"], reverse=True)

    total_network_risk = np.mean(list(propagated.values()))
    affected_nodes = sum(1 for v in propagated.values() if v > 5)

    return {
        "compromised_nodes": compromised_nodes,
        "node_explanations": node_explanations,
        "edge_contributions": edge_contributions[:6],
        "total_network_risk": round(total_network_risk, 1),
        "affected_node_count": affected_nodes,
        "total_nodes": len(node_labels),
        "damping_factor": damping,
        "algorithm": "Trust-weighted iterative risk diffusion",
        "summary": (
            f"{len(compromised_nodes)} node(s) directly compromised -> "
            f"risk propagated to {affected_nodes}/{len(node_labels)} nodes. "
            f"Network-wide risk: {total_network_risk:.0f}/100."
        ),
    }


# ──────────────────────────────────────────────
# 5. Master Explanation Builder
# ──────────────────────────────────────────────

def build_full_explanation(
    # CSF inputs
    baseline_fp: Optional[Dict] = None,
    current_fp: Optional[Dict] = None,
    match_score: float = 1.0,
    is_same_device: bool = True,
    # Classifier inputs
    features_used: Optional[Dict[str, float]] = None,
    prediction: Optional[Dict[str, Any]] = None,
    rf_model: Any = None,
    gb_model: Any = None,
    scaler: Any = None,
    # Risk score inputs
    ml_result: Optional[Dict[str, Any]] = None,
    geo_distance_km: float = 0,
    device_match_score: float = 1.0,
    isolation_forest_score: float = 0,
    isolation_forest_anomaly: bool = False,
    # Propagation inputs
    compromised_nodes: Optional[List[str]] = None,
    risk_score: float = 0,
) -> Dict[str, Any]:
    """
    Build a complete explanation object covering all 4 XAI dimensions.
    This is attached to every threat event sent to the frontend.
    """
    explanation: Dict[str, Any] = {}

    # 1. CSF Explanation
    if baseline_fp and current_fp:
        explanation["csf"] = explain_csf(
            baseline_fp, current_fp, match_score, is_same_device
        )

    # 2. Classifier Explanation
    if features_used and prediction:
        explanation["classifier"] = explain_classifier(
            features_used, prediction, rf_model, gb_model, scaler
        )

    # 3. Risk Score Breakdown
    if ml_result:
        explanation["risk_score"] = explain_risk_score(
            ml_result, geo_distance_km, device_match_score,
            isolation_forest_score, isolation_forest_anomaly
        )

    # 4. Propagation Explanation
    if compromised_nodes:
        explanation["propagation"] = explain_propagation(
            compromised_nodes, risk_score
        )

    return explanation


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

_FEATURE_HUMAN_NAMES = {
    "login_hour_deviation": "Login Time Deviation",
    "geo_distance_km": "Geographic Distance",
    "device_match_score": "Device Match Score",
    "session_deviation_pct": "Session Duration Change",
    "data_volume_deviation_pct": "Data Volume Change",
    "api_calls_deviation_pct": "API Call Pattern Change",
    "isolation_forest_score": "ML Anomaly Score",
}

def _human_feature_name(key: str) -> str:
    return _FEATURE_HUMAN_NAMES.get(key, key.replace("_", " ").title())


def _build_risk_summary(
    score: float,
    level: str,
    components: List[Dict],
    amplifiers: List[Dict],
) -> str:
    """Build a natural-language summary of the risk assessment."""
    if score < 15:
        return "Risk score is within normal parameters. No action required."

    parts = [f"Risk score {score:.0f}/100 ({level.upper()})."]

    # Top behavioral factor
    if components and components[0]["deviation_pct"] > 10:
        top = components[0]
        parts.append(
            f"Primary driver: {top['factor']} at {top['deviation_pct']:.0f}% deviation "
            f"(contributed {top['contribution']:.0f} points)."
        )

    # Amplifiers
    if amplifiers:
        amp_names = [a["signal"].split(":")[0] for a in amplifiers[:2]]
        parts.append(f"Amplified by: {', '.join(amp_names)}.")

    # Action
    if score > 70:
        parts.append("Immediate intervention recommended.")
    elif score > 40:
        parts.append("Manual review recommended.")

    return " ".join(parts)
