"""Deterministic, synthetic-only CSI fingerprint demonstration.

This module deliberately has no persistence, network, risk-engine, or incident
dependencies. A future hardware adapter can provide captured features to
compare_feature_vectors without changing the production risk pipeline.
"""

from __future__ import annotations

from datetime import datetime, timezone
import math
from typing import Sequence

_REFERENCE_FEATURES = (0.80, 0.20, 0.50, 0.10, 0.70)
_SCENARIOS = {
    "match": (0.79, 0.21, 0.49, 0.11, 0.68),
    "mismatch": (0.10, 0.80, 0.10, 0.90, 0.20),
}
_MATCH_THRESHOLD = 0.85


def _cosine_similarity(reference: Sequence[float], test: Sequence[float]) -> float:
    if len(reference) != len(test) or not reference:
        raise ValueError("Fingerprint feature vectors must have the same non-zero length.")
    reference_norm = math.sqrt(sum(value * value for value in reference))
    test_norm = math.sqrt(sum(value * value for value in test))
    if reference_norm == 0 or test_norm == 0:
        raise ValueError("Fingerprint feature vectors must have a non-zero magnitude.")
    return max(0.0, min(1.0, sum(a * b for a, b in zip(reference, test)) / (reference_norm * test_norm)))


def compare_feature_vectors(reference: Sequence[float], test: Sequence[float]) -> dict[str, float | str]:
    """Compare supplied fingerprint features without making security decisions."""
    similarity = round(_cosine_similarity(reference, test) * 100, 2)
    return {
        "similarity_score": similarity,
        "result": "MATCH" if similarity >= _MATCH_THRESHOLD * 100 else "MISMATCH",
    }


def generate_simulated_sample(scenario: str) -> dict:
    """Generate one reproducible synthetic scenario; never reads hardware."""
    if scenario not in _SCENARIOS:
        raise ValueError("scenario must be 'match' or 'mismatch'.")

    test_features = _SCENARIOS[scenario]
    comparison = compare_feature_vectors(_REFERENCE_FEATURES, test_features)
    matched = comparison["result"] == "MATCH"
    return {
        "sample_id": f"CSI-SIM-{scenario.upper()}-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scenario": scenario.upper(),
        "reference_fingerprint": list(_REFERENCE_FEATURES),
        "test_fingerprint": list(test_features),
        "similarity_score": comparison["similarity_score"],
        "result": comparison["result"],
        "explanation": (
            "Synthetic feature vectors exceed the demonstration similarity threshold."
            if matched
            else "Synthetic feature vectors are below the demonstration similarity threshold."
        ),
        "simulation_only": True,
        "hardware_connected": False,
    }
