"""Locate and load the real-data model, falling back to the synthetic-trained one."""
from __future__ import annotations

import json
import os
from typing import Any

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ml_models")
DEFAULT_MODEL = os.path.join(MODEL_DIR, "real_model.joblib")


def metadata_path(model_path: str) -> str:
    return os.path.splitext(model_path)[0] + ".json"


def synthetic_info(note: str | None = None) -> dict[str, Any]:
    info = {"source": "synthetic", "name": "isolation_forest_synthetic", "version": "synthetic-1",
            "data_source": "synthetic generated records", "trained_on_real_data": False}
    if note:
        info["degraded_note"] = note
    return info


def try_load_real_model(detector, path: str | None = None, expected_features: list[str] | None = None) -> dict[str, Any]:
    """Load the real-data model into ``detector`` (an OptimizedAnomalyDetector).

    Only call with a path you control: joblib files can execute code when loaded.
    On any problem the detector is left untouched and a synthetic info dict with a
    ``degraded_note`` is returned. The caller must have trained the synthetic model first.
    """
    path = path or os.environ.get("TRUSTNET_REAL_MODEL_PATH") or DEFAULT_MODEL
    if not os.path.isfile(path):
        return synthetic_info("Real-data model not found; using the synthetic-trained model.")
    try:
        with open(metadata_path(path), encoding="utf-8") as handle:
            meta = json.load(handle)
        features = expected_features or list(getattr(detector, "feature_names", []) or [])
        if features and meta.get("features") != features:
            return synthetic_info("Real-data model feature list does not match; using the synthetic-trained model.")
        candidate = type(detector)()
        candidate.load(path)
        if not candidate.trained:
            return synthetic_info("Real-data model file is not trained; using the synthetic-trained model.")
    except Exception as exc:  # corrupt file, missing metadata, version mismatch
        return synthetic_info(f"Real-data model could not be loaded ({type(exc).__name__}); using the synthetic-trained model.")
    detector.model, detector.scaler = candidate.model, candidate.scaler
    detector.feature_names, detector.metrics = candidate.feature_names, candidate.metrics
    detector.best_params, detector.trained = candidate.best_params, True
    return {"source": "real", "name": meta.get("name", "isolation_forest_real"), "version": meta.get("version"),
            "data_source": meta.get("dataset"), "trained_on_real_data": True, "rows": meta.get("rows"),
            "date_range": meta.get("date_range"), "trained_at": meta.get("trained_at")}
