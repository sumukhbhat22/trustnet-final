"""Reproducible holdout evaluation on fictional synthetic behavior records."""

from __future__ import annotations

import contextlib
import io
import json

from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from models.optimized_models import OptimizedAnomalyDetector

SEED = 42
FEATURES = [
    "session_duration",
    "data_volume",
    "api_calls",
    "geo_distance",
    "login_hour",
]


def _metrics(expected_anomaly, predicted_anomaly):
    matrix = confusion_matrix(expected_anomaly, predicted_anomaly, labels=[0, 1])
    tn, fp, fn, tp = [int(value) for value in matrix.ravel()]
    return {
        "accuracy": round(float(accuracy_score(expected_anomaly, predicted_anomaly)), 4),
        "precision": round(float(precision_score(expected_anomaly, predicted_anomaly, zero_division=0)), 4),
        "recall": round(float(recall_score(expected_anomaly, predicted_anomaly, zero_division=0)), 4),
        "f1": round(float(f1_score(expected_anomaly, predicted_anomaly, zero_division=0)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        "confusion_matrix_labels_0_1": matrix.tolist(),
        "alerts": int(predicted_anomaly.sum()),
        "actual_anomalies": int(expected_anomaly.sum()),
        "true_positive_incidents": tp,
        "false_alerts": fp,
        "missed_anomalies": fn,
    }


def _rules_only_baseline(samples):
    """Transparent baseline thresholds; not a trained or production rule engine."""
    session_duration = samples[:, 0]
    data_volume = samples[:, 1]
    api_calls = samples[:, 2]
    geo_distance = samples[:, 3]
    login_hour = samples[:, 4]
    return ((session_duration > 7.0) | (data_volume > 260) |
            (api_calls > 330) | (geo_distance > 82) | (login_hour > 18.5)).astype(int)


def main() -> None:
    detector = OptimizedAnomalyDetector()
    samples, labels = detector.generate_training_data(5000)
    train_samples, test_samples, train_labels, test_labels = train_test_split(
        samples,
        labels,
        test_size=0.2,
        random_state=SEED,
        stratify=labels,
    )

    with contextlib.redirect_stdout(io.StringIO()):
        training = detector.train(
            X=train_samples,
            y=train_labels,
            feature_names=FEATURES,
        )
    if training.get("status") != "success":
        raise RuntimeError(training.get("message", "Synthetic anomaly model training failed."))

    model_predictions, anomaly_scores = detector.predict(test_samples)
    expected_anomaly = (test_labels == -1).astype(int)
    model_anomalies = (model_predictions == -1).astype(int)
    baseline_anomalies = _rules_only_baseline(test_samples)
    result = {
        "evaluation": "synthetic_holdout_comparison",
        "data_notice": "Fictional generated records only; metrics are not estimates of operational detection accuracy.",
        "seed": SEED,
        "sample_count": int(len(samples)),
        "train_count": int(len(train_samples)),
        "test_count": int(len(test_samples)),
        "feature_order": FEATURES,
        "split": "stratified 80/20; random_state=42",
        "anomaly_class_definition": "label -1",
        "comparisons": {
            "rules_only_baseline": {
                "method": "fixed transparent thresholds; not trained",
                "metrics": _metrics(expected_anomaly, baseline_anomalies),
            },
            "isolation_forest": {
                "method": "OptimizedAnomalyDetector trained on training split",
                "metrics": _metrics(expected_anomaly, model_anomalies),
                "mean_anomaly_score": round(float(anomaly_scores.mean()), 4),
                "training_parameters": training["best_params"],
            },
        },
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
