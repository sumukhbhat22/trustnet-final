"""
Supervised Threat Classifier for TrustNet AI Guardian

This is a REAL supervised ML model (Random Forest + Gradient Boosting ensemble)
that produces clear predictive outputs:

  - Binary prediction: MALICIOUS / BENIGN
  - Attack type classification: credential_theft, session_hijack, brute_force, insider_threat
  - Confidence score (0-100%)
  - Predicted action: ALLOW / FLAG / RESTRICT / BLOCK

Unlike the Isolation Forest (unsupervised anomaly detection), this model is
trained on LABELED data so it learns the decision boundary between normal
and malicious logins and can classify the specific attack type.
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, accuracy_score, f1_score,
    precision_score, recall_score, confusion_matrix
)
from typing import Dict, Any, List, Tuple
import warnings
warnings.filterwarnings('ignore')


# ──────────────────────────────────────────────
# Attack type labels
# ──────────────────────────────────────────────

ATTACK_LABELS = {
    0: "benign",
    1: "credential_theft",
    2: "session_hijack",
    3: "brute_force",
    4: "insider_threat",
}

ATTACK_DESCRIPTIONS = {
    "benign":           "Normal legitimate login — no threat indicators detected.",
    "credential_theft": "Stolen credentials used from an unrecognized device/location.",
    "session_hijack":   "Session token replayed from a different device or network.",
    "brute_force":      "Automated login attempts with abnormal timing patterns.",
    "insider_threat":   "Authorized user exhibiting anomalous data access patterns.",
}

ACTION_MAP = {
    "benign":           "ALLOW",
    "credential_theft": "BLOCK",
    "session_hijack":   "BLOCK",
    "brute_force":      "RESTRICT",
    "insider_threat":   "FLAG",
}


class ThreatClassifier:
    """
    Ensemble classifier combining Random Forest + Gradient Boosting
    for multi-class threat prediction with clear predictive output.

    Features used (7 total):
      0. login_hour_deviation    — |actual_hour - baseline_hour|
      1. geo_distance_km         — haversine distance from baseline location
      2. device_match_score      — fingerprint similarity (0-1, 1 = same device)
      3. session_deviation_pct   — % change in session duration
      4. data_volume_deviation   — % change in data volume
      5. api_calls_deviation     — % change in API calls
      6. isolation_forest_score  — anomaly score from the unsupervised model
    """

    FEATURE_NAMES = [
        "login_hour_deviation",
        "geo_distance_km",
        "device_match_score",
        "session_deviation_pct",
        "data_volume_deviation_pct",
        "api_calls_deviation_pct",
        "isolation_forest_score",
    ]

    def __init__(self):
        self.rf_model = None
        self.gb_model = None
        self.scaler = StandardScaler()
        self.trained = False
        self.metrics: Dict[str, Any] = {}

    # ──────────────────────────────────────────
    # Synthetic labeled training data
    # ──────────────────────────────────────────

    def _generate_labeled_data(self, n_samples: int = 5000) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generate realistic labeled data for each attack class.

        Each row: [hour_dev, geo_km, device_match, session_dev%, data_dev%, api_dev%, if_score]
        """
        np.random.seed(42)
        samples_per_class = n_samples // 5

        # ── Class 0: Benign ──
        benign = np.column_stack([
            np.abs(np.random.normal(0.5, 0.8, samples_per_class)),     # small hour deviation
            np.random.exponential(5, samples_per_class),                # very short geo distance
            np.random.uniform(0.85, 1.0, samples_per_class),           # high device match
            np.abs(np.random.normal(5, 8, samples_per_class)),         # low session deviation
            np.abs(np.random.normal(3, 6, samples_per_class)),         # low data deviation
            np.abs(np.random.normal(4, 7, samples_per_class)),         # low API deviation
            np.random.uniform(0.0, 0.15, samples_per_class),           # low IF score
        ])

        # ── Class 1: Credential Theft ──
        # Different device, different location, same username
        cred_theft = np.column_stack([
            np.abs(np.random.normal(3, 3, samples_per_class)),         # moderate hour shift
            np.random.uniform(500, 12000, samples_per_class),          # very far geo
            np.random.uniform(0.0, 0.35, samples_per_class),          # very low device match
            np.abs(np.random.normal(60, 30, samples_per_class)),       # high session deviation
            np.abs(np.random.normal(80, 40, samples_per_class)),       # high data deviation
            np.abs(np.random.normal(90, 50, samples_per_class)),       # high API deviation
            np.random.uniform(0.5, 1.0, samples_per_class),           # high IF score
        ])

        # ── Class 2: Session Hijack ──
        # Same-ish location but different device, moderate deviations
        sess_hijack = np.column_stack([
            np.abs(np.random.normal(1, 1.5, samples_per_class)),       # small hour shift
            np.random.uniform(0, 200, samples_per_class),              # nearby geo
            np.random.uniform(0.1, 0.5, samples_per_class),           # low-medium device match
            np.abs(np.random.normal(40, 25, samples_per_class)),       # moderate session deviation
            np.abs(np.random.normal(50, 30, samples_per_class)),       # moderate data deviation
            np.abs(np.random.normal(70, 35, samples_per_class)),       # high API deviation
            np.random.uniform(0.35, 0.8, samples_per_class),          # medium-high IF score
        ])

        # ── Class 3: Brute Force ──
        # Fast repeated attempts, odd hours, same location usually
        brute_force = np.column_stack([
            np.abs(np.random.normal(8, 4, samples_per_class)),         # very odd hours
            np.random.uniform(0, 500, samples_per_class),              # any geo
            np.random.uniform(0.3, 0.7, samples_per_class),           # mixed device match
            np.abs(np.random.normal(10, 10, samples_per_class)),       # low session (quick attempts)
            np.abs(np.random.normal(15, 15, samples_per_class)),       # low data (just trying passwords)
            np.abs(np.random.normal(200, 80, samples_per_class)),      # VERY high API calls
            np.random.uniform(0.4, 0.9, samples_per_class),           # high IF score
        ])

        # ── Class 4: Insider Threat ──
        # Same device, same location, but abnormal data access
        insider = np.column_stack([
            np.abs(np.random.normal(2, 2, samples_per_class)),         # slight hour shift
            np.random.exponential(10, samples_per_class),              # short geo distance
            np.random.uniform(0.75, 1.0, samples_per_class),          # high device match (same device)
            np.abs(np.random.normal(20, 15, samples_per_class)),       # moderate session
            np.abs(np.random.normal(150, 60, samples_per_class)),      # VERY high data volume
            np.abs(np.random.normal(120, 50, samples_per_class)),      # high API calls
            np.random.uniform(0.2, 0.6, samples_per_class),           # medium IF score
        ])

        X = np.vstack([benign, cred_theft, sess_hijack, brute_force, insider])
        y = np.hstack([
            np.full(samples_per_class, 0),
            np.full(samples_per_class, 1),
            np.full(samples_per_class, 2),
            np.full(samples_per_class, 3),
            np.full(samples_per_class, 4),
        ])

        # Shuffle
        idx = np.random.permutation(len(X))
        return X[idx], y[idx]

    # ──────────────────────────────────────────
    # Training
    # ──────────────────────────────────────────

    def train(self) -> Dict[str, Any]:
        """Train the ensemble classifier on labeled threat data."""
        print("Generating labeled training data (5000 samples, 5 classes)...")
        X, y = self._generate_labeled_data(5000)

        print(f"   Classes: {', '.join(ATTACK_LABELS.values())}")
        print(f"   Features: {len(self.FEATURE_NAMES)}")
        print(f"   Samples per class: {len(X) // 5}")

        # Scale
        X_scaled = self.scaler.fit_transform(X)

        # Train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )

        # ── Random Forest ──
        print("\nTraining Random Forest (150 trees)...")
        self.rf_model = RandomForestClassifier(
            n_estimators=150,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1,
        )
        self.rf_model.fit(X_train, y_train)
        rf_acc = accuracy_score(y_test, self.rf_model.predict(X_test))
        print(f"   Random Forest accuracy: {rf_acc:.4f}")

        # ── Gradient Boosting ──
        print("Training Gradient Boosting (100 estimators)...")
        self.gb_model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            random_state=42,
        )
        self.gb_model.fit(X_train, y_train)
        gb_acc = accuracy_score(y_test, self.gb_model.predict(X_test))
        print(f"   Gradient Boosting accuracy: {gb_acc:.4f}")

        # ── Evaluate ensemble ──
        y_pred = self._ensemble_predict(X_test)
        ensemble_acc = accuracy_score(y_test, y_pred)
        f1_macro = f1_score(y_test, y_pred, average='macro')
        f1_weighted = f1_score(y_test, y_pred, average='weighted')
        precision = precision_score(y_test, y_pred, average='weighted')
        recall = recall_score(y_test, y_pred, average='weighted')

        print(f"\nEnsemble Performance:")
        print(f"   Accuracy:           {ensemble_acc:.4f}")
        print(f"   Precision:          {precision:.4f}")
        print(f"   Recall:             {recall:.4f}")
        print(f"   F1-Score (macro):   {f1_macro:.4f}")
        print(f"   F1-Score (weighted):{f1_weighted:.4f}")
        print("   Validation:         stratified 80/20 holdout")

        # Per-class report
        print(f"\n   Per-class report:")
        report = classification_report(
            y_test, y_pred,
            target_names=list(ATTACK_LABELS.values()),
            digits=3,
        )
        for line in report.split('\n'):
            if line.strip():
                print(f"   {line}")

        # Feature importance
        importances = self.rf_model.feature_importances_
        print(f"\n   Feature importance:")
        for name, imp in sorted(zip(self.FEATURE_NAMES, importances), key=lambda x: -x[1]):
            bar = '#' * int(imp * 40)
            print(f"   {name:30s} {imp:.3f} {bar}")

        self.trained = True
        self.metrics = {
            "accuracy": round(ensemble_acc, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_macro": round(f1_macro, 4),
            "f1_weighted": round(f1_weighted, 4),
            "rf_accuracy": round(rf_acc, 4),
            "gb_accuracy": round(gb_acc, 4),
        }

        return {"status": "success", "metrics": self.metrics}

    # ──────────────────────────────────────────
    # Prediction
    # ──────────────────────────────────────────

    def _ensemble_predict(self, X_scaled: np.ndarray) -> np.ndarray:
        """Weighted average of RF + GB probability predictions."""
        rf_proba = self.rf_model.predict_proba(X_scaled)
        gb_proba = self.gb_model.predict_proba(X_scaled)
        # 60% RF + 40% GB (RF tends to generalize better)
        avg_proba = 0.6 * rf_proba + 0.4 * gb_proba
        return np.argmax(avg_proba, axis=1)

    def _ensemble_predict_proba(self, X_scaled: np.ndarray) -> np.ndarray:
        """Weighted average probabilities."""
        rf_proba = self.rf_model.predict_proba(X_scaled)
        gb_proba = self.gb_model.predict_proba(X_scaled)
        return 0.6 * rf_proba + 0.4 * gb_proba

    def predict(
        self,
        login_hour_deviation: float,
        geo_distance_km: float,
        device_match_score: float,
        session_deviation_pct: float,
        data_volume_deviation_pct: float,
        api_calls_deviation_pct: float,
        isolation_forest_score: float,
    ) -> Dict[str, Any]:
        """
        Predict threat classification for a single login event.

        Returns a clear predictive output:
          - prediction:  "MALICIOUS" or "BENIGN"
          - attack_type: e.g. "credential_theft"
          - confidence:  0-100%
          - action:      "ALLOW" / "FLAG" / "RESTRICT" / "BLOCK"
          - probabilities: per-class breakdown
        """
        if not self.trained:
            return {
                "prediction": "UNKNOWN",
                "attack_type": "unknown",
                "confidence": 0,
                "action": "FLAG",
                "description": "Classifier not yet trained.",
                "probabilities": {},
            }

        features = np.array([[
            login_hour_deviation,
            geo_distance_km,
            device_match_score,
            session_deviation_pct,
            data_volume_deviation_pct,
            api_calls_deviation_pct,
            isolation_forest_score,
        ]])

        X_scaled = self.scaler.transform(features)
        proba = self._ensemble_predict_proba(X_scaled)[0]
        predicted_class = int(np.argmax(proba))
        confidence = float(proba[predicted_class]) * 100

        attack_type = ATTACK_LABELS[predicted_class]
        is_malicious = predicted_class != 0
        action = ACTION_MAP[attack_type]
        description = ATTACK_DESCRIPTIONS[attack_type]

        # Build per-class probability dict
        probabilities = {
            ATTACK_LABELS[i]: round(float(proba[i]) * 100, 1)
            for i in range(len(proba))
        }

        return {
            "prediction": "MALICIOUS" if is_malicious else "BENIGN",
            "attack_type": attack_type,
            "attack_label": attack_type.replace("_", " ").title(),
            "confidence": round(confidence, 1),
            "action": action,
            "description": description,
            "is_malicious": is_malicious,
            "probabilities": probabilities,
            "model": "RandomForest+GradientBoosting Ensemble",
            "features_used": dict(zip(self.FEATURE_NAMES, features[0].tolist())),
        }


# ──────────────────────────────────────────
# Module-level instance (trained on import)
# ──────────────────────────────────────────

threat_classifier = ThreatClassifier()
