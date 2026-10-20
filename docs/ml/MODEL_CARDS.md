# Model cards

All three models are part of demonstration software. None has been validated for operational use.

## 1. Isolation Forest, synthetic-trained (default)
- **Purpose:** unsupervised anomaly score per session for the risk engine.
- **Code:** `backend/models/optimized_models.py` (`OptimizedAnomalyDetector`); trained at API start.
- **Data:** generated fictional sessions (`generate_training_data`, 5,000 rows, 15% mild anomalies drawn from a wider distribution).
- **Features:** session_duration, data_volume, api_calls, geo_distance, login_hour.
- **Split / metrics:** `train()` reports metrics on its own training data (not a generalisation estimate). Held-out comparison: `docs/SYNTHETIC_EVALUATION.json` (single seed) and `docs/EVALUATION.md` (5 seeds, time split).
- **Result so far (synthetic):** on the 5-seed evaluation F1 is 0.555 against 0.544 for fixed rules; on the older single-seed set the rules baseline scored higher. No ML advantage is established.
- **Limitations / failure modes:** misses slow-and-low and mimicry behaviour (recall below 0.10 in `docs/EVALUATION.md`); global thresholds, no per-user baseline inside the model; contamination is chosen by a silhouette search, which is a weak criterion; sensitive to the generator it was trained on.

## 2. Isolation Forest, real-data trained (when present)
- **Code:** `backend/ml/train_real.py`; loaded by `backend/ml/registry.py` if `backend/ml_models/real_model.joblib` and its `.json` exist and the feature list matches; otherwise the app keeps the synthetic model and reports a `degraded_note` in `/api/health`.
- **Data:** a sample of the public RBA login dataset (Wiefling et al.). See `docs/ml/DATA.md`. Not committed.
- **Features:** same five; only login_hour is real, geo_distance is a new-country proxy, and three are constants.
- **Split:** earliest 70% by time to train (benign rows only), latest 30% to test. Metrics: ROC AUC and average precision on the test period, written to the model's metadata JSON.
- **Status:** the training path is tested with fabricated rows. It has **not** been run on the real dataset in the session that wrote it; no real-data metric exists yet.
- **Limitations:** results describe one public dataset; the model effectively sees hour and new-country; it cannot see device trust or MFA; a rules baseline may do as well.
- **Security note:** `joblib` files can run code when loaded. Only load model files you created.

## 3. Threat classifier (supervised)
- **Code:** `backend/models/threat_classifier.py` (Random Forest + Gradient Boosting ensemble).
- **Purpose:** label a session MALICIOUS/BENIGN and one of four attack types, with a confidence.
- **Data:** generated labelled synthetic sessions (5,000 rows, 5 classes); stratified 80/20 holdout reported at start-up.
- **Limitations:** trained and tested on the same generator, so holdout scores say little about unseen attacks; attack classes are the project's own scripted scenarios. The deterministic rule classifier in `models/threat_classifier.py`/`agents/investigator.py` and human approval remain the safeguards for any action.

## Known failure modes common to all
Novel attack styles outside the scripted ones, attackers who copy a user's normal hours and location, gradual drift of a legitimate user's behaviour (false alerts until the baseline moves), and any input outside the five-feature scale.
