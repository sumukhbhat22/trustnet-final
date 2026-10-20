"""Train the Isolation Forest on the real RBA login data with a time-based split.

Usage (from backend/):
    python -m ml.train_real --data ../data/raw/rba-dataset.csv --sample-frac 0.05
The dataset is downloaded by the owner and is never committed (see docs/ml/DATA.md).
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
from datetime import datetime, timezone

import numpy as np

from ml.data_loader import FEATURES, FEATURE_PROVENANCE, read_sample, time_split, to_features
from ml.registry import DEFAULT_MODEL, metadata_path
from models.optimized_models import OptimizedAnomalyDetector

DATASET_NAME = "Risk-Based Authentication (RBA) dataset, Wiefling et al."
VERSION_PREFIX = "real-"


def evaluate(detector, test) -> dict:
    """Metrics on the held-out latest period. Labels are used only here, never for training."""
    _, scores = detector.predict(test[FEATURES].to_numpy())
    labels = test["label"].to_numpy()
    out = {"test_rows": int(len(test)), "positives": int(labels.sum())}
    if 0 < labels.sum() < len(labels):
        from sklearn.metrics import average_precision_score, roc_auc_score
        out["roc_auc"] = round(float(roc_auc_score(labels, scores)), 4)
        out["average_precision"] = round(float(average_precision_score(labels, scores)), 4)
        out["positive_rate"] = round(float(labels.mean()), 6)
    else:
        out["note"] = "Metrics not computable: the test period holds only one class."
    return out


def train(df_features, *, train_frac: float = 0.7, max_train_rows: int = 50_000, seed: int = 42):
    train_df, test_df, split = time_split(df_features, train_frac)
    benign = train_df[train_df["label"] == 0]
    if len(benign) > max_train_rows:
        benign = benign.sample(n=max_train_rows, random_state=seed)
    if len(benign) < 50:
        raise ValueError("Fewer than 50 benign training rows; use a larger sample")
    detector = OptimizedAnomalyDetector()
    with contextlib.redirect_stdout(io.StringIO()):
        result = detector.train(X=benign[FEATURES].to_numpy(), feature_names=list(FEATURES))
    if result.get("status") != "success":
        raise RuntimeError(result.get("message", "training failed"))
    return detector, split, evaluate(detector, test_df), len(benign)


def save_with_metadata(detector, path: str, meta: dict) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with contextlib.redirect_stdout(io.StringIO()):
        detector.save(path)
    with open(metadata_path(path), "w", encoding="utf-8") as handle:
        json.dump(meta, handle, indent=2, sort_keys=True)
    return path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", required=True)
    ap.add_argument("--sample-frac", type=float, default=0.05)
    ap.add_argument("--max-rows", type=int, default=500_000)
    ap.add_argument("--train-frac", type=float, default=0.7)
    ap.add_argument("--out", default=DEFAULT_MODEL)
    args = ap.parse_args(argv)
    if not os.path.isfile(args.data):
        print(f"BLOCKED: dataset not found at {args.data}. Download it per docs/ml/DATA.md, then rerun.", file=sys.stderr)
        return 2
    raw = read_sample(args.data, sample_frac=args.sample_frac, max_rows=args.max_rows)
    feats = to_features(raw)
    detector, split, metrics, n_train = train(feats, train_frac=args.train_frac)
    now = datetime.now(timezone.utc)
    meta = {"name": "isolation_forest_real", "version": VERSION_PREFIX + now.strftime("%Y%m%d%H%M"),
            "dataset": DATASET_NAME, "rows": int(len(feats)), "rows_scanned": raw.attrs.get("rows_scanned"),
            "sample_frac": args.sample_frac, "train_rows_used": n_train,
            "date_range": [feats["ts"].min().isoformat(), feats["ts"].max().isoformat()],
            "split": split, "features": list(FEATURES), "feature_provenance": FEATURE_PROVENANCE,
            "metrics": metrics, "trained_at": now.isoformat(),
            "limitations": "Three of five features are neutral constants and geo_distance is a proxy; "
                           "metrics describe this one public dataset only."}
    save_with_metadata(detector, args.out, meta)
    print(json.dumps({"model": args.out, "rows": meta["rows"], "split": split, "metrics": metrics}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
