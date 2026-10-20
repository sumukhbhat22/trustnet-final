"""Load the public Risk-Based Authentication (RBA) login dataset (Wiefling et al.) into the
detector's five-feature schema.

Raw data is never committed (``data/`` is git-ignored). Identifying values are hashed or dropped.

Feature mapping (see docs/ml/DATA.md for the reasoning):

| model feature     | source                                             | quality                       |
|-------------------|----------------------------------------------------|-------------------------------|
| login_hour        | hour of "Login Timestamp" (UTC)                    | real                          |
| geo_distance      | 50 if the country was seen before for this user,   | PROXY (not a distance)        |
|                   | else 100 (centres of the synthetic normal/anomaly) |                               |
| session_duration  | constant 4.5 (neutral)                             | NOT AVAILABLE in dataset      |
| data_volume       | constant 150 (neutral)                             | NOT AVAILABLE in dataset      |
| api_calls         | constant 200 (neutral)                             | NOT AVAILABLE in dataset      |

Device-trust flags and MFA events are not in the dataset and are not used by this model.
"""
from __future__ import annotations

import hashlib
import os
from typing import Iterable

import numpy as np
import pandas as pd

FEATURES = ["session_duration", "data_volume", "api_calls", "geo_distance", "login_hour"]
NEUTRAL = {"session_duration": 4.5, "data_volume": 150.0, "api_calls": 200.0}
GEO_SEEN, GEO_UNSEEN = 50.0, 100.0

# Canonical name -> accepted raw column spellings (lower-cased, punctuation stripped).
_ALIASES = {
    "timestamp": ["login timestamp", "timestamp"],
    "user": ["user id", "userid", "user"],
    "country": ["country"],
    "success": ["login successful", "success"],
    "attack_ip": ["is attack ip"],
    "ato": ["is account takeover"],
}
FEATURE_PROVENANCE = {
    "login_hour": "real (hour of login timestamp, UTC)",
    "geo_distance": "proxy: 50 if country seen earlier for this user else 100",
    "session_duration": "not available in dataset: constant 4.5",
    "data_volume": "not available in dataset: constant 150",
    "api_calls": "not available in dataset: constant 200",
}


def _norm(name: str) -> str:
    return " ".join("".join(c if c.isalnum() else " " for c in str(name).lower()).split())


def _resolve_columns(columns: Iterable[str]) -> dict[str, str]:
    by_norm = {_norm(c): c for c in columns}
    found = {}
    for canon, options in _ALIASES.items():
        for option in options:
            if _norm(option) in by_norm:
                found[canon] = by_norm[_norm(option)]
                break
    missing = [c for c in ("timestamp", "user", "country") if c not in found]
    if missing:
        raise ValueError(f"Dataset is missing required columns for: {', '.join(missing)}")
    return found


def _truthy(series: pd.Series) -> pd.Series:
    return series.astype(str).str.strip().str.lower().isin({"true", "1", "yes"})


def hash_identifier(value: object, salt: str) -> str:
    return hashlib.sha256(f"{salt}|{value}".encode()).hexdigest()[:16]


def read_sample(path: str, *, sample_frac: float = 0.05, max_rows: int = 500_000,
                chunksize: int = 200_000, seed: int = 42, salt: str | None = None) -> pd.DataFrame:
    """Read ``path`` (csv, optionally .gz/.zip) in chunks, sample uniformly, keep only needed columns.

    The sample is uniform over the whole file so every time period stays represented. If ``max_rows``
    is reached, reading stops and the result is flagged in ``df.attrs['truncated']``.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    if not 0 < sample_frac <= 1:
        raise ValueError("sample_frac must be in (0, 1]")
    salt = salt if salt is not None else os.environ.get("TRUSTNET_DATA_SALT", "trustnet-local-salt")
    parts, kept, scanned, cols, truncated = [], 0, 0, None, False
    for i, chunk in enumerate(pd.read_csv(path, chunksize=chunksize, dtype=str)):
        if cols is None:
            cols = _resolve_columns(chunk.columns)
        scanned += len(chunk)
        sample = chunk.sample(frac=sample_frac, random_state=seed + i) if sample_frac < 1 else chunk
        keep = pd.DataFrame({"timestamp": sample[cols["timestamp"]],
                             "user": sample[cols["user"]].map(lambda v: hash_identifier(v, salt)),
                             "country": sample[cols["country"]].fillna("??")})
        keep["success"] = _truthy(sample[cols["success"]]) if "success" in cols else True
        keep["attack_ip"] = _truthy(sample[cols["attack_ip"]]) if "attack_ip" in cols else False
        keep["ato"] = _truthy(sample[cols["ato"]]) if "ato" in cols else False
        parts.append(keep)
        kept += len(keep)
        if kept >= max_rows:
            truncated = True
            break
    if not parts:
        raise ValueError("Dataset is empty")
    df = pd.concat(parts, ignore_index=True)
    df.attrs.update(rows_scanned=scanned, rows_kept=len(df), sample_frac=sample_frac, truncated=truncated)
    return df


def to_features(df: pd.DataFrame) -> pd.DataFrame:
    """Map a raw-sample frame (from ``read_sample``) to FEATURES plus metadata columns, time-sorted.

    ``geo_distance`` is causal: it only looks at that user's earlier rows, so it is split-independent.
    """
    out = df.copy()
    out["ts"] = pd.to_datetime(out["timestamp"], errors="coerce", utc=True)
    out = out.dropna(subset=["ts"]).sort_values("ts", kind="mergesort").reset_index(drop=True)
    out["login_hour"] = out["ts"].dt.hour.astype(float)
    first_for_user = ~out.duplicated(subset=["user"], keep="first")
    first_for_country = ~out.duplicated(subset=["user", "country"], keep="first")
    unseen = first_for_country & ~first_for_user
    out["geo_distance"] = np.where(unseen, GEO_UNSEEN, GEO_SEEN)
    for name, value in NEUTRAL.items():
        out[name] = value
    out["label"] = (out["ato"] | out["attack_ip"]).astype(int)
    return out[["ts", "user", *FEATURES, "label", "ato", "success"]]


def time_split(df: pd.DataFrame, train_frac: float = 0.7) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Split by time: rows strictly before the cut go to train, the rest to test. No row is in both,
    and no test timestamp precedes a train timestamp. Rows sharing the cut timestamp stay together."""
    if not 0 < train_frac < 1:
        raise ValueError("train_frac must be in (0, 1)")
    if len(df) < 4:
        raise ValueError("Not enough rows to split")
    ordered = df.sort_values("ts", kind="mergesort").reset_index(drop=True)
    cut_ts = ordered["ts"].iloc[int(len(ordered) * train_frac)]
    train, test = ordered[ordered["ts"] < cut_ts], ordered[ordered["ts"] >= cut_ts]
    if train.empty or test.empty:
        raise ValueError("Time split produced an empty side (too few distinct timestamps)")
    info = {"cut": cut_ts.isoformat(), "train_start": train["ts"].min().isoformat(),
            "train_end": train["ts"].max().isoformat(), "test_start": test["ts"].min().isoformat(),
            "test_end": test["ts"].max().isoformat(), "train_rows": len(train), "test_rows": len(test)}
    return train, test, info
