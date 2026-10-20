"""F-28: persisted asset criticality (1-5) used by risk propagation and the risk engine.

Pure sqlite module (no web framework) so it is unit-testable in isolation.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from models.database import get_db_connection

MIN_CRITICALITY = 1
MAX_CRITICALITY = 5
EXPOSURE_WINDOW_MINUTES = 15
# Extra risk points per criticality level above 1 when a user's *denied* access to a
# protected asset is observed in the window. Max extra = 4 * 2.5 = 10 points.
POINTS_PER_LEVEL = 2.5


def validate_criticality(value: Any) -> int:
    """Strictly validate: integers 1..5 only (no bool, float, str)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("criticality must be an integer between 1 and 5")
    if value < MIN_CRITICALITY or value > MAX_CRITICALITY:
        raise ValueError("criticality must be an integer between 1 and 5")
    return value


def get_criticality(asset_id: str) -> int | None:
    connection = get_db_connection()
    try:
        row = connection.execute(
            "SELECT criticality FROM protected_assets WHERE asset_id = ?", (asset_id,)
        ).fetchone()
        return int(row["criticality"]) if row else None
    finally:
        connection.close()


def set_criticality(asset_id: str, value: Any) -> dict[str, Any]:
    """Persist a new criticality. Raises ValueError (bad value) or KeyError (unknown asset)."""
    new_value = validate_criticality(value)
    connection = get_db_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT asset_id, label, asset_type, criticality, classification FROM protected_assets WHERE asset_id = ?",
            (asset_id,),
        ).fetchone()
        if row is None:
            connection.rollback()
            raise KeyError(asset_id)
        previous = int(row["criticality"])
        if previous != new_value:
            connection.execute(
                "UPDATE protected_assets SET criticality = ? WHERE asset_id = ?", (new_value, asset_id)
            )
        connection.commit()
        return {"asset_id": asset_id, "label": row["label"], "asset_type": row["asset_type"],
                "classification": row["classification"], "previous": previous,
                "criticality": new_value, "changed": previous != new_value}
    finally:
        connection.close()


def exposure_points(user_id: str, *, now: datetime | None = None) -> dict[str, Any]:
    """Risk points for a user derived from the SAVED criticality of protected assets
    they were recently denied access to. Allowed, authorised access adds nothing."""
    now = now or datetime.now(timezone.utc)
    cutoff = (now - timedelta(minutes=EXPOSURE_WINDOW_MINUTES)).isoformat()
    connection = get_db_connection()
    try:
        rows = connection.execute(
            """SELECT event_payload FROM security_events
               WHERE user_id = ? AND event_category = 'protected_asset_access' AND timestamp >= ?""",
            (user_id, cutoff),
        ).fetchall()
        best_level, best_asset = 0, None
        for row in rows:
            try:
                payload = json.loads(row["event_payload"] or "{}")
            except (TypeError, ValueError):
                continue
            if payload.get("allowed", False):
                continue
            asset_id = str(payload.get("asset_id") or "")
            level = connection.execute(
                "SELECT criticality FROM protected_assets WHERE asset_id = ?", (asset_id,)
            ).fetchone()
            if level and int(level["criticality"]) > best_level:
                best_level, best_asset = int(level["criticality"]), asset_id
    finally:
        connection.close()
    points = round(max(0, best_level - 1) * POINTS_PER_LEVEL, 2) if best_level else 0.0
    return {"points": points, "asset_id": best_asset, "criticality": best_level or None}
