"""Derived user/device behaviour profiles from persisted security events.

Profiles are calculated from recorded events rather than synthetic defaults. Users with
fewer than 30 events remain in explicit cold-start mode and should be scored by rules.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from math import ceil
from typing import Any

from models.security_events import list_security_events


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def _percentile95(values: list[int]) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[max(0, ceil(0.95 * len(ordered)) - 1)]


def build_user_profile(user_id: str) -> dict[str, Any]:
    """Build an explainable profile for a user using up to 10,000 persisted events."""
    events = list_security_events(user_id=user_id, limit=10000)
    events = sorted(events, key=lambda event: str(event.get("timestamp") or ""))
    hours = [0] * 24
    devices: dict[str, dict[str, str | None]] = {}
    ips: dict[str, dict[str, str | None]] = {}
    minute_counts: Counter[str] = Counter()
    login_event_count = 0

    for event in events:
        timestamp = _parse_time(event.get("timestamp"))
        if timestamp:
            category = str(event.get("event_category") or "").lower()
            if any(token in category for token in ("login", "auth", "session")):
                hours[timestamp.hour] += 1
                login_event_count += 1
            minute_counts[timestamp.strftime("%Y-%m-%dT%H:%MZ")] += 1
        for field, target in (("device_fingerprint_hash", devices), ("ip_address", ips)):
            value = event.get(field)
            if not isinstance(value, str) or not value.strip():
                continue
            first = str(event.get("timestamp") or "") or None
            last = first
            if value not in target:
                target[value] = {"first_seen": first, "last_seen": last}
            else:
                target[value]["first_seen"] = min(filter(None, [target[value]["first_seen"], first]), default=None)
                target[value]["last_seen"] = max(filter(None, [target[value]["last_seen"], last]), default=None)

    volumes = list(minute_counts.values())
    return {
        "user_id": user_id,
        "event_count": len(events),
        "mode": "rules" if len(events) < 30 else "profile",
        "cold_start": len(events) < 30,
        "login_hour_histogram": hours,
        "login_event_count": login_event_count,
        "known_devices": [{"device_hash": key, **value} for key, value in sorted(devices.items())],
        "known_ips": [{"ip_address": key, **value} for key, value in sorted(ips.items())],
        "request_volume": {
            "average_events_per_active_minute": round(sum(volumes) / len(volumes), 3) if volumes else 0.0,
            "p95_events_per_minute": _percentile95(volumes),
            "active_minutes": len(volumes),
        },
        "profile_source": "persisted_security_events",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "limitations": ["This is a derived descriptive profile, not a trained ML baseline."] if len(events) >= 30 else [
            "Fewer than 30 persisted events; use rule-based cold-start scoring.",
            "This is a derived descriptive profile, not a trained ML baseline.",
        ],
    }
