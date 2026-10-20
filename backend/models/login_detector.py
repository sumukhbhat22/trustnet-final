"""
Real-time login detection module for TrustNet AI Guardian.

This handles:
  1. Device fingerprint comparison (real fingerprint from browser)
  2. IP geolocation via ipinfo.io (free API — no key needed for < 50k req/month)
  3. Haversine distance calculation
  4. Feature vector construction from REAL login data
  5. Isolation Forest anomaly detection
  6. Risk scoring
  7. WebSocket broadcast to dashboard
"""

import math
import hashlib
import ipaddress
import json
from datetime import datetime
from typing import Optional, Dict, Any, List

from models import database as database_module
from models.database import get_db_connection, initialize_database

# ──────────────────────────────────────────────
# Haversine formula — real geo distance in km
# ──────────────────────────────────────────────

def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate great-circle distance between two points on Earth (km)."""
    R = 6371  # Earth radius in km
    φ1, φ2 = math.radians(lat1), math.radians(lat2)
    Δφ = math.radians(lat2 - lat1)
    Δλ = math.radians(lon2 - lon1)
    a = math.sin(Δφ / 2) ** 2 + math.cos(φ1) * math.cos(φ2) * math.sin(Δλ / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


# ──────────────────────────────────────────────
# GeoIP lookup (uses free ipinfo.io)
# ──────────────────────────────────────────────

# ── GeoIP cache + reusable client for speed ──
_geoip_cache: Dict[str, Dict[str, Any]] = {}
_httpx_client = None

def _get_httpx_client():
    global _httpx_client
    if _httpx_client is None:
        import httpx
        _httpx_client = httpx.AsyncClient(timeout=2)
    return _httpx_client


async def geoip_lookup(ip: str) -> Dict[str, Any]:
    """
    Look up IP geolocation using ipinfo.io (free, no key needed).
    Returns { city, region, country, lat, lon, org }.
    Falls back to defaults for localhost / private IPs.
    Uses caching + persistent HTTP client for fast repeated lookups.
    """

    if ip in _geoip_cache:
        return _geoip_cache[ip]

    # Local/private/reserved addresses have no public geolocation. Parse actual
    # IPv4 and IPv6 ranges instead of treating every 172.* address as private.
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return {
            "ip": ip, "city": "Unknown", "region": "Unknown", "country": "Unknown",
            "lat": 0.0, "lon": 0.0, "org": "Unknown", "is_private": True,
        }

    if not address.is_global:
        result = {
            "ip": ip, "city": "Local Network", "region": "Local", "country": "Local",
            "lat": 0.0, "lon": 0.0, "org": "Private Network", "is_private": True,
        }
        _geoip_cache[ip] = result
        return result

    try:
        client = _get_httpx_client()
        response = await client.get(f"https://ipinfo.io/{ip}/json")
        response.raise_for_status()
        data = response.json()
        coordinates = data.get("loc", "0,0").split(",")
        if len(coordinates) != 2:
            raise ValueError("GeoIP response has an invalid location")
        latitude, longitude = float(coordinates[0]), float(coordinates[1])
        if not math.isfinite(latitude) or not math.isfinite(longitude):
            raise ValueError("GeoIP response has non-finite coordinates")
        result = {
            "ip": ip,
            "city": data.get("city", "Unknown"),
            "region": data.get("region", "Unknown"),
            "country": data.get("country", "Unknown"),
            "lat": latitude,
            "lon": longitude,
            "org": data.get("org", "Unknown"),
            "is_private": False,
        }
        _geoip_cache[ip] = result
        return result
    except Exception as error:
        print(f"GeoIP lookup failed for {ip}: {error}")
        # Do not cache network errors; a later login can retry the lookup.
        return {
            "ip": ip, "city": "Unknown", "region": "Unknown", "country": "Unknown",
            "lat": 0.0, "lon": 0.0, "org": "Unknown", "is_private": False,
        }


async def close_geoip_client() -> None:
    """Close the shared async HTTP client during application shutdown."""
    global _httpx_client
    if _httpx_client is not None:
        await _httpx_client.aclose()
        _httpx_client = None


# ──────────────────────────────────────────────
# Device fingerprint comparison
# ──────────────────────────────────────────────

def hash_fingerprint(fp: Dict[str, Any]) -> str:
    """Create a deterministic hash of the important fingerprint fields."""
    key_fields = [
        str(fp.get("userAgent", "")),
        str(fp.get("platform", "")),
        str(fp.get("screenResolution", "")),
        str(fp.get("timezone", "")),
        str(fp.get("canvasHash", "")),
        str(fp.get("webglRenderer", "")),
        str(fp.get("hardwareConcurrency", "")),
        str(fp.get("colorDepth", "")),
    ]
    raw = "|".join(key_fields)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def compare_fingerprints(baseline_fp: Dict, current_fp: Dict) -> Dict[str, Any]:
    """
    Compare two fingerprints field by field.
    Returns match score (0-1) and list of differences.
    """
    fields_to_compare = [
        "userAgent", "platform", "screenResolution", "timezone",
        "canvasHash", "webglRenderer", "hardwareConcurrency",
        "colorDepth", "deviceType", "language",
    ]

    total = len(fields_to_compare)
    matches = 0
    differences: List[str] = []

    for field in fields_to_compare:
        base_val = str(baseline_fp.get(field, ""))
        curr_val = str(current_fp.get(field, ""))
        if base_val == curr_val:
            matches += 1
        else:
            differences.append(f"{field}: '{base_val}' -> '{curr_val}'")

    match_score = matches / total if total > 0 else 1.0
    return {
        "match_score": round(match_score, 3),
        # A 0.8 threshold allowed two changed fields out of ten, including
        # high-entropy canvas/GPU identifiers, to pass as the baseline device.
        "is_same_device": match_score >= 0.9,
        "differences": differences,
        "fields_matched": matches,
        "fields_total": total,
    }


# ──────────────────────────────────────────────
# Build ML feature vector from REAL login data
# ──────────────────────────────────────────────

def build_feature_vector(
    login_hour: int,
    geo_distance_km: float,
    device_match_score: float,
    baseline: Dict[str, Any],
) -> Dict[str, float]:
    """
    Convert real login data into the behavior_metrics dict
    that the existing risk_scorer and anomaly_detector expect.

    The key insight: deviations from baseline ARE the features.
    """

    # Device change flag: 0 = same, 1 = completely different
    device_change = 1.0 - device_match_score

    # Baseline normal values
    normal_login_hour = baseline.get("normal_login_hour", 9.2)
    normal_session_duration = baseline.get("normal_session_duration", 4.5)
    normal_data_volume = baseline.get("normal_data_volume", 120)
    normal_api_calls = baseline.get("normal_api_calls", 45)

    # Construct behavior_metrics for the risk scorer
    behavior_metrics = {
        "normal_login_time": normal_login_hour,
        "actual_login_time": float(login_hour),
        "normal_session_duration": normal_session_duration,
        "actual_session_duration": max(0.1, normal_session_duration * (1.0 - device_change * 0.8)),
        "normal_data_volume": normal_data_volume,
        "actual_data_volume": normal_data_volume * (1.0 + device_change * 2.0),
        "normal_api_calls": normal_api_calls,
        "actual_api_calls": normal_api_calls * (1.0 + device_change * 3.0),
        "normal_geo_distance": 0.0,
        "actual_geo_distance": geo_distance_km,
    }

    # Anomaly score derived from device mismatch + geo distance
    # This feeds into the risk scorer as a secondary signal
    anomaly_score = min(1.0, (device_change * 0.5) + min(1.0, geo_distance_km / 5000) * 0.5)

    return {
        "behavior_metrics": behavior_metrics,
        "anomaly_score": round(anomaly_score, 4),
    }


# ──────────────────────────────────────────────
# User baseline store (in-memory for demo)
# ──────────────────────────────────────────────

# Stores the first login as "normal" baseline per username.
# Any subsequent login from a different device/IP/geo is compared against this.
user_baselines: Dict[str, Dict[str, Any]] = {}
_BASELINES_DATABASE_PATH: str | None = None


def _ensure_baselines_loaded() -> None:
    global _BASELINES_DATABASE_PATH
    active_path = database_module._DB_PATH
    if _BASELINES_DATABASE_PATH == active_path:
        return
    initialize_database()
    connection = get_db_connection()
    try:
        rows = connection.execute("SELECT * FROM login_baselines").fetchall()
    finally:
        connection.close()
    user_baselines.clear()
    for row in rows:
        user_baselines[row["username"]] = {
            "username": row["username"],
            "fingerprint": json.loads(row["fingerprint"]),
            "fingerprint_hash": row["fingerprint_hash"],
            "geo": json.loads(row["geo"]),
            "normal_login_hour": row["normal_login_hour"],
            "normal_session_duration": row["normal_session_duration"],
            "normal_data_volume": row["normal_data_volume"],
            "normal_api_calls": row["normal_api_calls"],
            "created_at": row["created_at"],
        }
    _BASELINES_DATABASE_PATH = active_path


def _persist_baseline(baseline: Dict[str, Any]) -> None:
    connection = get_db_connection()
    try:
        connection.execute(
            """INSERT INTO login_baselines
               (username, fingerprint, fingerprint_hash, geo, normal_login_hour,
                normal_session_duration, normal_data_volume, normal_api_calls, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(username) DO UPDATE SET
                 fingerprint = excluded.fingerprint,
                 fingerprint_hash = excluded.fingerprint_hash,
                 geo = excluded.geo,
                 normal_login_hour = excluded.normal_login_hour,
                 normal_session_duration = excluded.normal_session_duration,
                 normal_data_volume = excluded.normal_data_volume,
                 normal_api_calls = excluded.normal_api_calls,
                 created_at = excluded.created_at""",
            (
                baseline["username"], json.dumps(baseline["fingerprint"], sort_keys=True),
                baseline["fingerprint_hash"], json.dumps(baseline["geo"], sort_keys=True),
                baseline["normal_login_hour"], baseline["normal_session_duration"],
                baseline["normal_data_volume"], baseline["normal_api_calls"], baseline["created_at"],
            ),
        )
        connection.commit()
    finally:
        connection.close()


def get_or_create_baseline(username: str, fingerprint: Dict, geo: Dict, login_hour: int) -> Dict[str, Any]:
    """
    Get the stored baseline for a user to compare against.
    If first login → store it as the baseline (owner's device).
    """
    _ensure_baselines_loaded()
    if username in user_baselines:
        return user_baselines[username]

    # First login — this becomes the baseline
    baseline = {
        "username": username,
        "fingerprint": fingerprint,
        "fingerprint_hash": hash_fingerprint(fingerprint),
        "geo": geo,
        "normal_login_hour": login_hour,
        "normal_session_duration": 4.5,
        "normal_data_volume": 120,
        "normal_api_calls": 45,
        "created_at": datetime.now().isoformat(),
    }
    user_baselines[username] = baseline
    _persist_baseline(baseline)
    print(f"Baseline stored for '{username}' - device: {fingerprint.get('deviceType', '?')}, "
          f"location: {geo.get('city', '?')}, {geo.get('country', '?')}")
    return baseline


def reset_baseline(username: str) -> bool:
    """Reset a user's baseline (for re-registration)."""
    _ensure_baselines_loaded()
    existed = user_baselines.pop(username, None) is not None
    connection = get_db_connection()
    try:
        connection.execute("DELETE FROM login_baselines WHERE username = ?", (username,))
        connection.commit()
    finally:
        connection.close()
    return existed


def reset_all_baselines():
    """Clear all baselines."""
    _ensure_baselines_loaded()
    user_baselines.clear()
    connection = get_db_connection()
    try:
        connection.execute("DELETE FROM login_baselines")
        connection.commit()
    finally:
        connection.close()
