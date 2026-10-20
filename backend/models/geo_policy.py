"""Configurable country allow-list policy for login traffic.

This is a policy gate, not a substitute for a bundled offline GeoIP database.
Production country decisions use the country code returned by the configured
GeoIP provider. The X-Demo-Country override is accepted only in explicit demo
mode and never in production. Private/reserved addresses bypass country policy.
"""
from __future__ import annotations

import ipaddress
import os
from typing import Mapping, Any

_TRUE = {"1", "true", "yes", "on"}


def demo_mode_enabled() -> bool:
    return (
        os.getenv("TRUSTNET_ENV", "development").strip().lower() != "production"
        and os.getenv("DEMO_MODE", "").strip().lower() in _TRUE
    )


def allowed_countries() -> set[str]:
    raw = os.getenv("TRUSTNET_ALLOWED_COUNTRIES", "")
    return {part.strip().upper() for part in raw.split(",") if part.strip()}


def evaluate_country_policy(ip: str, geo: Mapping[str, Any], headers: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Return an auditable allow/deny decision for an IP/GeoIP result."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        return {"allowed": True, "reason": "private_network_bypass", "country": "LOCAL", "policy_enabled": bool(allowed_countries())}

    configured = allowed_countries()
    if not configured:
        return {"allowed": True, "reason": "policy_disabled", "country": str(geo.get("country", "Unknown")).upper(), "policy_enabled": False}

    country = str(geo.get("country", "Unknown")).strip().upper()
    headers = headers or {}
    demo_country = next((v for k, v in headers.items() if k.lower() == "x-demo-country"), None)
    if demo_country and demo_mode_enabled():
        country = str(demo_country).strip().upper()
        source = "demo_override"
    else:
        source = "geoip"
    allowed = country in configured
    return {
        "allowed": allowed,
        "reason": "country_allowed" if allowed else "country_not_allowlisted",
        "country": country,
        "source": source,
        "policy_enabled": True,
    }
