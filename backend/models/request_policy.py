"""Request-monitoring policy for excluding routine dashboard polling noise."""

from __future__ import annotations

# These read-only endpoints are refreshed on short intervals by dashboard pages.
# Counting them as user traffic can make the dashboard's own polling look like
# a high request rate. Mutating requests and unlisted GET endpoints are still
# monitored normally.
_DASHBOARD_POLL_PATHS = frozenset({
    "/api/health",
    "/api/live-threat",
    "/api/dashboard/summary",
    "/api/network/topology",
    "/api/network/events",
    "/api/network/anomalies",
    "/api/incidents",
    "/api/devices",
    "/api/agents/activity",
    "/api/agents/learning",
    "/api/notifications/unread-count",
    "/api/attack-chain/status",
    "/api/baselines",
    "/api/csi/simulation/sample",
})


def should_record_request(method: str, path: str) -> bool:
    """Return False only for known GET dashboard polls; default to monitoring."""
    normalized_method = method.upper()
    normalized_path = path.rstrip("/") or "/"
    if normalized_method == "GET" and normalized_path in _DASHBOARD_POLL_PATHS:
        return False
    return True
