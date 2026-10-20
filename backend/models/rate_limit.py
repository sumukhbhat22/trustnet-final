"""Enforced sliding-window rate limiter (per client IP). In-memory: correct for a single process only.

Enabled by default in production (TRUSTNET_ENV=production); override with TRUSTNET_RATE_LIMIT_ENABLED=1/0.
Limits: TRUSTNET_RATE_LIMIT_API_PER_MIN (default 600) and TRUSTNET_RATE_LIMIT_LOGIN_PER_MIN (default 20).
Behind a multi-process/multi-host deployment use a shared limiter (reverse proxy or Redis) instead.
"""

from __future__ import annotations

from collections import defaultdict, deque
import os
import threading
import time


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: float = 60.0, clock=time.monotonic):
        if limit < 1:
            raise ValueError("Rate-limit capacity must be at least 1 request per window.")
        if window_seconds <= 0:
            raise ValueError("Rate-limit window must be positive.")
        self.limit, self.window, self._clock = limit, window_seconds, clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._last_cleanup = clock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            # Remove expired timestamps for this client first.
            hits = self._hits[key]
            while hits and now - hits[0] >= self.window:
                hits.popleft()
            # Also discard inactive client keys periodically. Without this, a
            # stream of distinct source IPs can grow the in-memory map forever.
            if now - self._last_cleanup >= self.window:
                expired_keys = [client for client, events in self._hits.items()
                                if not events or now - events[-1] >= self.window]
                for client in expired_keys:
                    self._hits.pop(client, None)
                self._last_cleanup = now
                # `hits` may have been removed only if it was empty; restore the
                # current key before appending the new event.
                hits = self._hits[key]
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


def enabled() -> bool:
    default = "1" if os.environ.get("TRUSTNET_ENV", "").lower() == "production" else "0"
    return os.environ.get("TRUSTNET_RATE_LIMIT_ENABLED", default) == "1"


api_limiter = SlidingWindowLimiter(int(os.environ.get("TRUSTNET_RATE_LIMIT_API_PER_MIN", "600")))
login_limiter = SlidingWindowLimiter(int(os.environ.get("TRUSTNET_RATE_LIMIT_LOGIN_PER_MIN", "20")))
