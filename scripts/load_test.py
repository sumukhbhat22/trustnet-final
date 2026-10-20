#!/usr/bin/env python3
"""Small load generator for an HTTP endpoint (standard library only).

    python scripts/load_test.py --url http://localhost:8010/api/events/ingest --token $TOKEN --rate 20 --seconds 15

Sends synthetic JSON events at about --rate requests/second from a thread pool and reports achieved
requests/second, p50/p95/max latency and error rate. Numbers describe only the machine and server you
ran it against; they are not capacity claims. Never point it at a system you do not own.
"""
from __future__ import annotations

import argparse
import json
import math
import statistics
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    rank = math.ceil(pct / 100 * len(ordered))  # nearest-rank method
    return ordered[max(1, min(len(ordered), rank)) - 1]


def summarize(latencies: list[float], errors: int, elapsed: float) -> dict:
    total = len(latencies) + errors
    return {"requests": total, "errors": errors, "error_rate": round(errors / total, 4) if total else 0.0,
            "achieved_rps": round(total / elapsed, 2) if elapsed > 0 else 0.0,
            "latency_ms": {"p50": round(statistics.median(latencies) * 1000, 2) if latencies else None,
                           "p95": round(percentile(latencies, 95) * 1000, 2) if latencies else None,
                           "max": round(max(latencies) * 1000, 2) if latencies else None}}


def run(url: str, token: str | None, rate: float, seconds: float, workers: int, make_body) -> dict:
    latencies: list[float] = []
    errors = 0
    lock = threading.Lock()

    def one(i: int) -> None:
        nonlocal errors
        req = urllib.request.Request(url, data=json.dumps(make_body(i)).encode(), method="POST",
                                     headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
                ok = 200 <= resp.status < 300
        except urllib.error.HTTPError as exc:
            ok = False
            exc.read()
        except (urllib.error.URLError, OSError):
            ok = False
        elapsed = time.perf_counter() - start
        with lock:
            if ok:
                latencies.append(elapsed)
            else:
                errors += 1

    begin = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        i = 0
        while time.perf_counter() - begin < seconds:
            pool.submit(one, i)
            i += 1
            time.sleep(max(0.0, begin + i / rate - time.perf_counter()))
    return summarize(latencies, errors, time.perf_counter() - begin)


def synthetic_event(i: int) -> dict:
    return {"event_type": "request", "user_id": f"load-user-{i % 20}", "source": "synthetic-load-test",
            "request_path": "/api/demo/synthetic-session", "http_method": "GET", "status_code": 200}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", required=True)
    ap.add_argument("--token")
    ap.add_argument("--rate", type=float, default=20)
    ap.add_argument("--seconds", type=float, default=15)
    ap.add_argument("--workers", type=int, default=16)
    args = ap.parse_args()
    print(json.dumps(run(args.url, args.token, args.rate, args.seconds, args.workers, synthetic_event), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
