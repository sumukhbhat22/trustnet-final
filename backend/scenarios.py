"""Paced local runner for the real TrustNet demo scenario API.

Requires DEMO_MODE=1 on the server and an administrator bearer token supplied
through TRUSTNET_DEMO_TOKEN. This sends requests only to the configured local/demo
TrustNet API; it does not execute attacks or contact external targets.
"""
from __future__ import annotations
import argparse
import json
import os
import time
import requests
from demo_scenarios import SCENARIOS


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay synthetic TrustNet scenarios through the API")
    parser.add_argument("--server", default=os.environ.get("TRUSTNET_API_URL", "http://127.0.0.1:8010/api"))
    parser.add_argument("--scenario", choices=[s["id"] for s in SCENARIOS] + ["all"], default="all")
    parser.add_argument("--interval", type=float, default=3.0)
    args = parser.parse_args()
    token = os.environ.get("TRUSTNET_DEMO_TOKEN", "")
    if not token:
        raise SystemExit("Set TRUSTNET_DEMO_TOKEN to an administrator access token. Do not hardcode tokens.")
    if args.interval < 0.5 or args.interval > 60:
        raise SystemExit("--interval must be between 0.5 and 60 seconds")
    selected = SCENARIOS if args.scenario == "all" else [next(s for s in SCENARIOS if s["id"] == args.scenario)]
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    for index, scenario in enumerate(selected):
        response = session.post(f"{args.server.rstrip('/')}/demo/scenarios/{scenario['id']}/replay", timeout=15)
        if not response.ok:
            raise SystemExit(f"Scenario {scenario['id']} failed: HTTP {response.status_code}: {response.text[:300]}")
        print(json.dumps({"step": index + 1, "total": len(selected), "scenario": scenario["id"], "result": response.json()}, indent=2))
        if index + 1 < len(selected):
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
