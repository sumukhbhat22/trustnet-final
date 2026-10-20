"""Trusted/rogue client helper for TrustNet's local demo API."""
from __future__ import annotations
import argparse
import os
import requests

ASSETS = ("asset-people-api", "admin-db", "finance-db", "hr-records", "file-export-log")

def main() -> None:
    parser = argparse.ArgumentParser(description="Request metadata-only protected assets in a local TrustNet demo")
    parser.add_argument("--role", choices=("trusted", "rogue"), required=True)
    parser.add_argument("--server", default=os.environ.get("TRUSTNET_API_URL", "http://127.0.0.1:8010/api"))
    parser.add_argument("--asset", choices=ASSETS, default="admin-db")
    args = parser.parse_args()
    token = os.environ.get("TRUSTNET_TRUSTED_TOKEN" if args.role == "trusted" else "TRUSTNET_ROGUE_TOKEN", "")
    if not token:
        raise SystemExit(f"Set {'TRUSTNET_TRUSTED_TOKEN' if args.role == 'trusted' else 'TRUSTNET_ROGUE_TOKEN'}; never put tokens in source code.")
    response = requests.get(f"{args.server.rstrip('/')}/protected-assets/{args.asset}", headers={"Authorization": f"Bearer {token}"}, timeout=10)
    print(f"role={args.role} asset={args.asset} status={response.status_code}")
    print(response.text[:1000])

if __name__ == "__main__":
    main()
