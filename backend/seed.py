"""Seed deterministic fictional TrustNet demo identities and historical activity.

Usage (local demo only): DEMO_MODE=1 python backend/seed.py
This never runs in production and does not seed a well-known administrator password.
All generated people and activity are fictional and explicitly tagged synthetic.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import os
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from models.database import initialize_database, get_db_connection
from models.security_auth import create_user, list_users, get_user_by_id
from models.device_registry import register_login_device
from models.network_topology import list_protected_assets
from models.security_events import persist_security_event, initialize_audit_chain

SEED = 42


def main() -> None:
    if os.environ.get("DEMO_MODE", "").strip().lower() not in {"1", "true", "yes", "on"}:
        raise SystemExit("Refusing to seed: set DEMO_MODE=1 explicitly.")
    if os.environ.get("TRUSTNET_ENV", "development").strip().lower() == "production":
        raise SystemExit("Refusing to seed synthetic data in production.")

    random.seed(SEED)
    initialize_database()
    initialize_audit_chain()
    existing = {u["email"].lower() for u in list_users()}
    for index in range(1, 21):
        email = f"demo.employee{index:02d}@trustnet.local"
        if email not in existing:
            # Deterministic unique demo-only secret; no administrator account is created here.
            password = "DemoOnly-" + hashlib.sha256(f"trustnet-demo-{SEED}-{index}".encode()).hexdigest()[:24] + "!"
            create_user(email, password, "analyst" if index % 7 == 0 else "viewer", user_id=f"demo-employee-{index:02d}")
        user = get_user_by_id(f"demo-employee-{index:02d}")
        if user:
            register_login_device(user["id"], {
                "userAgent": "TrustNet Synthetic Client", "platform": "Demo OS", "language": "en-US",
                "screenResolution": "1920x1080", "timezone": "Asia/Kolkata", "canvasHash": f"seed-device-{index:02d}",
                "webglRenderer": "Synthetic GPU", "hardwareConcurrency": 8, "colorDepth": 24, "deviceType": "desktop",
            }, first_login=True)

    list_protected_assets()
    conn = get_db_connection()
    try:
        existing_seed = conn.execute("SELECT COUNT(*) FROM security_events WHERE event_category='seeded_synthetic_activity'").fetchone()[0]
    finally:
        conn.close()
    if existing_seed:
        print(f"Seed already present ({existing_seed} synthetic events); no duplicate history added.")
        return

    now = datetime.now(timezone.utc)
    cities = ["Bengaluru", "Mysuru", "Hyderabad", "Pune", "Chennai"]
    for day in range(21):
        for index in range(1, 21):
            # Working-hour patterns with small deterministic jitter; all values are fabricated.
            for session in range(2 if index % 4 == 0 else 1):
                hour = max(9, min(18, 9 + (index % 7) + random.choice([-1, 0, 0, 1])))
                stamp = (now - timedelta(days=20-day, hours=now.hour-hour, minutes=random.randrange(0, 60))).isoformat()
                event_id = f"SEED-{day:02d}-{index:02d}-{session:02d}"
                persist_security_event({
                    "id": event_id, "timestamp": stamp, "user_id": f"demo-employee-{index:02d}",
                    "ip_address": f"192.0.2.{(index % 200) + 1}", "device_fingerprint_hash": hashlib.sha256(f"device-{index}".encode()).hexdigest(),
                    "request_path": "/api/demo/synthetic-session", "http_method": "GET", "status_code": 200,
                    "session_id": f"synthetic-session-{day}-{index}-{session}", "event_category": "seeded_synthetic_activity",
                    "risk_indicators": [], "event_payload": {"synthetic": True, "seed": SEED, "city": cities[index % len(cities)], "working_hour": hour, "data_volume_mb": random.randint(5, 120), "api_calls": random.randint(8, 70)},
                })
    print("Seed complete: 20 fictional users, synthetic devices, protected demo assets, and 21 days of synthetic activity.")
    print("Data notice: all generated identities, IPs, locations, and activity are fictional.")


if __name__ == "__main__":
    main()
