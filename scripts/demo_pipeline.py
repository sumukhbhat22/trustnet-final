#!/usr/bin/env python3
"""Deterministic end-to-end demo: event -> persisted -> risk -> incident -> agent -> verdict -> score effect.

Runs the real FastAPI app in-process against a TEMPORARY database. Every event is labelled
source="synthetic" (demo data); nothing here is real-world telemetry. Usage: python scripts/demo_pipeline.py
"""
import json, os, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
os.environ["TRUSTNET_DB_PATH"] = str(Path(tempfile.mkdtemp(prefix="trustnet-demo-")) / "demo.db")

from fastapi.testclient import TestClient  # noqa: E402
import main  # noqa: E402
from models.security_auth import get_user_by_id, issue_access_token, list_users, reset_auth_state  # noqa: E402

def show(title, data):
    print(f"\n== {title}\n{json.dumps(data, indent=2, default=str)[:1400]}")

with TestClient(main.app) as client:
    reset_auth_state(); list_users()
    admin = {"Authorization": f"Bearer {issue_access_token(get_user_by_id('sumukh'))}"}
    show("1. Saved risk policy (read by the single risk engine)", client.get("/api/risk-policy", headers=admin).json())
    event = {"event_id": "DEMO-EVT-0001", "user_id": "demo_user", "source": "synthetic", "request_path": "/login",
             "behavioral_score": 92, "anomaly_score": 85, "classifier_label": "credential_theft", "classifier_confidence": 90}
    r = client.post("/api/events/ingest", headers=admin, json=event).json()
    show("2. Ingest (persisted event, fused risk, incident)", {k: r[k] for k in ("accepted", "data_label", "incident_id", "incident_created")} | {"score": r["risk"]["score"], "policy": r["risk"]["policy"]})
    show("3. Duplicate delivery is idempotent", client.post("/api/events/ingest", headers=admin, json=event).json())
    incident_id = r["incident_id"]
    show("4. Agent pipeline view (investigation, proposed responses, activity)", {k: v for k, v in client.get(f"/api/incidents/{incident_id}/agent", headers=admin).json().items() if k in ("investigation", "responses")})
    v = client.post(f"/api/incidents/{incident_id}/verdict", headers=admin, json={"verdict": "false_positive", "notes": "demo"}).json()
    show("5. Analyst verdict -> before/after score", v["score_effect"])
    show("6. Audit chain integrity", client.get("/api/audit/verify", headers=admin).json())
