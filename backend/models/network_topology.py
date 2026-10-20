"""Build the dashboard topology from live identities, devices, and asset policy."""

from __future__ import annotations

import json
from typing import Any

from models.database import get_db_connection
from models.device_registry import list_devices
from models.incident_store import list_incidents
from models.security_auth import list_users

_DEMO_ASSETS = (
    ("asset-people-api", "People Directory API", "app", 3, "internal"),
    ("asset-analytics-db", "Analytics Warehouse", "database", 4, "confidential"),
    ("asset-identity-vault", "Identity Vault", "database", 5, "restricted"),
    ("admin-db", "Administration Database", "database", 5, "restricted"),
    ("finance-db", "Finance Database", "database", 5, "restricted"),
    ("hr-records", "Human Resources Records", "database", 4, "confidential"),
    ("file-export-log", "File Export Log", "service", 4, "confidential"),
)

# Demo authorization is least-privilege: analysts and viewers cannot write or
# reach the restricted identity vault.
_DEMO_POLICIES = (
    ("admin", "asset-people-api", "read", 1),
    ("admin", "asset-people-api", "write", 1),
    ("admin", "asset-analytics-db", "read", 1),
    ("admin", "asset-analytics-db", "write", 1),
    ("admin", "asset-identity-vault", "read", 1),
    ("admin", "asset-identity-vault", "write", 1),
    ("analyst", "asset-people-api", "read", 1),
    ("analyst", "asset-analytics-db", "read", 1),
    ("viewer", "asset-people-api", "read", 1),
    ("admin", "admin-db", "read", 1),
    ("admin", "admin-db", "write", 1),
    ("admin", "finance-db", "read", 1),
    ("admin", "finance-db", "write", 1),
    ("admin", "hr-records", "read", 1),
    ("admin", "file-export-log", "read", 1),
    ("analyst", "finance-db", "read", 1),
    ("analyst", "hr-records", "read", 1),
    ("analyst", "file-export-log", "read", 1),
)


def list_protected_assets() -> list[dict[str, Any]]:
    connection = get_db_connection()
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.executemany(
            """INSERT OR IGNORE INTO protected_assets
               (asset_id, label, asset_type, criticality, classification)
               VALUES (?, ?, ?, ?, ?)""",
            _DEMO_ASSETS,
        )
        connection.executemany(
            """INSERT OR IGNORE INTO asset_policies (role, asset_id, action, allowed)
               VALUES (?, ?, ?, ?)""",
            _DEMO_POLICIES,
        )
        connection.commit()
        rows = connection.execute(
            """SELECT asset_id, label, asset_type, criticality, classification
               FROM protected_assets ORDER BY criticality DESC, label"""
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def authorize_asset_read(role: str, asset_id: str) -> dict[str, Any] | None:
    list_protected_assets()
    connection = get_db_connection()
    try:
        asset = connection.execute(
            """SELECT asset_id, label, asset_type, criticality, classification
               FROM protected_assets WHERE asset_id = ?""",
            (asset_id,),
        ).fetchone()
        if asset is None:
            return None
        policy = connection.execute(
            """SELECT allowed FROM asset_policies
               WHERE role = ? AND asset_id = ? AND action = 'read'""",
            (role, asset_id),
        ).fetchone()
        return {"asset": dict(asset), "allowed": bool(policy and policy["allowed"])}
    finally:
        connection.close()


def build_network_topology() -> dict[str, Any]:
    users = list_users()
    devices = list_devices()
    assets = list_protected_assets()
    incidents = list_incidents(status="active")
    user_risk: dict[str, float] = {}
    device_risk: dict[str, float] = {}
    for incident in incidents:
        user_id = incident["user_id"]
        user_risk[user_id] = max(user_risk.get(user_id, 0.0), float(incident["risk_score"]))
        device_id = incident.get("device_id")
        if device_id:
            device_risk[device_id] = max(device_risk.get(device_id, 0.0), float(incident["risk_score"]))

    connection = get_db_connection()
    try:
        policies = connection.execute(
            "SELECT role, asset_id FROM asset_policies WHERE allowed = 1 AND action = 'read'"
        ).fetchall()
    finally:
        connection.close()
    accessible_assets: dict[str, set[str]] = {}
    for policy in policies:
        accessible_assets.setdefault(policy["role"], set()).add(policy["asset_id"])

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    positions = {
        "user": _column_positions(users, 105),
        "device": _column_positions(devices, 400),
        "asset": _column_positions(assets, 695),
    }

    def add_node(node_id: str, label: str, node_type: str, x: float, y: float, risk: float,
                 criticality: int | None = None) -> None:
        extra = {} if criticality is None else {
            "criticality": criticality,
            # Blast radius = propagated risk scaled by the saved asset criticality (F-28).
            "blastRadius": round(risk * criticality / 5),
        }
        nodes.append({
            **extra,
            "id": node_id,
            "label": label,
            "type": node_type,
            "x": x,
            "y": y,
            "compromised": risk >= 70,
            "propagationRisk": round(risk),
        })

    users_by_id = {user["id"]: user for user in users}
    for user, (x, y) in zip(users, positions["user"]):
        add_node(f"user:{user['id']}", user["email"], "user", x, y, user_risk.get(user["id"], 0.0))

    asset_risks = {asset["asset_id"]: 0.0 for asset in assets}
    for device, (x, y) in zip(devices, positions["device"]):
        user = users_by_id.get(device["user_id"])
        risk = 100.0 if device["quarantined"] else max(
            device_risk.get(device["device_id"], 0.0), user_risk.get(device["user_id"], 0.0)
        )
        device_node_id = f"device:{device['device_id']}"
        add_node(device_node_id, device["label"], "device", x, y, risk)
        if user:
            edges.append({
                "from": f"user:{user['id']}", "to": device_node_id,
                "active": True, "attackPath": risk >= 50,
            })
            for asset_id in accessible_assets.get(user["role"], set()):
                if asset_id not in asset_risks:
                    continue
                asset_risks[asset_id] = max(asset_risks[asset_id], risk)
                edges.append({
                    "from": device_node_id, "to": f"asset:{asset_id}",
                    "active": True, "attackPath": risk >= 50,
                })

    # Include real persisted protected-asset access attempts in the topology. A denied
    # access is still an attempted path and is rendered as an attack edge, not as an
    # authorized relationship. Event payloads contain metadata only.
    connection = get_db_connection()
    try:
        access_rows = connection.execute(
            "SELECT event_payload FROM security_events WHERE event_category='protected_asset_access' ORDER BY timestamp DESC LIMIT 500"
        ).fetchall()
    finally:
        connection.close()
    access_edges: list[dict[str, Any]] = []
    known_edge_pairs = {(edge["from"], edge["to"]) for edge in edges}
    known_device_ids = {device["device_id"] for device in devices}
    known_asset_ids = {asset["asset_id"] for asset in assets}
    for row in access_rows:
        try:
            payload = json.loads(row["event_payload"] or "{}")
        except (TypeError, ValueError):
            continue
        asset_id = str(payload.get("asset_id") or "")
        device_id = str(payload.get("device_id") or "")
        if asset_id not in known_asset_ids:
            continue
        if not payload.get("allowed", False):
            asset_risks[asset_id] = max(asset_risks.get(asset_id, 0.0), 100.0)
        elif device_id in device_risk:
            asset_risks[asset_id] = max(asset_risks.get(asset_id, 0.0), device_risk[device_id])
        if device_id in known_device_ids:
            source, target = f"device:{device_id}", f"asset:{asset_id}"
            if (source, target) not in known_edge_pairs:
                access_edges.append({"from": source, "to": target, "active": True,
                                     "attackPath": not bool(payload.get("allowed", False)) or asset_risks.get(asset_id, 0.0) >= 50,
                                     "accessAttempt": True, "allowed": bool(payload.get("allowed", False))})
                known_edge_pairs.add((source, target))

    for asset, (x, y) in zip(assets, positions["asset"]):
        add_node(
            f"asset:{asset['asset_id']}", asset["label"], asset["asset_type"],
            x, y, asset_risks[asset["asset_id"]], criticality=int(asset["criticality"]),
        )
    edges.extend(access_edges)
    return {"nodes": nodes, "edges": edges, "assets": assets, "policy_default": "deny"}


def _column_positions(items: list[dict[str, Any]], x: float) -> list[tuple[float, float]]:
    if not items:
        return []
    spacing = 380 / (len(items) + 1)
    return [(x, 50 + spacing * index) for index in range(1, len(items) + 1)]
