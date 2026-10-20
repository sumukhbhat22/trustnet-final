"""
Main FastAPI application for TrustNet AI Guardian ML Backend
Provides endpoints for anomaly detection, risk scoring, and network analysis
"""
import sys
import ipaddress
import math
import os
import re
from pathlib import Path

# Set up path
backend_path = str(Path(__file__).parent)
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from fastapi import FastAPI, APIRouter, HTTPException, Body, Request, Response, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi import status
import jwt
from fastapi.middleware.cors import CORSMiddleware
import numpy as np
from datetime import datetime, timezone
import json
import asyncio
import logging
import time
from uuid import uuid4
from contextlib import asynccontextmanager
from models.optimized_models import anomaly_detector, risk_scorer, propagation_analyzer
from models.threat_classifier import threat_classifier
import attack_chain as attack_chain_module
from models.login_detector import (
    geoip_lookup, haversine, hash_fingerprint, compare_fingerprints,
    build_feature_vector, get_or_create_baseline, reset_baseline,
    reset_all_baselines, user_baselines, close_geoip_client,
)
from models import rate_limit
from models.account_restrictions import (
    active_restriction, create_restriction, list_restrictions, release_restriction,
)
from models.device_registry import get_device, list_devices, register_login_device, reset_devices, reset_user_devices, set_device_status
from models.risk_engine import compute_risk, get_signals, list_known_users, record_signals, reset_risk_state, reset_user_risk
from models import risk_policy
from models.incident_store import (
    attach_events_to_active_incidents, get_incident, get_incident_events,
    list_incidents, maybe_create_risk_incident, reset_incidents, transition_incident,
)
from models.security_auth import (
    PERMISSIONS, authenticate, create_user, decode_access_token, get_user_by_id,
    issue_access_token, list_users, login_history, reset_auth_state, revoke_access_token, update_user_account,
    consume_websocket_ticket, create_websocket_ticket, finalize_login_attempt, ACCESS_TOKEN_MINUTES,
)
from models.network_monitor import (
    list_network_events, network_anomaly_count, record_auth_failure,
    record_request, reset_network_state,
)
from models.request_policy import should_record_request
from models.explainability import build_full_explanation, explain_risk_score, explain_propagation
from models.database import initialize_database, get_db_connection
from models.refresh_tokens import issue_refresh_token, rotate_refresh_token, revoke_refresh_token
from agents import orchestrator as agent_orchestrator
from agents import learning as agent_learning
from agents import response as agent_response
from agents.common import get_settings as get_agent_settings, list_activity as list_agent_activity, update_settings as update_agent_settings, audit as agent_audit, reset_agent_state
from agents import notifier as agent_notifier
from agents.notifier import list_notifications
from models.security_events import (
    initialize_audit_chain, list_authentication_events, verify_audit_chain,
    persist_security_event, validate_security_event,
)
from models.csi_simulator import generate_simulated_sample
from models.behavior_profiles import build_user_profile
from models.mfa import enforce_mfa, require_mfa_for_user, create_mfa_challenge, verify_mfa_challenge, clear_mfa_state, mark_mfa_verified
from models import totp_service
import event_export
from models.security_events import verify_audit_anchors
from models.geo_policy import evaluate_country_policy
from models.network_topology import authorize_asset_read, build_network_topology, list_protected_assets
from models import asset_criticality
from models.incident_report import generate_incident_pdf
from demo_scenarios import build_replay_plan
from models.risk_engine import (
    calculate_centralized_risk, get_restrict_threshold, risk_tier_for_score,
    set_restrict_threshold,
)
from routes.schemas import (
    RiskScoreRequest, RiskScoreResponse, AnomalyDetectionRequest,
    PropagationAnalysisRequest, HealthResponse
)

models_ready = False
active_model_info: dict = {"source": "synthetic", "name": "isolation_forest_synthetic", "version": "synthetic-1", "data_source": "synthetic generated records", "trained_on_real_data": False}
_DEMO_ACCOUNT_ID = "trustnet-demo"
ANOMALY_FEATURE_ORDER = (
    "session_duration",
    "data_volume",
    "api_calls",
    "geo_distance",
    "login_hour",
)

# ── WebSocket connection manager (for instant dashboard push) ──
WS_MAX_LIFETIME_SECONDS = ACCESS_TOKEN_MINUTES * 60  # a socket never outlives the access token that minted its ticket


class ConnectionManager:
    """Manages WebSocket connections for live push to all dashboards."""
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self._meta: dict[int, dict] = {}  # id(ws) -> {"user_id", "expires"}

    async def connect(self, ws: WebSocket, user_id: str | None = None):
        await ws.accept()
        self.active_connections.append(ws)
        self._meta[id(ws)] = {"user_id": user_id, "expires": time.monotonic() + WS_MAX_LIFETIME_SECONDS}
        print(f"Dashboard connected via WebSocket ({len(self.active_connections)} total)")

    def disconnect(self, ws: WebSocket):
        self._meta.pop(id(ws), None)
        if ws in self.active_connections:
            self.active_connections.remove(ws)
            print(f"Dashboard disconnected ({len(self.active_connections)} remaining)")

    async def close_for_user(self, user_id: str, reason: str = "Session ended") -> int:
        """Close every live socket that belongs to a user (logout / revoked access)."""
        targets = [c for c in list(self.active_connections) if self._meta.get(id(c), {}).get("user_id") == user_id]
        for conn in targets:
            try:
                await conn.close(code=4401, reason=reason)
            except Exception:
                pass
            self.disconnect(conn)
        return len(targets)

    async def broadcast(self, data: dict):
        """Push a threat event to ALL connected dashboards instantly."""
        message = json.dumps(data)
        dead = []
        now = time.monotonic()
        for conn in list(self.active_connections):
            meta = self._meta.get(id(conn))
            if meta and meta["expires"] <= now:  # expired session: close instead of sending more data
                try:
                    await conn.close(code=4401, reason="Session expired")
                except Exception:
                    pass
                dead.append(conn)
                continue
            try:
                await conn.send_text(message)
            except Exception:
                dead.append(conn)
        for d in dead:
            self.disconnect(d)

    # Alias used throughout the codebase
    async def broadcast_to_admins(self, data: dict):
        await self.broadcast(data)

ws_manager = ConnectionManager()

# ── In-memory live threat feed (updated by attack simulator, polled by frontend)
live_threat_state = {
    "active": False,
    "phase": "idle",           # idle | recon | escalation | breach | exfiltration
    "risk_score": 0,
    "threat_level": "safe",
    "attacker_ip": None,
    "attacker_location": None,
    "attacker_device": None,
    "target_user": None,
    "anomalies": [],
    "ml_result": {},
    "incident": None,
    "compromised_nodes": [],
    "timestamp": None,
}

def reset_live_threat():
    global live_threat_state
    live_threat_state = {
        "active": False,
        "phase": "idle",
        "risk_score": 0,
        "threat_level": "safe",
        "attacker_ip": None,
        "attacker_location": None,
        "attacker_device": None,
        "target_user": None,
        "anomalies": [],
        "ml_result": {},
        "incident": None,
        "compromised_nodes": [],
        "timestamp": None,
    }


def initialize_models() -> None:
    """Train demo models once during application startup and publish readiness."""
    global models_ready
    models_ready = False
    print("\n" + "=" * 70)
    print("TrustNet ML Backend Starting Up")
    print("=" * 70)
    try:
        print("\nTraining Isolation Forest with optimal parameters...")
        anomaly_result = anomaly_detector.train()
        if anomaly_result.get("status") != "success":
            raise RuntimeError(anomaly_result.get("message", "Isolation Forest training failed."))
        print("Anomaly Detector Ready!")
        # Prefer a real-data model when one exists; otherwise keep the synthetic one and say so.
        from ml.registry import try_load_real_model
        global active_model_info
        active_model_info = try_load_real_model(anomaly_detector)
        print(f"   - Model source: {active_model_info['source']} ({active_model_info.get('version')})")
        print(f"   - Precision: {anomaly_result['metrics'].get('precision', 'N/A')}")
        print(f"   - Recall: {anomaly_result['metrics'].get('recall', 'N/A')}")
        print(f"   - F1-Score: {anomaly_result['metrics'].get('f1', 'N/A')}")
        print(f"   - Best Contamination: {anomaly_result['best_params'].get('contamination')}")
        print(f"   - N-Estimators: {anomaly_result['best_params'].get('n_estimators')}")

        print("\nRisk Scorer initialized with optimal weights")
        print("Propagation Analyzer initialized")
        print("\n" + "-" * 60)
        classifier_result = threat_classifier.train()
        if classifier_result.get("status") != "success":
            raise RuntimeError(classifier_result.get("message", "Threat classifier training failed."))
        metrics = classifier_result["metrics"]
        print("\nThreat Classifier Ready!")
        print(f"   - Ensemble Accuracy: {metrics['accuracy']}")
        print(f"   - F1 (weighted):     {metrics['f1_weighted']}")
        print("   - Validation:       stratified 80/20 holdout")
        print("-" * 60)

        models_ready = bool(anomaly_detector.trained and threat_classifier.trained)
        if not models_ready:
            raise RuntimeError("One or more required ML models did not finish training.")
        print("\n" + "=" * 70)
        print("TrustNet ML Backend Ready - All Models Trained")
        print("=" * 70 + "\n")
    except Exception:
        models_ready = False
        print("Model startup failed; API remains unavailable until restart.")
        raise


@asynccontextmanager
async def lifespan(_app: FastAPI):
    initialize_database()
    initialize_audit_chain()
    # Recover interrupted approvals at startup, not only when an incident is
    # investigated again. Never replay an interrupted action: response.recover_stuck
    # marks stale `executing` rows failed and appends an audit event.
    recovered_actions = agent_response.recover_stuck()
    expired_approvals = agent_response.expire_stale()
    if recovered_actions or expired_approvals:
        print(
            "TrustNet recovery: "
            f"{recovered_actions} interrupted action(s) marked failed; "
            f"{expired_approvals} expired approval(s) closed."
        )
    initialize_models()
    try:
        yield
    finally:
        await close_geoip_client()
        print("TrustNet ML Backend shutting down...")


def dashboard_summary_payload() -> dict:
    """Build the current authoritative in-memory dashboard summary."""
    risks = [compute_risk(user_id) for user_id in list_known_users()]
    device_rows = list_devices()
    incident_rows = list_incidents()
    active_incidents = [item for item in incident_rows if item["status"] in {"open", "investigating"}]
    return {
        "generated_at": datetime.now().astimezone().isoformat(),
        "overall_risk": {
            "average": round(sum(item["score"] for item in risks) / len(risks), 2) if risks else 0.0,
            "maximum": max((item["score"] for item in risks), default=0.0),
            "users_scored": len(risks),
        },
        "active_incident_count": len(active_incidents),
        "network_anomalies": network_anomaly_count(),
        "device_counts": {
            "total": len(device_rows),
            "trusted": sum(item["trust_status"] == "trusted" for item in device_rows),
            "unknown": sum(item["trust_status"] == "unknown" for item in device_rows),
            "flagged": sum(item["trust_status"] == "flagged" for item in device_rows),
        },
        # Stable, documented aliases for the dashboard summary contract.
        # Keep the older fields above for compatibility with existing pages.
        "systemRisk": max((item["score"] for item in risks), default=0.0),
        "avgUserRisk": round(sum(item["score"] for item in risks) / len(risks), 2) if risks else 0.0,
        "openIncidents": len(active_incidents),
        "anomalies": network_anomaly_count(),
        "trustedDevices": sum(item["trust_status"] == "trusted" for item in device_rows),
        "devicesToReview": sum(item["trust_status"] in {"unknown", "flagged"} for item in device_rows),
        "networkAnomalies": network_anomaly_count(),
        "mlStatus": "available" if models_ready else "initializing",
        "dataSource": "runtime",
        "recent_incidents": incident_rows[:5],
        "data_scope": "Runtime risk signals and SQLite-backed device/incident records; seeded/demo events may be synthetic.",
    }


async def broadcast_dashboard_update(reason: str) -> None:
    await ws_manager.broadcast_to_admins({
        "type": "dashboard_update",
        "reason": reason,
        "summary": dashboard_summary_payload(),
        "timestamp": datetime.now().astimezone().isoformat(),
    })

async def run_agents(incident: dict | None, trigger: str) -> dict | None:
    """Run the agent pipeline for an incident and push real activity to admin dashboards."""
    if not incident:
        return None
    try:
        summary = await asyncio.to_thread(agent_orchestrator.process_incident, incident["id"], trigger)
    except Exception as error:  # agent failure must never break login/risk handling
        print(f"Agent pipeline error for {incident['id']}: {error}")
        return None
    if summary and summary.get("ran"):
        await ws_manager.broadcast_to_admins({
            "type": "agent_activity", "trigger": trigger, "summary": summary,
            "activity": list_agent_activity(8, incident["id"]),
            "timestamp": datetime.now().astimezone().isoformat(),
        })
        await broadcast_dashboard_update("agent_activity")
    return summary


async def export_record(kind: str, record: dict | None) -> None:
    """Send an incident/approval summary to the optional SIEM export (off unless TRUSTNET_EXPORT_ENABLED=1).

    Only a minimal summary leaves the system. Delivery runs in a thread and never raises; each attempt is audited.
    """
    cfg = event_export.config_from_env()
    if not cfg["enabled"] or not record:
        return

    def _audit(action: str, payload: dict) -> None:
        agent_audit("export", action, incident=None, actor="system:event_export", payload=payload)

    try:
        await asyncio.to_thread(event_export.export_event, kind, record, cfg, _audit)
    except Exception as error:  # noqa: BLE001 - export must never break the request path
        logging.getLogger("trustnet.export").warning("event export failed: %s", type(error).__name__)


def _incident_summary(incident: dict) -> dict:
    keys = ("id", "status", "user_id", "type", "threat_level", "risk_score", "attack_type", "response_action", "created_at", "updated_at")
    return {k: incident.get(k) for k in keys if k in incident}


async def open_incident(risk: dict, *, evidence: list[str] | None = None, event_ids: list[str] | None = None, trigger: str = "pipeline") -> dict | None:
    """Create/update the persistent incident, then run the agent pipeline on it."""
    incident = maybe_create_risk_incident(risk, evidence=evidence, event_ids=event_ids)
    if incident:
        await run_agents(incident, trigger)
        incident = get_incident(incident["id"]) or incident
        await export_record("incident", _incident_summary(incident))
    return incident


# Create FastAPI app
app = FastAPI(
    title="TrustNet AI Guardian ML Backend",
    description="Advanced ML-powered security threat detection and analysis",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS: explicit origins only (override with TRUSTNET_CORS_ORIGINS="https://a.example,https://b.example").
_DEFAULT_CORS_ORIGINS = "http://localhost:8080,http://127.0.0.1:8080,http://localhost:8081,http://127.0.0.1:8081,http://localhost:5173,http://127.0.0.1:5173"
_CORS_ORIGINS = [o.strip() for o in os.environ.get("TRUSTNET_CORS_ORIGINS", _DEFAULT_CORS_ORIGINS).split(",") if o.strip() and o.strip() != "*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=3600,
)


@app.middleware("http")
async def enforce_rate_limits(request: Request, call_next):
    """Return 429 when a client IP exceeds the API or login limits (when enabled)."""
    if rate_limit.enabled() and request.url.path.startswith("/api"):
        ip = _client_ip(request)
        is_login = request.method == "POST" and request.url.path in {"/api/login", "/api/auth/login"}
        if (is_login and not rate_limit.login_limiter.allow(ip)) or not rate_limit.api_limiter.allow(ip):
            return JSONResponse(status_code=429, content={"detail": "Too many requests. Slow down and retry shortly."},
                                headers={"Retry-After": "60"})
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith("/api"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.middleware("http")
async def network_request_monitor(request: Request, call_next):
    """Record API traffic and push observable request/anomaly events to dashboards."""
    started = asyncio.get_running_loop().time()
    response = await call_next(request)
    auth_context = getattr(request.state, "authentication_event_context", None)
    if (
        auth_context
        and not getattr(request.state, "authentication_event_recorded", False)
        and response.status_code >= 500
    ):
        await _record_authentication_event(
            request,
            username=auth_context["username"],
            source_ip=auth_context["source_ip"],
            outcome="FAILURE",
            reason="authentication_pipeline_error",
            event_source=auth_context["event_source"],
            status_code=response.status_code,
            user_id=auth_context.get("user_id"),
        )
    elif (
        request.method == "POST"
        and request.url.path in {"/api/login", "/api/auth/login"}
        and response.status_code == 422
        and not getattr(request.state, "authentication_event_recorded", False)
    ):
        await _record_authentication_event(
            request,
            username="invalid_input",
            source_ip=_client_ip(request),
            outcome="FAILURE",
            reason="invalid_request",
            event_source="LIVE",
            status_code=422,
        )
    if request.url.path.startswith("/api/") and should_record_request(request.method, request.url.path):
        endpoint = re.sub(r"(?<=/)(?:dev-[a-f0-9]{16}|INC-[A-F0-9]{10})(?=/|$)", "{id}", request.url.path)
        actor = getattr(request.state, "authenticated_user", None)
        user_id = actor["id"] if actor else None
        try:
            authorization = request.headers.get("authorization", "")
            if user_id is None and authorization.lower().startswith("bearer "):
                claims = decode_access_token(authorization[7:].strip())
                candidate = get_user_by_id(str(claims.get("sub", "")))
                if candidate and candidate["role"] == claims.get("role"):
                    user_id = candidate["id"]
                    request.state.token_device_id = claims.get("device_id")
        except (jwt.PyJWTError, ValueError, TypeError):
            pass
        elapsed_ms = (asyncio.get_running_loop().time() - started) * 1000
        event, anomalies = record_request(
            ip=_client_ip(request), user_id=user_id, endpoint=endpoint,
            method=request.method, status_code=response.status_code, response_time_ms=elapsed_ms,
        )
        extra_anomalies = getattr(request.state, "extra_network_anomalies", [])
        if extra_anomalies:
            event["anomaly_types"] = list(dict.fromkeys(event["anomaly_types"] + [item["anomaly_types"][0] for item in extra_anomalies]))
            event["evidence"] = "; ".join(filter(None, [event.get("evidence"), *(item.get("evidence") for item in extra_anomalies)]))
            event["affected_users"] = extra_anomalies[0].get("affected_users", [])
            anomalies.extend(extra_anomalies)
        await ws_manager.broadcast_to_admins({"type": "network_event", "event": event, "anomalies": anomalies})
        affected_users = {user_id} if user_id and anomalies else set()
        for anomaly in anomalies:
            affected_users.update(anomaly.get("affected_users", []))
        if affected_users:
            correlated_event_ids = [event["id"], *(item["id"] for item in anomalies)]
            for affected_user in affected_users:
                risk = compute_risk(affected_user)
                incident = await open_incident(
                    risk,
                    evidence=[item["evidence"] for item in anomalies],
                    event_ids=correlated_event_ids,
                )
                if incident:
                    await ws_manager.broadcast_to_admins({"type": "network_incident", "incident": incident})
            await broadcast_dashboard_update("network_anomaly_detected")
        if user_id:
            correlated_event_ids = [event["id"], *(item["id"] for item in anomalies)]
            attach_events_to_active_incidents(
                user_id,
                correlated_event_ids,
                device_id=getattr(request.state, "token_device_id", None),
            )
    return response

# Create router
router = APIRouter(prefix="/api", tags=["ml"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


async def get_current_user(request: Request, token: str = Depends(oauth2_scheme)) -> dict:
    """Decode a bearer token and resolve the active user on protected routes."""
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired access token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        claims = decode_access_token(token)
        user = get_user_by_id(str(claims.get("sub", "")))
        if user is None or not user["is_active"] or claims.get("role") != user["role"]:
            raise credentials_error
        token_device_id = claims.get("device_id")
        if token_device_id is not None:
            device = get_device(str(token_device_id))
            if device is None or device["user_id"] != user["id"]:
                raise credentials_error
            if device["quarantined"] or device["trust_status"] in {"flagged", "revoked"}:
                raise HTTPException(status_code=403, detail={"code": "DEVICE_REVOKED" if device["trust_status"] == "revoked" else "DEVICE_QUARANTINED", "message": "This device has been revoked or quarantined."})
        restriction = active_restriction(user["id"])
        if restriction:
            mode = restriction.get("mode", "block")
            if mode == "block":
                raise HTTPException(status_code=403, detail={"code": "BLOCKED", "expires_at": restriction["expires_at"]})
            if mode == "read_only":
                path = request.url.path
                sensitive = path.startswith(("/api/users", "/api/devices", "/api/account-restrictions", "/api/demo/", "/api/policies", "/api/audit", "/api/incidents/", "/api/hr/records", "/api/files/export")) or path.startswith("/api/protected-assets/")
                if request.method.upper() != "GET" or sensitive:
                    raise HTTPException(status_code=403, detail={"code": "RESTRICTED", "mode": "read_only", "expires_at": restriction["expires_at"]})
        # The challenge/verify endpoints must remain reachable for a user whose session
        # is waiting for step-up authentication. All other protected requests are gated.
        if request.url.path not in {"/api/mfa/challenge", "/api/mfa/verify", "/api/mfa/totp/verify", "/api/mfa/totp/status"}:
            device_key = str(claims.get("device_id") or "account")
            enforce_mfa(user["id"], device_key)
        authenticated = {**user, "token_claims": claims}
        request.state.authenticated_user = user
        return authenticated
    except (jwt.PyJWTError, ValueError, TypeError):
        raise credentials_error


def require_permission(permission: str):
    async def checker(user: dict = Depends(get_current_user)) -> dict:
        if permission not in PERMISSIONS.get(user["role"], set()):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return checker


def _client_ip(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    try:
        peer_address = ipaddress.ip_address(peer.split("%", 1)[0])
    except ValueError:
        return peer

    configured_proxies = os.environ.get("TRUSTNET_TRUSTED_PROXIES", "")
    try:
        trusted_proxies = [
            ipaddress.ip_network(value.strip(), strict=False)
            for value in configured_proxies.split(",")
            if value.strip()
        ]
    except ValueError as error:
        raise RuntimeError("TRUSTNET_TRUSTED_PROXIES must contain valid IP addresses or CIDR networks.") from error
    if not any(peer_address in network for network in trusted_proxies):
        return str(peer_address)

    forwarded_for = request.headers.get("x-forwarded-for", "")
    forwarded_values = [item.strip() for item in forwarded_for.split(",")]
    if not forwarded_for or len(forwarded_values) > 20:
        return str(peer_address)
    try:
        forwarded_addresses = [
            ipaddress.ip_address(value.split("%", 1)[0])
            for value in forwarded_values
        ]
    except ValueError:
        return str(peer_address)

    for address in reversed([*forwarded_addresses, peer_address]):
        if not any(address in network for network in trusted_proxies):
            return str(address)
    return str(forwarded_addresses[0])


async def _record_authentication_event(
    request: Request,
    *,
    username: str,
    source_ip: str,
    outcome: str,
    reason: str | None,
    event_source: str = "LIVE",
    status_code: int,
    user_id: str | None = None,
) -> dict:
    safe_reasons = {
        None, "invalid_credentials", "account_locked", "account_restricted",
        "account_inactive", "invalid_fingerprint", "geo_policy_denied",
        "device_untrusted", "device_pending", "risk_restricted",
        "authentication_pipeline_error", "authentication_unavailable", "invalid_request",
    }
    safe_reason = reason if reason in safe_reasons else "authentication_denied"
    event = persist_security_event({
        "id": f"AUTH-{uuid4().hex.upper()}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": user_id,
        "ip_address": source_ip,
        "request_path": request.url.path,
        "http_method": "POST",
        "status_code": status_code,
        "event_category": "authentication_attempt",
        "risk_indicators": [],
        "event_payload": {
            "event_type": "authentication_attempt",
            "event_source": event_source,
            "outcome": outcome,
            "username": username,
            "reason": safe_reason,
        },
    })
    request.state.authentication_event_recorded = True
    view = {
        "id": event["id"],
        "timestamp": event["timestamp"],
        "event_type": "authentication_attempt",
        "outcome": outcome,
        "username": username,
        "source_ip": source_ip,
        "reason": safe_reason,
        "event_source": event_source,
        "status_code": status_code,
    }
    await ws_manager.broadcast_to_admins({"type": "authentication_event", "event": view})
    return view


@router.post("/mfa/challenge")
async def mfa_challenge_endpoint(request: Request, user: dict = Depends(get_current_user)):
    device_key = "account"
    demo_enabled = os.environ.get("TRUSTNET_ENV", "development").lower() != "production" and os.environ.get("DEMO_MODE", "").lower() in {"1", "true", "yes", "on"}
    if not demo_enabled and not agent_notifier.smtp_configured():
        raise HTTPException(status_code=503, detail="MFA delivery is not configured. Configure SMTP or enable DEMO_MODE for a local demonstration.")
    result = create_mfa_challenge(user["id"], device_key)
    if agent_notifier.smtp_configured():
        try:
            agent_notifier.send_mfa_code(user["email"], result["code"])
        except Exception as error:
            agent_audit("mfa", "delivery_failed", incident=None, actor=f"user:{user['id']}", payload={"error_type": type(error).__name__})
            raise HTTPException(status_code=503, detail="MFA delivery failed; request a new code after checking mail configuration.") from error
    agent_audit("mfa", "challenge_created", incident=None, actor=f"user:{user['id']}", payload={"device_id": device_key, "delivery": "smtp" if agent_notifier.smtp_configured() else "demo"})
    response = {"status": "challenge_created", "expires_in_seconds": 300, "delivery": "email" if agent_notifier.smtp_configured() else "demo_only"}
    # Return a development-only code solely for a local demo; never expose it in production.
    if demo_enabled and not agent_notifier.smtp_configured():
        response["demo_code"] = result["code"]
    return response


@router.post("/mfa/verify")
async def mfa_verify_endpoint(payload: dict = Body(...), user: dict = Depends(get_current_user)):
    code = payload.get("code", "")
    if not isinstance(code, str) or not re.fullmatch(r"\d{6}", code):
        raise HTTPException(status_code=422, detail="code must be a six-digit string")
    device_key = "account"
    try:
        result = verify_mfa_challenge(user["id"], device_key, code)
    except ValueError as error:
        agent_audit("mfa", "verification_failed", incident=None, actor=f"user:{user['id']}", payload={"device_id": device_key, "reason": str(error)})
        raise HTTPException(status_code=403, detail={"code": "MFA_INVALID", "message": str(error)}) from error
    agent_audit("mfa", "verification_succeeded", incident=None, actor=f"user:{user['id']}", payload={"device_id": device_key})
    return {"status": "verified", "verified_at": result["verified_at"]}


def _totp_http_error(user: dict, action: str, error: "totp_service.TotpError") -> HTTPException:
    agent_audit("mfa", f"totp_{action}_failed", incident=None, actor=f"user:{user['id']}", payload={"code": error.code})
    return HTTPException(status_code=error.status, detail={"code": error.code, "message": error.message})


@router.get("/mfa/totp/status")
async def totp_status_endpoint(user: dict = Depends(get_current_user)):
    return totp_service.status(user["id"])


@router.post("/mfa/totp/enroll")
async def totp_enroll_endpoint(user: dict = Depends(get_current_user)):
    try:
        result = totp_service.begin_enrolment(user["id"], user["email"])
    except totp_service.TotpError as error:
        raise _totp_http_error(user, "enroll", error) from error
    agent_audit("mfa", "totp_enrolment_started", incident=None, actor=f"user:{user['id']}", payload={})
    return result


@router.post("/mfa/totp/confirm")
async def totp_confirm_endpoint(payload: dict = Body(...), user: dict = Depends(get_current_user)):
    code = payload.get("code", "")
    if not isinstance(code, str) or not re.fullmatch(r"\d{6}", code.replace(" ", "")):
        raise HTTPException(status_code=422, detail="code must be a six-digit string")
    try:
        result = totp_service.confirm_enrolment(user["id"], code)
    except totp_service.TotpError as error:
        raise _totp_http_error(user, "confirm", error) from error
    agent_audit("mfa", "totp_enrolment_confirmed", incident=None, actor=f"user:{user['id']}", payload={"backup_codes_issued": len(result["backup_codes"])})
    return result


@router.post("/mfa/totp/verify")
async def totp_verify_endpoint(payload: dict = Body(...), user: dict = Depends(get_current_user)):
    code = payload.get("code", "")
    if not isinstance(code, str) or not (4 <= len(code.strip()) <= 32):
        raise HTTPException(status_code=422, detail="code must be a TOTP code or a backup code")
    try:
        result = totp_service.verify_second_factor(user["id"], code)
    except totp_service.TotpError as error:
        raise _totp_http_error(user, "verify", error) from error
    verified_at = mark_mfa_verified(user["id"], "account")
    agent_audit("mfa", "totp_verification_succeeded", incident=None, actor=f"user:{user['id']}", payload={"method": result["method"]})
    return {"status": "verified", "verified_at": verified_at, **result}


@router.delete("/users/{user_id}/mfa/totp", dependencies=[Depends(require_permission("manage_users"))])
async def totp_admin_reset_endpoint(user_id: str, user: dict = Depends(get_current_user)):
    """Admin recovery for a lost authenticator. An administrator cannot reset their own enrolment."""
    if user_id == user["id"]:
        raise HTTPException(status_code=403, detail="Use another administrator to reset your own TOTP enrolment")
    if get_user_by_id(user_id) is None:
        raise HTTPException(status_code=404, detail="User not found")
    totp_service.disable(user_id)
    agent_audit("mfa", "totp_reset_by_admin", incident=None, actor=f"user:{user['id']}", payload={"target_user_id": user_id})
    return {"status": "totp_reset", "user_id": user_id}


@router.post("/users/{user_id}/mfa/require", dependencies=[Depends(require_permission("manage_users"))])
async def require_user_mfa_endpoint(user_id: str, user: dict = Depends(get_current_user)):
    target = get_user_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    if target["id"] == user["id"]:
        raise HTTPException(status_code=403, detail="An administrator cannot trigger step-up on their own account through this route")
    device_id = "account"
    require_mfa_for_user(target["id"], device_id)
    agent_audit("mfa", "step_up_required", incident=None, actor=f"user:{user['id']}", payload={"target_user_id": target["id"], "device_id": device_id})
    return {"status": "mfa_required", "user_id": target["id"]}


@router.post("/auth/register")
async def register_user(payload: dict = Body(...), _admin: dict = Depends(require_permission("manage_users"))):
    role = payload.get("role")
    if role not in {"analyst", "viewer"}:
        raise HTTPException(status_code=422, detail="New accounts may only be analyst or viewer roles.")
    try:
        user = create_user(str(payload.get("email", "")), str(payload.get("password", "")), role)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    return {"user": user}


@router.post("/auth/refresh")
async def auth_refresh(request: Request, response: Response):
    raw = request.cookies.get("trustnet_refresh")
    rotated = rotate_refresh_token(raw or "")
    if not rotated:
        response.delete_cookie("trustnet_refresh", path="/api/auth", httponly=True, samesite="lax")
        raise HTTPException(status_code=401, detail={"code":"REFRESH_INVALID","message":"Refresh session is invalid or expired."})
    if rotated.get("reuse_detected"):
        response.delete_cookie("trustnet_refresh", path="/api/auth", httponly=True, samesite="lax")
        agent_audit("auth", "refresh_reuse_detected", incident=None, actor=f"user:{rotated['user_id']}", payload={"family_id":rotated["family_id"]})
        raise HTTPException(status_code=401, detail={"code":"REFRESH_REUSE_DETECTED","message":"Refresh-token reuse detected; the session family was revoked."})
    user = get_user_by_id(rotated["user_id"])
    if not user or not user["is_active"]:
        revoke_refresh_token(rotated["token"])
        response.delete_cookie("trustnet_refresh", path="/api/auth", httponly=True, samesite="lax")
        raise HTTPException(status_code=401, detail={"code":"SESSION_INVALID","message":"Account is inactive."})
    device_id = rotated.get("device_id")
    if device_id:
        device = get_device(device_id)
        if not device or device.get("user_id") != user["id"] or device.get("trust_status") == "revoked" or device.get("quarantined"):
            revoke_refresh_token(rotated["token"])
            response.delete_cookie("trustnet_refresh", path="/api/auth", httponly=True, samesite="lax")
            raise HTTPException(status_code=403, detail={"code":"DEVICE_REVOKED","message":"This device cannot refresh its session."})
    response.set_cookie(key="trustnet_refresh", value=rotated["token"], httponly=True,
        secure=os.environ.get("TRUSTNET_ENV", "development").lower() == "production",
        samesite="lax", path="/api/auth", max_age=7 * 24 * 60 * 60)
    agent_audit("auth", "refresh_rotated", incident=None, actor=f"user:{user['id']}", payload={"family_id":rotated["family_id"]})
    return {"access_token":issue_access_token(user, device_id=device_id), "token_type":"bearer", "expires_in":ACCESS_TOKEN_MINUTES*60}


@router.get("/auth/me")
async def auth_me(user: dict = Depends(get_current_user)):
    return {"user": {key: value for key, value in user.items() if key != "token_claims"}, "permissions": sorted(PERMISSIONS[user["role"]])}


@router.post("/auth/logout")
async def auth_logout(request: Request, response: Response, user: dict = Depends(get_current_user)):
    revoke_access_token(user["token_claims"])
    revoke_refresh_token(request.cookies.get("trustnet_refresh"))
    response.delete_cookie("trustnet_refresh", path="/api/auth", httponly=True, samesite="lax")
    await ws_manager.close_for_user(user["id"], "Logged out")
    return {"status": "logged_out"}


@router.post("/auth/ws-ticket")
async def auth_websocket_ticket(user: dict = Depends(get_current_user)):
    return {"ticket": create_websocket_ticket(user["id"]), "expires_in": 60}


@router.get("/users", dependencies=[Depends(require_permission("manage_users"))])
async def get_users_endpoint():
    return {"users": list_users()}


@router.patch("/users/{user_id}")
async def update_user_endpoint(user_id: str, payload: dict = Body(...), user: dict = Depends(require_permission("manage_users"))):
    if user_id == user["id"] and ("role" in payload or payload.get("is_active") is False):
        raise HTTPException(status_code=403, detail="You cannot change your own role or disable your own account.")
    allowed_fields = {"role", "is_active", "password"}
    if not payload or set(payload) - allowed_fields:
        raise HTTPException(status_code=422, detail="Allowed fields: role, is_active, password.")
    try:
        updated = update_user_account(user_id, role=payload.get("role"), is_active=payload.get("is_active"), password=payload.get("password"))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    if updated is None:
        raise HTTPException(status_code=404, detail="User not found.")
    agent_audit("users", "account_updated", incident=None, actor=f"user:{user['id']}", payload={"target_user_id": user_id, "changed_fields": sorted(payload.keys())})
    if payload.get("is_active") is False:
        await ws_manager.close_for_user(user_id, "Account disabled")
    return {"user": updated}


@router.get("/users/{user_id}/login-history", dependencies=[Depends(require_permission("manage_users"))])
async def get_login_history_endpoint(user_id: str, limit: int = 100):
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
    return {"user_id": user_id, "attempts": login_history(user_id, limit)}

def _database_ok() -> bool:
    try:
        conn = get_db_connection()
        try:
            conn.execute("SELECT 1").fetchone()
        finally:
            conn.close()
        return True
    except Exception:  # noqa: BLE001 - health must report, not raise
        return False


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Readiness with a degraded mode.

    unavailable: database unreachable or models not trained. degraded: serving, but a safeguard is missing
    (fallback/synthetic model note, or audit checkpoints are unconfigured). healthy: all checks pass.
    Only booleans and status words are returned; no paths, keys or versions of secrets.
    """
    database_ok = _database_ok()
    model_info = {k: active_model_info.get(k) for k in ("source", "name", "version", "data_source", "trained_on_real_data", "degraded_note") if k in active_model_info}
    from models.security_events import _anchor_key
    checks = {
        "database": "ok" if database_ok else "down",
        "models": "ready" if models_ready else "not_ready",
        "audit_checkpoints": "configured" if _anchor_key() is not None else "unconfigured",
        "totp_encryption_key": "configured" if len(os.environ.get("TRUSTNET_TOTP_KEY", "")) >= 32 else "unconfigured",
        "event_export": "enabled" if event_export.config_from_env()["enabled"] else "off",
    }
    if not database_ok or not models_ready:
        status, message = "unavailable", "TrustNet is not ready: " + ("database unreachable" if not database_ok else "models have not completed startup training")
    elif model_info.get("degraded_note") or checks["audit_checkpoints"] == "unconfigured":
        status, message = "degraded", "TrustNet is serving with a missing safeguard; see checks"
    else:
        status, message = "healthy", "TrustNet ML models are ready"
    return {"status": status, "message": message, "version": "1.0.0", "model": model_info, "checks": checks}


@router.post("/csf/train", dependencies=[Depends(require_permission("manage_users"))])
async def csf_train(payload: dict = Body(...)):
    """Train/prepare the centralized signal model. This project keeps the model lightweight."""
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="Payload must be an object.")
    return {
        "status": "ok",
        "trained": True,
        "model": "isolation_forest",
        "description": "Centralized signal model ready for feature scoring.",
        "samples_seen": int(payload.get("samples_seen", 0) or 0),
    }


@router.post("/csf/score", dependencies=[Depends(require_permission("view_dashboard"))])
async def csf_score(payload: dict = Body(...)):
    """Calculate the centralized CSF-based risk score with validation."""
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="Payload must be an object.")
    features = payload.get("features") or {}
    if not isinstance(features, dict):
        raise HTTPException(status_code=422, detail="features must be an object.")
    try:
        score = calculate_centralized_risk(features)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    tier = risk_tier_for_score(score)
    return {
        "user_id": payload.get("user_id"),
        "risk_score": score,
        "tier": tier,
        "score_source": "centralized_csf_formula",
        "inputs": {
            "csf": float(features.get("csf", 0.0)),
            "network": float(features.get("network", 0.0)),
            "deviceUntrusted": float(features.get("deviceUntrusted", 0.0)),
            "geoFlag": float(features.get("geoFlag", 0.0)),
        },
    }


@router.post("/risk-score", response_model=RiskScoreResponse, dependencies=[Depends(require_permission("view_dashboard"))])
async def calculate_risk_score(request: RiskScoreRequest):
    """
    Calculate risk score for a user using optimized ML model
    
    Enhanced with:
    - Adaptive sensitivity
    - Confidence scoring
    - Multi-factor analysis
    """
    if not models_ready:
        raise HTTPException(status_code=503, detail="ML models are not ready yet.")
    try:
        metrics_dict = request.behavior_metrics.model_dump()
        
        # Use optimized risk scorer with adaptive sensitivity
        result = risk_scorer.calculate_risk_score(
            behavior_metrics=metrics_dict,
            anomaly_score=request.anomaly_score,
            sensitivity=1.0  # Can be adjusted per user
        )
        
        return {
            "overall_score": result['overall_score'],
            "threat_level": result['threat_level'],
            "deviations": result['deviations'],
            "recommendation": result['recommendation']
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error calculating risk score: {str(e)}")

@router.post("/anomaly-detection", dependencies=[Depends(require_permission("view_dashboard"))])
async def detect_anomalies(request: AnomalyDetectionRequest):
    """
    Detect anomalies using optimized Isolation Forest
    
    Features:
    - RobustScaler preprocessing
    - Optimal contamination parameter
    - Cross-validated hyperparameters
    """
    if not models_ready:
        raise HTTPException(status_code=503, detail="ML models are not ready yet.")
    try:
        if not request.records:
            return {"results": []}
        
        features = list(request.records[0].keys())
        if len(features) != 5 or set(features) != set(ANOMALY_FEATURE_ORDER):
            raise HTTPException(status_code=422, detail=f"Anomaly records must contain exactly these 5 features: {', '.join(ANOMALY_FEATURE_ORDER)}.")
        if any(set(record) != set(features) for record in request.records):
            raise HTTPException(status_code=422, detail="Every anomaly record must contain the same feature keys.")
        data = np.array([
            [record[feature] for feature in ANOMALY_FEATURE_ORDER]
            for record in request.records
        ], dtype=float)
        if not np.isfinite(data).all():
            raise HTTPException(status_code=422, detail="Anomaly feature values must be finite numbers.")
        
        # Use optimized prediction
        predictions, scores = anomaly_detector.predict(data)
        
        results = []
        for i, record in enumerate(request.records):
            is_anomaly = predictions[i] == -1
            anomaly_score = float(scores[i])
            
            # Better risk level classification
            if anomaly_score > 0.85:
                risk_level = "critical"
            elif anomaly_score > 0.65:
                risk_level = "high"
            elif anomaly_score > 0.4:
                risk_level = "medium"
            elif anomaly_score > 0.15:
                risk_level = "low"
            else:
                risk_level = "safe"
            
            results.append({
                **record,
                "is_anomaly": bool(is_anomaly),
                "anomaly_score": round(anomaly_score, 4),
                "risk_level": risk_level
            })
        
        return {"results": results}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error detecting anomalies: {str(e)}")


@router.post("/train-anomaly-detector", dependencies=[Depends(require_permission("manage_users"))])
async def train_anomaly_detector(training_data: dict = Body(...)):
    """Retrain the anomaly detector using the API's fixed five-feature shape."""
    global models_ready
    if not models_ready:
        raise HTTPException(status_code=503, detail="ML models are not ready yet.")
    if "data" not in training_data or "features" not in training_data:
        raise HTTPException(status_code=422, detail="Request must include 'data' and 'features'.")

    try:
        data = np.asarray(training_data["data"], dtype=float)
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=f"Training data must be a numeric matrix: {error}") from error

    features = training_data["features"]
    if data.ndim != 2 or data.shape[0] < 10:
        raise HTTPException(status_code=422, detail="Training data must be a 2D matrix with at least 10 rows.")
    if data.shape[1] != 5 or features != list(ANOMALY_FEATURE_ORDER):
        raise HTTPException(status_code=422, detail=f"Training features must be ordered as: {', '.join(ANOMALY_FEATURE_ORDER)}.")
    if not np.isfinite(data).all() or not all(isinstance(feature, str) and feature.strip() for feature in features):
        raise HTTPException(status_code=422, detail="Training values must be finite and feature names non-empty strings.")

    result = anomaly_detector.train(data, features)
    if result.get("status") != "success":
        raise HTTPException(status_code=422, detail=result.get("message", "Model training failed."))
    models_ready = bool(anomaly_detector.trained and threat_classifier.trained)
    return result

@router.post("/propagation-analysis", dependencies=[Depends(require_permission("view_dashboard"))])
async def analyze_propagation(request: PropagationAnalysisRequest):
    """Analyze risk propagation through network"""
    if not models_ready:
        raise HTTPException(status_code=503, detail="ML models are not ready yet.")
    try:
        node_ids = [node.id for node in request.nodes]
        if len(node_ids) != len(set(node_ids)):
            raise HTTPException(status_code=422, detail="Network node IDs must be unique.")
        known_ids = set(node_ids)
        invalid_edges = [
            (edge.from_node, edge.to_node)
            for edge in request.edges
            if edge.from_node not in known_ids or edge.to_node not in known_ids
        ]
        if invalid_edges:
            raise HTTPException(status_code=422, detail=f"Network edges reference unknown nodes: {invalid_edges[:5]}")

        nodes = [
            {
                "id": node.id,
                "label": node.label,
                "type": node.node_type,
                "x": node.x,
                "y": node.y,
                "compromised": node.compromised,
                "propagationRisk": node.propagationRisk
            }
            for node in request.nodes
        ]
        
        edges = [
            {
                "from": edge.from_node,
                "to": edge.to_node,
                "active": edge.active,
                "attackPath": edge.attackPath
            }
            for edge in request.edges
        ]
        
        analysis_result = propagation_analyzer.analyze_network(nodes, edges)
        
        return {
            "total_network_risk": analysis_result['total_network_risk'],
            "critical_count": len(analysis_result['critical_nodes']),
            "critical_nodes": analysis_result['critical_nodes'],
            "all_nodes": analysis_result['all_nodes']
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing propagation: {str(e)}")

@router.post("/batch-risk-analysis", dependencies=[Depends(require_permission("view_dashboard"))])
async def batch_risk_analysis(users_data: list = Body(...)):
    """Analyze risk scores for multiple users"""
    if not models_ready:
        raise HTTPException(status_code=503, detail="ML models are not ready yet.")
    try:
        results = []
        for user in users_data:
            user_id = user.get("id")
            metrics = {
                "normal_login_time": user.get("normal_login_time", 9.2),
                "actual_login_time": user.get("actual_login_time", 9.2),
                "normal_session_duration": user.get("normal_session_duration", 4.5),
                "actual_session_duration": user.get("actual_session_duration", 4.5),
                "normal_data_volume": user.get("normal_data_volume", 120),
                "actual_data_volume": user.get("actual_data_volume", 120),
                "normal_api_calls": user.get("normal_api_calls", 45),
                "actual_api_calls": user.get("actual_api_calls", 45),
                "normal_geo_distance": user.get("normal_geo_distance", 0),
                "actual_geo_distance": user.get("actual_geo_distance", 0),
            }
            anomaly_score = user.get("anomaly_score", 0.0)
            risk_analysis = risk_scorer.calculate_risk_score(metrics, anomaly_score)
            devices = list_devices(str(user_id)) if user_id is not None else []
            device = devices[0] if devices else None
            fused_risk = record_signals(
                str(user_id or "unknown"),
                behavioral_score=risk_analysis["overall_score"],
                anomaly_score=min(100.0, float(anomaly_score) * 100),
                classifier_label=str(user.get("classifier_label", "benign")),
                classifier_confidence=float(user.get("classifier_confidence", 0.0)),
                device_id=device["device_id"] if device else None,
                device_trust_status=device["trust_status"] if device else "unknown",
            )
            incident = await open_incident(
                fused_risk,
                evidence=["Batch behavior risk crossed the high-risk threshold"],
            )
            
            results.append({
                "user_id": user_id,
                "overall_score": fused_risk["score"],
                "threat_level": fused_risk["level"],
                "recommendation": risk_analysis['recommendation'],
                "deviations": risk_analysis['deviations'],
                "fused_risk": fused_risk,
                "incident": incident,
            })
        await broadcast_dashboard_update("batch_risk_recomputed")
        return {"user_risk_scores": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error in batch analysis: {str(e)}")

# ── Live Threat Endpoints (for real-time demo) ──

@router.get("/live-threat", dependencies=[Depends(require_permission("view_dashboard"))])
async def get_live_threat():
    """Frontend polls this every 2s to get current threat state"""
    return live_threat_state

@router.post("/live-threat/reset", dependencies=[Depends(require_permission("approve_incidents"))])
async def reset_threat():
    """Reset the live threat state"""
    reset_live_threat()
    return {"status": "reset", "message": "Live threat cleared"}

@router.post("/inject-threat", dependencies=[Depends(require_permission("approve_incidents"))])
async def inject_threat(request: Request, payload: dict = Body(...)):
    """
    Attack simulator sends threat data here.
    The data goes through the REAL ML pipeline before updating the live feed.
    
    Expected payload:
    {
        "phase": "recon|escalation|breach|exfiltration",
        "attacker_ip": "203.0.113.42",
        "attacker_location": "Moscow, RU",
        "attacker_device": "Unknown Linux Host",
        "target_user": "Alex Chen",
        "behavior_metrics": { ... },
        "anomaly_score": 0.0-1.0,
        "anomalies": ["list of anomaly descriptions"],
        "compromised_nodes": ["n1", "n4"]
    }
    """
    global live_threat_state

    if not models_ready:
        raise HTTPException(status_code=503, detail="ML models are not ready yet.")
    
    try:
        # ── Run through REAL ML models ──
        metrics = payload.get("behavior_metrics", {})
        anomaly_score = payload.get("anomaly_score", 0.0)
        required_metrics = {
            "normal_login_time", "actual_login_time", "normal_session_duration",
            "actual_session_duration", "normal_data_volume", "actual_data_volume",
            "normal_api_calls", "actual_api_calls", "normal_geo_distance", "actual_geo_distance",
        }
        if not isinstance(metrics, dict) or not required_metrics.issubset(metrics):
            raise HTTPException(status_code=422, detail=f"behavior_metrics must include: {', '.join(sorted(required_metrics))}")
        try:
            metric_values = np.asarray([metrics[key] for key in required_metrics], dtype=float)
            anomaly_score = float(anomaly_score)
        except (TypeError, ValueError) as error:
            raise HTTPException(status_code=422, detail=f"Threat metrics must be numeric: {error}") from error
        if not np.isfinite(metric_values).all() or not 0 <= anomaly_score <= 1:
            raise HTTPException(status_code=422, detail="Threat metrics must be finite and anomaly_score must be between 0 and 1.")
        if not isinstance(payload.get("anomalies", []), list) or not all(isinstance(item, str) for item in payload.get("anomalies", [])):
            raise HTTPException(status_code=422, detail="anomalies must be a list of strings.")
        compromised_nodes = payload.get("compromised_nodes", [])
        valid_node_ids = {f"n{i}" for i in range(1, 11)}
        if not isinstance(compromised_nodes, list) or not all(node_id in valid_node_ids for node_id in compromised_nodes):
            raise HTTPException(status_code=422, detail="compromised_nodes must contain valid node IDs from n1 through n10.")
        
        # 1. Risk scoring via ML
        ml_result = risk_scorer.calculate_risk_score(
            behavior_metrics=metrics,
            anomaly_score=anomaly_score,
            sensitivity=1.0
        )
        
        # 2. Anomaly detection via Isolation Forest
        anomaly_data = np.array([[
            metrics.get("actual_session_duration", 4.5),
            metrics.get("actual_data_volume", 120),
            metrics.get("actual_api_calls", 45),
            metrics.get("actual_geo_distance", 0),
            metrics.get("actual_login_time", 9.2),
        ]])
        predictions, scores = anomaly_detector.predict(anomaly_data)
        
        ml_result["isolation_forest_anomaly"] = bool(predictions[0] == -1)
        ml_result["isolation_forest_score"] = round(float(scores[0]), 4)

        target_user = str(payload.get("target_user", "unknown"))
        target_devices = list_devices(target_user)
        target_device = target_devices[0] if target_devices else None
        deviations = ml_result.get("deviations", {})
        prediction = threat_classifier.predict(
            login_hour_deviation=abs(float(metrics["actual_login_time"]) - float(metrics["normal_login_time"])),
            geo_distance_km=float(metrics["actual_geo_distance"]),
            device_match_score=0.15,
            session_deviation_pct=float(deviations.get("session_deviation", 0)),
            data_volume_deviation_pct=float(deviations.get("data_volume_deviation", 0)),
            api_calls_deviation_pct=float(deviations.get("api_calls_deviation", 0)),
            isolation_forest_score=float(ml_result["isolation_forest_score"]),
        )
        # Keep the network-observed peer address separate from the simulator's
        # claimed attacker_ip field. The latter is untrusted scenario metadata.
        observed_source_ip = _client_ip(request)
        fused_risk = record_signals(
            target_user,
            behavioral_score=float(ml_result["overall_score"]),
            anomaly_score=min(100.0, float(ml_result["isolation_forest_score"]) * 100),
            classifier_label=prediction.get("attack_type", "unknown"),
            classifier_confidence=prediction.get("confidence", 0),
            device_id=target_device["device_id"] if target_device else None,
            device_trust_status=target_device["trust_status"] if target_device else "unknown",
            ip_address=observed_source_ip,
        )
        stored_incident = await open_incident(
            fused_risk,
            evidence=list(payload.get("anomalies", [])) + [f"Simulated threat: {payload.get('attack_type', 'unspecified')}"]
        )
        incident = None if stored_incident is None else {
            "id": stored_incident["id"],
            "timestamp": stored_incident["created_at"],
            "userId": "u1",
            "userName": target_user,
            "type": stored_incident["title"],
            "description": "; ".join(stored_incident["evidence"]),
            "riskScore": stored_incident["risk_score"],
            "threatLevel": stored_incident["severity"].lower(),
            "status": "active",
            "response": "Analyst review required",
            "deviation": round(max(ml_result.get("deviations", {}).values(), default=0)),
        }
        
        # Update the live state
        live_threat_state = {
            "active": True,
            "phase": payload.get("phase", "recon"),
            "risk_score": fused_risk["score"],
            "threat_level": fused_risk["level"],
            "attacker_ip": payload.get("attacker_ip"),
            "observed_source_ip": observed_source_ip,
            "attacker_location": payload.get("attacker_location"),
            "attacker_device": payload.get("attacker_device"),
            "target_user": payload.get("target_user"),
            "anomalies": payload.get("anomalies", []),
            "ml_result": ml_result,
            "prediction": prediction,
            "fused_risk": fused_risk,
            "incident": incident,
            "compromised_nodes": compromised_nodes,
            "timestamp": datetime.now().isoformat(),
        }
        
        phase = payload.get("phase", "?")
        score = ml_result["overall_score"]
        level = ml_result["threat_level"]
        print(f"LIVE THREAT [{phase.upper()}] -> Score: {score} | Level: {level} | IF-Anomaly: {ml_result['isolation_forest_anomaly']}")

        await ws_manager.broadcast_to_admins({"type": "login_threat", **live_threat_state})
        await broadcast_dashboard_update("threat_injected")
        
        return {
            "status": "injected",
            "ml_result": ml_result,
            "fused_risk": fused_risk,
            "live_threat": live_threat_state
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threat injection failed: {str(e)}")

# ── WebSocket endpoint (ADMIN dashboards connect here — attackers never see this) ──
@app.websocket("/ws/admin")
async def admin_websocket_endpoint(websocket: WebSocket, ticket: str | None = None):
    user = consume_websocket_ticket(ticket or "")
    if not user or user["role"] not in {"admin", "analyst"}:
        await websocket.close(code=4401, reason="SOC stream is restricted to admin and analyst accounts")
        return
    await ws_manager.connect(websocket, user["id"])
    try:
        while True:
            data = await websocket.receive_text()
            # Re-validate on every message (the dashboard pings every 30 s): a user who was deactivated, demoted,
            # or temporarily restricted after connecting must not keep receiving live security data.
            current = get_user_by_id(user["id"])
            if (not current or not current["is_active"] or active_restriction(current["id"])
                    or current["role"] not in {"admin", "analyst"}):
                await websocket.close(code=4401, reason="Session no longer valid")
                ws_manager.disconnect(websocket)
                return
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


# ── Real Login Detection Endpoint ──
@router.post("/login")
@router.post("/auth/login")
async def real_login(request: Request, response: Response, payload: dict = Body(...)):
    """
    REAL login detection pipeline:
      1. Receive device fingerprint from browser
      2. Get client IP → GeoIP lookup → lat/lon
      3. Compare fingerprint against stored baseline
      4. Calculate haversine geo distance
      5. Build ML feature vector from REAL data
      6. Run through Isolation Forest + Risk Scorer
      7. Push result to dashboard via WebSocket

    Expected payload from frontend:
    {
        "username": "alex_chen",
        "fingerprint": { userAgent, platform, screenResolution, timezone, ... }
    }
    """
    global live_threat_state

    username = payload.get("email", payload.get("username", "unknown"))
    password = payload.get("password", "")
    fingerprint = payload.get("fingerprint", {})
    source_fingerprint_id = payload.get("fingerprint_id", "")
    event_source = "LIVE"
    source_ip = _client_ip(request)

    if not models_ready:
        if isinstance(username, str) and username.strip() and isinstance(password, str):
            await _record_authentication_event(
                request,
                username=username.strip(),
                source_ip=source_ip,
                outcome="FAILURE",
                reason="authentication_unavailable",
                event_source=event_source,
                status_code=503,
            )
        raise HTTPException(status_code=503, detail="ML models are not ready yet.")

    if not isinstance(username, str) or not username.strip():
        await _record_authentication_event(
            request, username="invalid_input", source_ip=source_ip,
            outcome="FAILURE", reason="invalid_request", event_source=event_source,
            status_code=422,
        )
        raise HTTPException(status_code=422, detail="username must be a non-empty string.")
    if not isinstance(password, str):
        await _record_authentication_event(
            request, username=username.strip(), source_ip=source_ip,
            outcome="FAILURE", reason="invalid_request", event_source=event_source,
            status_code=422,
        )
        raise HTTPException(status_code=422, detail="password must be a string.")
    username = username.strip()

    auth_username = username.strip()
    authenticated_user, auth_failure_reason, audit_attempt_id = authenticate(
        auth_username, password, ip=source_ip, device_id=str(source_fingerprint_id or "") or None,
    )

    if not authenticated_user:
        safe_auth_reason = (
            auth_failure_reason
            if auth_failure_reason in {"account_locked", "account_restricted", "account_inactive"}
            else "invalid_credentials"
        )
        authentication_event = await _record_authentication_event(
            request,
            username=auth_username,
            source_ip=source_ip,
            outcome="FAILURE",
            reason=safe_auth_reason,
            event_source=event_source,
            status_code=401,
        )
        # Still get client IP for the alert
        fail_ip = source_ip

        stuffing_event = record_auth_failure(fail_ip, auth_username.lower())
        if stuffing_event:
            request.state.extra_network_anomalies = [stuffing_event]
        failed_risk = record_signals(
            auth_username.lower(),
            behavioral_score=85.0,
            anomaly_score=85.0,
            classifier_label="credential_theft",
            classifier_confidence=100.0,
            # A failed password attempt is not proof that the caller used the
            # account owner's registered device. Keep it account-scoped only.
            device_id=None,
            device_trust_status="unknown",
        )
        failed_incident = await open_incident(
            failed_risk,
            evidence=["Invalid password attempt", f"Source IP: {fail_ip}"],
        )

        failed_event = {
            "type": "login_threat",
            "active": True,
            "phase": "login",
            "source_fingerprint_id": source_fingerprint_id,
            "username": username,
            "risk_score": failed_risk["score"],
            "threat_level": failed_risk["level"],
            "attacker_ip": fail_ip,
            "attacker_location": "Unknown",
            "attacker_device": f"{fingerprint.get('deviceType', 'unknown')} — {fingerprint.get('platform', 'unknown')}" if isinstance(fingerprint, dict) else "Unknown device",
            "target_user": username,
            "attack_type": "Failed Login — Invalid Credentials",
            "anomalies": ["Invalid password attempt", f"Username: {username}", f"Source IP: {fail_ip}"],
            "compromised_nodes": ["n1"],
            "incident": None if not failed_incident else {
                "id": failed_incident["id"],
                "timestamp": failed_incident["created_at"],
                "userId": "u1",
                "userName": username,
                "type": "Failed Login — Invalid Credentials",
                "description": "; ".join(failed_incident["evidence"]),
                "riskScore": failed_incident["risk_score"],
                "threatLevel": failed_incident["severity"].lower(),
                "status": "active",
                "response": "Block source IP",
                "deviation": 100,
            },
            "fused_risk": failed_risk,
            "timestamp": datetime.now().isoformat(),
        }

        # Update live_threat_state so polling also keeps the threat active
        live_threat_state = {
            **failed_event,
            "type": "login_threat",
        }

        # Push failed login to admin dashboards
        await ws_manager.broadcast_to_admins(failed_event)
        await broadcast_dashboard_update("invalid_login_incident")
        print(f"\n{'-'*60}")
        print(f"FAILED LOGIN: {username} (wrong password) from {fail_ip}")
        print(f"{'-'*60}")

        return JSONResponse(status_code=401, content={
            **failed_event,
            "authentication_event_id": authentication_event["id"],
            "authentication_event_timestamp": authentication_event["timestamp"],
            "login_status": "denied",
            "message": (
                "Account temporarily locked. Try again after 15 minutes."
                if auth_failure_reason == "account_locked"
                else "Account is restricted by an administrator."
                if auth_failure_reason == "account_restricted"
                else "Invalid username or password."
            ),
            "login_attempt_reason": auth_failure_reason,
            "detail": (
                "Account temporarily locked. Try again after 15 minutes."
                if auth_failure_reason == "account_locked"
                else "Account is restricted by an administrator."
                if auth_failure_reason == "account_restricted"
                else "Invalid username or password."
            ),
        })

    required_fingerprint_fields = {
        "userAgent", "platform", "screenResolution", "timezone", "canvasHash",
        "webglRenderer", "hardwareConcurrency", "colorDepth", "deviceType", "language",
    }
    if not isinstance(fingerprint, dict) or not required_fingerprint_fields.issubset(fingerprint):
        finalize_login_attempt(audit_attempt_id, success=False, device_id=None, reason="invalid_fingerprint")
        authentication_event = await _record_authentication_event(
            request,
            username=auth_username,
            source_ip=source_ip,
            outcome="FAILURE",
            reason="invalid_fingerprint",
            event_source=event_source,
            status_code=422,
            user_id=authenticated_user["id"],
        )
        raise HTTPException(status_code=422, detail="fingerprint is missing required device identity fields.")
    if not all(isinstance(fingerprint[field], (str, int, float)) for field in required_fingerprint_fields):
        finalize_login_attempt(audit_attempt_id, success=False, device_id=None, reason="invalid_fingerprint")
        authentication_event = await _record_authentication_event(
            request,
            username=auth_username,
            source_ip=source_ip,
            outcome="FAILURE",
            reason="invalid_fingerprint",
            event_source=event_source,
            status_code=422,
            user_id=authenticated_user["id"],
        )
        raise HTTPException(status_code=422, detail="fingerprint fields must be strings or numeric values.")

    username = authenticated_user["id"]
    request.state.authenticated_user = authenticated_user
    request.state.authentication_event_context = {
        "username": auth_username,
        "source_ip": source_ip,
        "event_source": event_source,
        "user_id": authenticated_user["id"],
    }

    # ── STEP 2: Get real client IP & geolocation ──
    # Use the transport peer until trusted proxy configuration is explicit;
    # accepting arbitrary X-Forwarded-For values would let clients spoof history.
    client_ip = source_ip

    geo = await geoip_lookup(client_ip)
    country_decision = evaluate_country_policy(client_ip, geo, request.headers)
    if not country_decision["allowed"]:
        finalize_login_attempt(audit_attempt_id, success=False, device_id=None, reason="geo_policy_denied")
        authentication_event = await _record_authentication_event(
            request,
            username=auth_username,
            source_ip=client_ip,
            outcome="FAILURE",
            reason="geo_policy_denied",
            event_source=event_source,
            status_code=403,
            user_id=authenticated_user["id"],
        )
        agent_audit(
            "geo_policy", "login_denied", incident=None,
            actor=f"user:{authenticated_user['id']}",
            payload={"country": country_decision.get("country"), "source": country_decision.get("source"), "ip": client_ip},
        )
        raise HTTPException(status_code=403, detail={
            "code": "GEO_POLICY_DENIED",
            "message": "Login blocked by the configured country access policy.",
            "country": country_decision.get("country"),
        })
    login_hour = datetime.now().hour

    print(f"\n{'-'*60}")
    print(f"LOGIN ATTEMPT: {username}")
    print(f"   IP: {client_ip}")
    print(f"   Geo: {geo['city']}, {geo['country']} ({geo['lat']}, {geo['lon']})")
    print(f"   Device: {fingerprint.get('deviceType', '?')} | {fingerprint.get('platform', '?')}")
    print(f"   Screen: {fingerprint.get('screenResolution', '?')} | Canvas: {fingerprint.get('canvasHash', '?')}")
    print(f"   Time: {login_hour}:00")

    # ── STEP 3: Compare with stored baseline ──
    is_first_login = username not in user_baselines
    baseline = get_or_create_baseline(username, fingerprint, geo, login_hour)
    device = register_login_device(username, fingerprint, first_login=is_first_login)
    # Optional local-demo convenience: let the built-in admin enroll the current
    # browser without a second admin session. Never enable this in production.
    demo_device_enrollment = (
        username == "sumukh"
        and os.environ.get("TRUSTNET_ENV", "development").strip().lower() != "production"
        and os.environ.get("TRUSTNET_DEMO_ALLOW_NEW_DEVICE", "0").strip().lower() in {"1", "true", "yes", "on"}
        and device["trust_status"] == "unknown"
    )
    if demo_device_enrollment:
        device = set_device_status(device["device_id"], "trusted") or device
    access_token = issue_access_token(authenticated_user, device_id=device["device_id"])
    refresh_token, _refresh_family = issue_refresh_token(authenticated_user["id"], device["device_id"])
    # Fingerprint comparison
    fp_comparison = compare_fingerprints(baseline["fingerprint"], fingerprint)
    baseline_device_match = fp_comparison["is_same_device"]
    registered_trusted_device = device["trust_status"] == "trusted"
    device_recognized = baseline_device_match or registered_trusted_device
    effective_device_match_score = 1.0 if registered_trusted_device else fp_comparison["match_score"]

    # Geo distance (haversine)
    baseline_geo = baseline["geo"]
    geo_distance = haversine(
        baseline_geo["lat"], baseline_geo["lon"],
        geo["lat"], geo["lon"]
    )

    # Login hour deviation
    hour_deviation = abs(login_hour - baseline.get("normal_login_hour", 9))

    print(f"\n   COMPARISON vs BASELINE:")
    print(f"   Device match:  {fp_comparison['match_score']*100:.0f}% ({fp_comparison['fields_matched']}/{fp_comparison['fields_total']} fields)")
    print(f"   Same device:   {'YES' if fp_comparison['is_same_device'] else 'NO MISMATCH'}")
    print(f"   Geo distance:  {geo_distance:.0f} km")
    print(f"   Hour deviation: {hour_deviation}h")

    if fp_comparison["differences"]:
        print(f"   Changes:")
        for d in fp_comparison["differences"][:5]:
            print(f"     -> {d}")

    # ── STEP 4: Build ML feature vector from REAL data ──
    features = build_feature_vector(
        login_hour=login_hour,
        geo_distance_km=geo_distance,
        device_match_score=effective_device_match_score,
        baseline=baseline,
    )

    # ── STEP 5: Run through REAL ML models ──
    metrics = features["behavior_metrics"]
    anomaly_score_input = features["anomaly_score"]

    # Risk Scorer
    ml_result = risk_scorer.calculate_risk_score(
        behavior_metrics=metrics,
        anomaly_score=anomaly_score_input,
        sensitivity=1.0,
    )

    # Isolation Forest
    anomaly_data = np.array([[
        metrics["actual_session_duration"],
        metrics["actual_data_volume"],
        metrics["actual_api_calls"],
        metrics["actual_geo_distance"],
        metrics["actual_login_time"],
    ]])
    predictions, scores = anomaly_detector.predict(anomaly_data)
    ml_result["isolation_forest_anomaly"] = bool(predictions[0] == -1) and not is_first_login
    ml_result["isolation_forest_score"] = round(float(scores[0]), 4)

    # A baseline-establishing login has no prior per-user observations to
    # classify. Treat it as enrollment, not as a suspicious event because a
    # generic synthetic model happens to dislike the first sample.
    if is_first_login:
        ml_result["overall_score"] = 0.0
        ml_result["threat_level"] = "safe"
        ml_result["recommendation"] = "monitor"
        ml_result["confidence"] = 0.0

    risk_score = round(ml_result["overall_score"])
    threat_level = ml_result["threat_level"]

    # ── STEP 5b: Supervised Threat Classifier ──
    # Build deviations for classifier features
    deviations = ml_result.get("deviations", {})
    session_dev = deviations.get("session_deviation", 0)
    data_dev = deviations.get("data_volume_deviation", 0)
    api_dev = deviations.get("api_calls_deviation", 0)

    prediction = threat_classifier.predict(
        login_hour_deviation=float(hour_deviation),
        geo_distance_km=float(geo_distance),
        device_match_score=float(effective_device_match_score),
        session_deviation_pct=float(session_dev),
        data_volume_deviation_pct=float(data_dev),
        api_calls_deviation_pct=float(api_dev),
        isolation_forest_score=float(ml_result.get("isolation_forest_score", 0)),
    )
    if is_first_login:
        prediction.update({
            "prediction": "BENIGN",
            "attack_type": "benign",
            "attack_label": "Benign",
            "confidence": 100.0,
            "action": "ALLOW",
            "description": "First successful login established this account's device baseline.",
            "is_malicious": False,
            "probabilities": {"benign": 100.0},
        })

    fused_risk = record_signals(
        username,
        behavioral_score=risk_score,
        anomaly_score=(0.0 if is_first_login else min(100.0, float(ml_result.get("isolation_forest_score", 0.0)) * 100)),
        classifier_label=prediction.get("attack_type", "unknown"),
        classifier_confidence=prediction.get("confidence", 0.0),
        device_id=device["device_id"],
        device_trust_status=device["trust_status"],
        ip_address=client_ip,
    )
    risk_score = fused_risk["score"]
    threat_level = fused_risk["level"]
    fused_incident = await open_incident(
        fused_risk,
        evidence=[
            f"Fingerprint match {fp_comparison['match_score'] * 100:.0f}%",
            f"Geo distance {geo_distance:.1f} km",
            f"Classifier {prediction.get('attack_type', 'unknown')} ({prediction.get('confidence', 0)}% confidence)",
        ],
    )
    agent_summary = await run_agents(fused_incident, "login")
    if agent_summary:
        device = get_device(device["device_id"]) or device
    incident = None
    if fused_incident:
        incident = {
            "id": fused_incident["id"],
            "timestamp": fused_incident["created_at"],
            "userId": "u1",
            "userName": username,
            "type": fused_incident["title"],
            "description": "; ".join(fused_incident["evidence"]),
            "riskScore": fused_incident["risk_score"],
            "threatLevel": fused_incident["severity"].lower(),
            "status": "active",
            "response": "Analyst review required",
            "deviation": round(max(ml_result.get("deviations", {}).values(), default=0)),
        }

    print(f"\n   ML RESULTS:")
    print(f"   Risk Score:         {risk_score}/100")
    print(f"   Threat Level:       {threat_level.upper()}")
    print(f"   IF Anomaly:         {'YES' if ml_result['isolation_forest_anomaly'] else 'No'}")
    print(f"   IF Score:           {ml_result['isolation_forest_score']}")
    print(f"   Recommendation:     {ml_result['recommendation']}")
    print(f"   Confidence:         {ml_result.get('confidence', 'N/A')}%")
    print(f"\n   SUPERVISED PREDICTION:")
    print(f"   Verdict:            {prediction['prediction']}")
    print(f"   Attack Type:        {prediction['attack_label']}")
    print(f"   Confidence:         {prediction['confidence']}%")
    print(f"   Action:             {prediction['action']}")
    print(f"{'-'*60}")

    # Build anomaly descriptions from REAL differences
    anomalies = []
    if not device_recognized:
        anomalies.append(f"New device detected — {100 - fp_comparison['match_score']*100:.0f}% fingerprint mismatch")
    if geo_distance > 100:
        anomalies.append(f"Geo-location deviation: {geo_distance:,.0f} km ({geo['city']}, {geo['country']})")
    if hour_deviation > 4:
        anomalies.append(f"Login time deviation: {login_hour}:00 (normal: {baseline.get('normal_login_hour', 9)}:00)")
    if ml_result["isolation_forest_anomaly"]:
        anomalies.append(f"Isolation Forest flagged as anomaly (score: {ml_result['isolation_forest_score']})")
    for key, val in ml_result.get("deviations", {}).items():
        if val > 80:
            anomalies.append(f"{key}: {val:.0f}% deviation from baseline")

    # Determine compromised nodes based on risk
    compromised = []
    if risk_score > 30:
        compromised.append("n1")  # User endpoint
    if risk_score > 50:
        compromised.append("n4")  # Web app
    if risk_score > 70:
        compromised.extend(["n7", "n9"])  # Core server + DB

    # ── STEP 5c: Explainable AI ──
    explanation = build_full_explanation(
        baseline_fp=baseline["fingerprint"],
        current_fp=fingerprint,
        match_score=fp_comparison["match_score"],
        is_same_device=fp_comparison["is_same_device"],
        features_used=prediction.get("features_used", {}),
        prediction=prediction,
        rf_model=threat_classifier.rf_model,
        gb_model=threat_classifier.gb_model,
        scaler=threat_classifier.scaler,
        ml_result=ml_result,
        geo_distance_km=geo_distance,
        device_match_score=effective_device_match_score,
        isolation_forest_score=ml_result.get("isolation_forest_score", 0),
        isolation_forest_anomaly=ml_result.get("isolation_forest_anomaly", False),
        compromised_nodes=compromised,
        risk_score=risk_score,
    )
    print(f"   XAI: {len(explanation)} explanation layers generated")

    # ── STEP 6 & 7: Update live state + push via WebSocket ──
    threat_event = {
        "type": "login_threat",
        "active": True,
        "phase": "login",
        "source_fingerprint_id": source_fingerprint_id,
        "username": username,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "attacker_ip": client_ip,
        "attacker_location": f"{geo['city']}, {geo['country']}",
        "attacker_device": f"{fingerprint.get('deviceType', 'unknown')} — {fingerprint.get('platform', 'unknown')}",
        "target_user": username,
        "attack_type": prediction["attack_label"] if prediction["is_malicious"] else "Real Login Detection",
        "prediction": prediction,
        "anomalies": anomalies,
        "ml_result": ml_result,
        "fingerprint_comparison": fp_comparison,
        "registered_device_trusted": registered_trusted_device,
        "geo_distance_km": round(geo_distance, 1),
        "geo": geo,
        "login_hour": login_hour,
        "incident": incident,
        "compromised_nodes": compromised,
        "explanation": explanation,
        "device": device,
        "fused_risk": fused_risk,
        "agent": agent_summary,
        "timestamp": datetime.now().isoformat(),
    }

    # Update the polled live_threat_state too (for backward compat)
    live_threat_state = {
        "active": True,
        "phase": "login",
        "source_fingerprint_id": source_fingerprint_id,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "attacker_ip": client_ip,
        "attacker_location": f"{geo['city']}, {geo['country']}",
        "attacker_device": f"{fingerprint.get('deviceType', 'unknown')} — {fingerprint.get('platform', 'unknown')}",
        "target_user": username,
        "anomalies": anomalies,
        "ml_result": ml_result,
        "prediction": prediction,
        "fingerprint_comparison": fp_comparison,
        "geo_distance_km": round(geo_distance, 1),
        "geo": geo,
        "login_hour": login_hour,
        "incident": incident,
        "compromised_nodes": compromised,
        "explanation": explanation,
        "timestamp": datetime.now().isoformat(),
    }

    # Push to admin dashboards via WebSocket
    await ws_manager.broadcast_to_admins(threat_event)
    await broadcast_dashboard_update("login_risk_recomputed")

    # Add simplified login_status for the attacker-facing login portal
    # Key rule: if device fingerprint doesn't match → ACCESS DENIED
    if device["trust_status"] in {"flagged", "revoked"}:
        login_status = "denied"
        user_message = "Access denied. This device has been flagged or revoked by an administrator."
    elif not device_recognized:
        login_status = "denied"
        user_message = "Access denied. Unrecognized device."
    elif not device_recognized and device["trust_status"] != "trusted":
        login_status = "restricted"
        user_message = "Device is awaiting administrator trust approval."
    elif risk_score >= 70:
        login_status = "restricted"
        user_message = "Access temporarily restricted. Please contact your administrator."
    else:
        login_status = "allowed"
        user_message = "Login successful."

    finalize_login_attempt(
        audit_attempt_id,
        success=login_status == "allowed",
        device_id=device["device_id"],
        reason=None if login_status == "allowed" else login_status,
    )
    if login_status == "allowed":
        failure_reason = None
    elif login_status == "restricted" and not is_first_login and device["trust_status"] != "trusted":
        failure_reason = "device_pending"
    elif login_status == "restricted":
        failure_reason = "risk_restricted"
    else:
        failure_reason = "device_untrusted"
    authentication_event = await _record_authentication_event(
        request,
        username=auth_username,
        source_ip=client_ip,
        outcome="SUCCESS" if login_status == "allowed" else "FAILURE",
        reason=failure_reason,
        event_source=event_source,
        status_code=200,
        user_id=authenticated_user["id"],
    )

    # Refresh token is only in an HttpOnly cookie; never include it in JSON.
    if login_status == "allowed":
        response.set_cookie(
            key="trustnet_refresh", value=refresh_token, httponly=True,
            secure=os.environ.get("TRUSTNET_ENV", "development").lower() == "production",
            samesite="lax", path="/api/auth", max_age=7 * 24 * 60 * 60,
        )

    # Return full data (admin dashboard reads ML fields) + simplified fields (login portal reads login_status)
    return {
        **threat_event,
        "authentication_event_id": authentication_event["id"],
        "authentication_event_timestamp": authentication_event["timestamp"],
        "login_status": login_status,
        "message": user_message,
        "access_token": access_token if login_status == "allowed" else None,
        "token_type": "bearer" if login_status == "allowed" else None,
        "expires_in": ACCESS_TOKEN_MINUTES * 60 if login_status == "allowed" else 0,
        "user": authenticated_user,
        "permissions": sorted(PERMISSIONS[authenticated_user["role"]]) if login_status == "allowed" else [],
    }


@router.get("/auth/events", dependencies=[Depends(require_permission("view_dashboard"))])
async def get_authentication_events_endpoint(limit: int = 100):
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 500")
    events = list_authentication_events(limit)
    return {"events": events, "count": len(events), "data_scope": "live_authentication_events_only"}


def _require_development_demo() -> None:
    if os.environ.get("TRUSTNET_ENV", "development").strip().lower() == "production":
        raise HTTPException(status_code=404, detail="Development demo account controls are disabled.")


@router.get("/demo/account")
async def get_demo_account_endpoint(_user: dict = Depends(require_permission("manage_users"))):
    _require_development_demo()
    demo_user = get_user_by_id(_DEMO_ACCOUNT_ID)
    restrictions = await asyncio.to_thread(list_restrictions, _DEMO_ACCOUNT_ID)
    active = next((item for item in restrictions if item["status"] == "active"), None)
    return {
        "account": None if demo_user is None else {
            "id": demo_user["id"], "email": demo_user["email"], "role": demo_user["role"],
            "is_active": demo_user["is_active"],
        },
        "restriction": active,
        "restriction_history": restrictions[:20],
    }


@router.post("/demo/account/setup", status_code=201)
async def setup_demo_account_endpoint(
    payload: dict = Body(...),
    user: dict = Depends(require_permission("manage_users")),
):
    _require_development_demo()
    if set(payload) != {"password"} or not isinstance(payload.get("password"), str):
        raise HTTPException(status_code=422, detail="Provide only the dedicated demo account password.")
    if get_user_by_id(_DEMO_ACCOUNT_ID):
        raise HTTPException(status_code=409, detail="The dedicated demo account already exists.")
    try:
        demo_user = create_user(
            "trustnet-demo@trustnet.local",
            payload["password"],
            "viewer",
            user_id=_DEMO_ACCOUNT_ID,
        )
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    agent_audit(
        "demo_account", "created", incident=None, actor=f"user:{user['id']}",
        payload={"target_user_id": _DEMO_ACCOUNT_ID, "role": "viewer"},
    )
    await broadcast_dashboard_update("demo_account_created")
    return {"account": {"id": demo_user["id"], "email": demo_user["email"], "role": demo_user["role"]}}


@router.post("/demo/account/restrict")
async def restrict_demo_account_endpoint(user: dict = Depends(require_permission("manage_users"))):
    _require_development_demo()
    demo_user = get_user_by_id(_DEMO_ACCOUNT_ID)
    if demo_user is None:
        raise HTTPException(status_code=404, detail="Initialize the dedicated demo account first.")
    restriction = await asyncio.to_thread(
        create_restriction,
        demo_user,
        minutes=30,
        incident_id=None,
        action_id=None,
        actor=f"user:{user['id']}",
        reason="TrustNet end-to-end demonstration",
        mode="block",
    )
    await broadcast_dashboard_update("demo_account_restricted")
    return {"restriction": restriction}


@router.post("/demo/account/release")
async def release_demo_account_endpoint(user: dict = Depends(require_permission("manage_users"))):
    _require_development_demo()
    active = await asyncio.to_thread(active_restriction, _DEMO_ACCOUNT_ID)
    if active is None:
        raise HTTPException(status_code=409, detail="The dedicated demo account has no active restriction.")
    released = await asyncio.to_thread(release_restriction, active["id"], f"user:{user['id']}")
    if released is None:
        raise HTTPException(status_code=409, detail="The demo restriction has already expired or been released.")
    await broadcast_dashboard_update("demo_account_released")
    return {"restriction": released}


@router.get("/csi/simulation/sample", dependencies=[Depends(require_permission("view_dashboard"))])
async def get_csi_simulation_sample_endpoint(scenario: str = "match"):
    try:
        return generate_simulated_sample(scenario.lower())
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@router.get("/devices", dependencies=[Depends(require_permission("view_dashboard"))])
async def get_devices_endpoint():
    devices = list_devices()
    return {"devices": devices, "count": len(devices)}


@router.get("/devices/{user_id}", dependencies=[Depends(require_permission("view_dashboard"))])
async def get_user_devices_endpoint(user_id: str):
    devices = list_devices(user_id)
    return {"user_id": user_id, "devices": devices, "count": len(devices)}


@router.post("/devices/{device_id}/trust", dependencies=[Depends(require_permission("manage_devices"))])
async def trust_device_endpoint(device_id: str):
    device = set_device_status(device_id, "trusted", quarantined=False)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found.")
    risk = compute_risk(device["user_id"])
    incident = await open_incident(risk, evidence=[f"Device {device_id} trust status updated to trusted"])
    await run_agents(incident, "device_trust_changed")
    await broadcast_dashboard_update("device_trust_changed")
    return {"device": device, "risk": risk, "incident": get_incident(incident["id"]) if incident else None}


@router.post("/devices/{device_id}/revoke")
async def revoke_device_endpoint(device_id: str, user: dict = Depends(require_permission("manage_devices"))):
    device = get_device(device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found.")
    revoked = set_device_status(device_id, "revoked", quarantined=True)
    agent_audit("device", "revoked", incident=None, actor=f"user:{user['id']}", payload={"device_id": device_id, "target_user_id": device["user_id"]})
    await ws_manager.close_for_user(device["user_id"], "Device revoked; re-authentication required")
    await broadcast_dashboard_update("device_revoked")
    return {"status": "revoked", "device": revoked}


@router.get("/risk/{user_id}", dependencies=[Depends(require_permission("view_dashboard"))])
async def get_user_risk_endpoint(user_id: str):
    risk = compute_risk(user_id)
    had_open_incident = any(
        item["user_id"] == user_id and item["status"] in {"open", "investigating"}
        for item in list_incidents()
    )
    incident = await open_incident(risk, evidence=["Risk recomputed from current stored security signals"])
    await run_agents(incident, "risk_recompute")
    if incident and not had_open_incident:
        await broadcast_dashboard_update("risk_incident_created")
    return {**risk, "incident": get_incident(incident["id"]) if incident else None}


def _forbid_self_target(incident: dict, user: dict, action: str) -> None:
    """403 + audit when an account tries to dismiss/resolve an incident that targets itself (escalation only raises
    scrutiny, so it is allowed)."""
    try:
        agent_response.assert_not_self_target(incident, user, action)
    except agent_response.ResponseError as error:
        raise HTTPException(status_code=error.status_code, detail=str(error)) from error


@router.get("/incidents", dependencies=[Depends(require_permission("view_dashboard"))])
async def list_incidents_endpoint(status: str | None = None):
    valid_statuses = {"active", "open", "investigating", "resolved", "dismissed"}
    if status is not None and status not in valid_statuses:
        raise HTTPException(status_code=422, detail=f"status must be one of {sorted(valid_statuses)}")
    incidents = list_incidents(status=status)
    return {"incidents": incidents, "count": len(incidents)}


@router.get("/incidents/{incident_id}", dependencies=[Depends(require_permission("view_dashboard"))])
async def get_incident_endpoint(incident_id: str):
    incident = get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return incident


@router.post("/incidents/{incident_id}/approve")
async def approve_incident_endpoint(incident_id: str, user: dict = Depends(require_permission("approve_incidents"))):
    try:
        result = await asyncio.to_thread(agent_orchestrator.approve_incident, incident_id, user)
    except agent_response.ResponseError as error:
        raise HTTPException(status_code=error.status_code, detail=str(error)) from error
    await broadcast_dashboard_update("incident_response_approved")
    return {"incident": result["incident"], "device": result["device"], "response": result["action"]}


@router.post("/incidents/{incident_id}/dismiss", dependencies=[Depends(require_permission("approve_incidents"))])
async def dismiss_incident_endpoint(incident_id: str, user: dict = Depends(get_current_user)):
    current = get_incident(incident_id)
    if current is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    _forbid_self_target(current, user, "dismiss")
    if current["status"] in {"resolved", "dismissed"}:
        raise HTTPException(status_code=409, detail=f"Cannot dismiss incident in {current['status']} status.")
    incident = transition_incident(incident_id, "dismissed", response_action="dismissed_by_analyst")
    await broadcast_dashboard_update("incident_dismissed")
    return {"incident": incident}


@router.get("/incidents/{incident_id}/report.pdf", dependencies=[Depends(require_permission("approve_incidents"))])
async def incident_report_pdf_endpoint(incident_id: str, user: dict = Depends(get_current_user)):
    """F-32: analyst/admin only (viewers get 403). Audited because it exports incident evidence."""
    pdf = generate_incident_pdf(incident_id)
    if pdf is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    persist_security_event({
        "user_id": user["id"], "request_path": f"/api/incidents/{incident_id}/report.pdf", "http_method": "GET",
        "event_category": "incident_export", "risk_indicators": ["incident_export"],
        "event_payload": {"actor": f"user:{user['id']}", "incident_id": incident_id, "bytes": len(pdf)},
    })
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="trustnet-incident-{incident_id}.pdf"',
                             "Cache-Control": "no-store"})


@router.get("/incidents/{incident_id}/events", dependencies=[Depends(require_permission("view_dashboard"))])
async def get_incident_events_endpoint(incident_id: str):
    if get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    events = get_incident_events(incident_id)
    return {"events": events, "count": len(events)}


@router.post("/incidents/{incident_id}/resolve", dependencies=[Depends(require_permission("approve_incidents"))])
async def resolve_incident_endpoint(incident_id: str, user: dict = Depends(get_current_user)):
    current = get_incident(incident_id)
    if current is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    _forbid_self_target(current, user, "resolve")
    if current["status"] in {"resolved", "dismissed"}:
        raise HTTPException(status_code=409, detail=f"Cannot resolve incident in {current['status']} status.")
    incident = transition_incident(incident_id, "resolved", response_action="resolved_by_analyst")
    await broadcast_dashboard_update("incident_resolved")
    return {"incident": incident}


@router.post("/incidents/{incident_id}/escalate", dependencies=[Depends(require_permission("approve_incidents"))])
async def escalate_incident_endpoint(incident_id: str):
    current = get_incident(incident_id)
    if current is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    if current["status"] in {"resolved", "dismissed"}:
        raise HTTPException(status_code=409, detail=f"Cannot escalate incident in {current['status']} status.")
    incident = transition_incident(incident_id, "investigating", response_action="escalated_to_analyst")
    await broadcast_dashboard_update("incident_escalated")
    return {"incident": incident}


def _agent_error(error: "agent_response.ResponseError") -> HTTPException:
    return HTTPException(status_code=error.status_code, detail=str(error))


@router.get("/incidents/{incident_id}/learning-replay", dependencies=[Depends(require_permission("view_dashboard"))])
async def get_incident_learning_replay_endpoint(incident_id: str):
    """Return persisted risk-score evidence around analyst feedback for one incident."""
    incident = get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    effect = risk_policy.get_verdict_effect(incident_id)
    profile = agent_learning.get_behavior_profile(str(incident.get("user_id") or "")) if incident.get("user_id") else None
    try:
        return agent_learning.build_incident_replay(incident_id, incident, effect, profile)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@router.get("/incidents/{incident_id}/agent", dependencies=[Depends(require_permission("view_dashboard"))])
async def get_incident_agent_view_endpoint(incident_id: str):
    view = agent_orchestrator.incident_agent_view(incident_id)
    if view is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return view


@router.post("/incidents/{incident_id}/investigate", dependencies=[Depends(require_permission("approve_incidents"))])
async def investigate_incident_endpoint(incident_id: str):
    if get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    summary = await asyncio.to_thread(agent_orchestrator.process_incident, incident_id, "manual", force=True)
    if summary is None:
        raise HTTPException(status_code=409, detail="Incident is closed; it cannot be re-investigated.")
    await broadcast_dashboard_update("agent_activity")
    return {"summary": summary, "view": agent_orchestrator.incident_agent_view(incident_id)}


@router.post("/incidents/{incident_id}/responses/{action_id}/approve")
async def approve_response_endpoint(incident_id: str, action_id: str, user: dict = Depends(require_permission("approve_incidents"))):
    action = agent_response.get_action(action_id)
    if action is None or action["incident_id"] != incident_id:
        raise HTTPException(status_code=404, detail="Response action not found for this incident.")
    try:
        executed = await asyncio.to_thread(agent_response.approve, action_id, user)
    except agent_response.ResponseError as error:
        raise _agent_error(error) from error
    await broadcast_dashboard_update("response_approved")
    await export_record("approval", {"decision": "approved", "incident_id": incident_id, "action_id": action_id, "approver": user.get("id"),
                                     "action_type": (executed or {}).get("action_type")})
    return {"response": executed, "incident": get_incident(incident_id)}


@router.post("/incidents/{incident_id}/responses/{action_id}/reject")
async def reject_response_endpoint(incident_id: str, action_id: str, payload: dict = Body(default={}), user: dict = Depends(require_permission("approve_incidents"))):
    action = agent_response.get_action(action_id)
    if action is None or action["incident_id"] != incident_id:
        raise HTTPException(status_code=404, detail="Response action not found for this incident.")
    try:
        rejected = await asyncio.to_thread(agent_response.reject, action_id, user, str(payload.get("reason", "")))
    except agent_response.ResponseError as error:
        raise _agent_error(error) from error
    await broadcast_dashboard_update("response_rejected")
    await export_record("approval", {"decision": "rejected", "incident_id": incident_id, "action_id": action_id, "approver": user.get("id")})
    return {"response": rejected}


@router.get("/account-restrictions", dependencies=[Depends(require_permission("view_dashboard"))])
async def list_account_restrictions_endpoint(user_id: str | None = None):
    return {"restrictions": await asyncio.to_thread(list_restrictions, user_id)}


@router.post("/account-restrictions/{restriction_id}/release")
async def release_account_restriction_endpoint(restriction_id: str, user: dict = Depends(require_permission("approve_incidents"))):
    restriction = next(
        (item for item in await asyncio.to_thread(list_restrictions)
         if item["id"] == restriction_id),
        None,
    )
    if restriction is None:
        raise HTTPException(status_code=404, detail="Restriction not found.")
    if restriction["user_id"] == _DEMO_ACCOUNT_ID and user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only an administrator can release the dedicated demo account restriction.")
    released = await asyncio.to_thread(release_restriction, restriction_id, f"user:{user['id']}")
    if released is None:
        raise HTTPException(status_code=409, detail="Restriction is not active (already expired or released).")
    await broadcast_dashboard_update("account_restriction_released")
    return {"restriction": released}


@router.post("/incidents/{incident_id}/verdict")
async def submit_verdict_endpoint(incident_id: str, payload: dict = Body(...), user: dict = Depends(require_permission("approve_incidents"))):
    try:
        result = await asyncio.to_thread(
            agent_orchestrator.submit_verdict, incident_id, str(payload.get("verdict", "")), str(payload.get("notes", "")), user)
    except agent_response.ResponseError as error:
        raise _agent_error(error) from error
    await broadcast_dashboard_update("analyst_verdict")
    return result


@router.get("/agents/activity", dependencies=[Depends(require_permission("view_dashboard"))])
async def agent_activity_endpoint(limit: int = 50):
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 200")
    return {"activity": list_agent_activity(limit)}


@router.get("/agents/learning", dependencies=[Depends(require_permission("view_dashboard"))])
async def agent_learning_endpoint():
    return agent_learning.evaluate()


@router.get("/agents/autonomy", dependencies=[Depends(require_permission("view_dashboard"))])
async def get_agent_autonomy_endpoint():
    return get_agent_settings()


@router.put("/agents/autonomy")
async def update_agent_autonomy_endpoint(payload: dict = Body(...), user: dict = Depends(require_permission("manage_users"))):
    try:
        settings = update_agent_settings(payload)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    agent_audit("autonomy", "settings_changed", incident=None, actor=f"user:{user['id']}", payload={"changes": payload, "settings": settings})
    await broadcast_dashboard_update("agent_settings_changed")
    return settings


@router.get("/notifications")
async def list_notifications_endpoint(
    limit: int = 50,
    user: dict = Depends(require_permission("view_dashboard")),
):
    if limit < 1 or limit > 200:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 200")
    # Notifications may contain sensitive incident details. Always scope API
    # responses to the authenticated recipient, even for admin/analyst roles.
    rows = await asyncio.to_thread(list_notifications, limit, None, user["email"])
    return {"notifications": rows}


@router.get("/notifications/unread-count")
async def notifications_unread_count_endpoint(user: dict = Depends(require_permission("view_dashboard"))):
    return {"unread_count": await asyncio.to_thread(agent_notifier.unread_count, user["email"])}


@router.post("/notifications/read-all")
async def notifications_read_all_endpoint(user: dict = Depends(require_permission("view_dashboard"))):
    changed = await asyncio.to_thread(agent_notifier.mark_read, user["email"], None)
    return {"marked_read": changed, "unread_count": await asyncio.to_thread(agent_notifier.unread_count, user["email"])}


@router.post("/notifications/{notification_id}/read")
async def notification_read_endpoint(notification_id: str, user: dict = Depends(require_permission("view_dashboard"))):
    changed = await asyncio.to_thread(agent_notifier.mark_read, user["email"], notification_id)
    if not changed:
        raise HTTPException(status_code=404, detail="Unread notification not found for this user.")
    return {"marked_read": changed, "unread_count": await asyncio.to_thread(agent_notifier.unread_count, user["email"])}



@router.get("/risk-policy", dependencies=[Depends(require_permission("view_dashboard"))])
async def get_risk_policy_endpoint():
    return {**risk_policy.get_policy(), "restrict_threshold": get_restrict_threshold(),
            "ranges": {"sensitivity": risk_policy.SENSITIVITY_RANGE, "learning_rate": risk_policy.LEARNING_RATE_RANGE,
                       "max_weight_sum": risk_policy.MAX_WEIGHT_SUM}}


@router.put("/risk-policy")
async def update_risk_policy_endpoint(payload: dict = Body(...), user: dict = Depends(require_permission("manage_users"))):
    before = risk_policy.get_policy()
    try:
        policy = risk_policy.update_policy(payload)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    if policy["version"] != before["version"]:
        persist_security_event({
            "user_id": user["id"], "request_path": "/api/risk-policy", "http_method": "PUT",
            "event_category": "policy_change", "risk_indicators": ["policy:risk_policy"],
            "event_payload": {"actor": f"user:{user['id']}", "from_version": before["version"], "to_version": policy["version"],
                              "changes": {k: policy[k] for k in policy if policy[k] != before.get(k)}},
        })
        await broadcast_dashboard_update("risk_policy_changed")
    return policy


INGEST_SOURCES = {"runtime", "synthetic", "external"}
INGEST_SCORE_FIELDS = ("behavioral_score", "anomaly_score", "geo_score", "classifier_confidence")


def _external_ingest_enabled() -> bool:
    return os.environ.get("TRUSTNET_ALLOW_EXTERNAL_INGEST", "").lower() in {"1", "true", "yes"}


@router.post("/events/ingest")
async def ingest_event_endpoint(payload: dict = Body(...), user: dict = Depends(require_permission("approve_incidents"))):
    """Validated, idempotent event ingestion: event -> persisted -> signals -> fused risk -> incident -> live push.

    ``source`` labels provenance: ``runtime`` (events from this application), ``synthetic`` (demo/test fixtures) or
    ``external`` (only accepted when TRUSTNET_ALLOW_EXTERNAL_INGEST is set). Scores that are not supplied are NOT invented:
    the user's previously recorded signal is kept, otherwise 0 (cold start).
    """
    event_id = payload.get("event_id")
    if not isinstance(event_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{6,64}", event_id):
        raise HTTPException(status_code=422, detail="event_id (idempotency key, 6-64 chars of A-Z a-z 0-9 _ . : -) is required.")
    source = payload.get("source", "runtime")
    if source not in INGEST_SOURCES:
        raise HTTPException(status_code=422, detail="source must be runtime, synthetic or external.")
    if source == "external" and not _external_ingest_enabled():
        raise HTTPException(status_code=403, detail="External telemetry ingestion is not configured (set TRUSTNET_ALLOW_EXTERNAL_INGEST=1).")
    target = payload.get("user_id")
    if not isinstance(target, str) or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", target):
        raise HTTPException(status_code=422, detail="user_id is required (1-64 chars).")
    scores: dict[str, float] = {}
    for field in INGEST_SCORE_FIELDS:
        if field in payload:
            value = payload[field]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 100:
                raise HTTPException(status_code=422, detail=f"{field} must be a number between 0 and 100.")
            scores[field] = float(value)
    label = payload.get("classifier_label", None)
    if label is not None and (not isinstance(label, str) or len(label) > 64):
        raise HTTPException(status_code=422, detail="classifier_label must be a string up to 64 chars.")
    device_id = payload.get("device_id")
    if device_id is not None and (not isinstance(device_id, str) or len(device_id) > 64):
        raise HTTPException(status_code=422, detail="device_id must be a string up to 64 chars.")

    connection = get_db_connection()
    try:
        duplicate = connection.execute("SELECT id FROM security_events WHERE id = ?", (event_id,)).fetchone()
    finally:
        connection.close()
    if duplicate:
        return {"accepted": False, "duplicate": True, "event_id": event_id, "detail": "Event already ingested; nothing was reprocessed."}

    raw_indicators = payload.get("risk_indicators", [])
    event_in = {
        "id": event_id, "timestamp": payload.get("timestamp"), "user_id": target,
        "ip_address": payload.get("ip_address"), "device_fingerprint_hash": payload.get("device_fingerprint_hash"),
        "request_path": payload.get("request_path", "/ingest"), "http_method": payload.get("http_method", "POST"),
        "status_code": payload.get("status_code"), "session_id": payload.get("session_id"),
        "event_category": payload.get("event_category", "ingested_event"),
        "risk_indicators": raw_indicators, "event_payload": {"source": source, "ingested_by": user["id"], **scores},
    }
    try:
        validate_security_event(event_in)
        stored = persist_security_event(event_in)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    previous = get_signals(target)
    device = get_device(device_id) if device_id else None
    fused = record_signals(
        target,
        behavioral_score=scores.get("behavioral_score", previous.get("behavioral_score", 0.0)),
        anomaly_score=scores.get("anomaly_score", previous.get("anomaly_score", 0.0)),
        classifier_label=label if label is not None else previous.get("classifier_label", "unknown"),
        classifier_confidence=scores.get("classifier_confidence", previous.get("classifier_confidence", 0.0)),
        device_id=device_id if device else previous.get("device_id"),
        device_trust_status=device["trust_status"] if device else previous.get("device_trust_status", "unknown"),
        geo_score=scores.get("geo_score", previous.get("geo_score", 0.0)),
    )
    had_open = any(i["user_id"] == target and i["status"] in {"open", "investigating"} for i in list_incidents())
    incident = await open_incident(fused, evidence=[f"Ingested {source} event {event_id}"], event_ids=[event_id], trigger="event_ingest")
    await ws_manager.broadcast_to_admins({
        "type": "event_ingested", "event_id": event_id, "source": source, "user_id": target,
        "score": fused["score"], "level": fused["level"], "policy_version": fused["policy"]["version"],
        "incident_id": incident["id"] if incident else None, "timestamp": datetime.now().astimezone().isoformat(),
    })
    await broadcast_dashboard_update("event_ingested")
    return {
        "accepted": True, "duplicate": False, "event_id": event_id, "source": source,
        "data_label": {"runtime": "runtime application event", "synthetic": "synthetic/demo data", "external": "external telemetry (configured)"}[source],
        "persisted_event": stored if isinstance(stored, dict) else {"id": event_id},
        "risk": fused, "incident_id": incident["id"] if incident else None, "incident_created": bool(incident and not had_open),
    }


@router.get("/behavior-profiles/{user_id}", dependencies=[Depends(require_permission("view_dashboard"))])
async def behavior_profile_endpoint(user_id: str):
    """Return an explainable profile derived from persisted events; sparse users stay in rules-only cold start."""
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", user_id):
        raise HTTPException(status_code=422, detail="Invalid user_id.")
    return build_user_profile(user_id)


@router.get("/dashboard/summary", dependencies=[Depends(require_permission("view_dashboard"))])
async def get_dashboard_summary_endpoint():
    return dashboard_summary_payload()


@router.get("/policies/restrict-threshold", dependencies=[Depends(require_permission("manage_users"))])
async def get_restrict_threshold_endpoint():
    return {"restrict_threshold": get_restrict_threshold(), "minimum": 50, "maximum": 85, "recommended_default": 61}


@router.put("/policies/restrict-threshold", dependencies=[Depends(require_permission("manage_users"))])
async def update_restrict_threshold_endpoint(payload: dict = Body(...)):
    try:
        threshold = set_restrict_threshold(payload.get("restrict_threshold"))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    await broadcast_dashboard_update("restrict_threshold_changed")
    return {"restrict_threshold": threshold, "minimum": 50, "maximum": 85, "recommended_default": 61}


@router.get("/network/events", dependencies=[Depends(require_permission("view_dashboard"))])
async def get_network_events_endpoint(ip: str | None = None, user_id: str | None = None, limit: int = 200):
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 1000")
    events = list_network_events(ip=ip, user_id=user_id, limit=limit)
    return {"events": events, "count": len(events)}


@router.get("/network/topology", dependencies=[Depends(require_permission("view_dashboard"))])
async def get_network_topology_endpoint():
    return build_network_topology()


@router.get("/assets", dependencies=[Depends(require_permission("view_dashboard"))])
async def list_assets_endpoint():
    return {"assets": list_protected_assets(), "range": [asset_criticality.MIN_CRITICALITY, asset_criticality.MAX_CRITICALITY]}


@router.put("/assets/{asset_id}/criticality")
async def update_asset_criticality_endpoint(asset_id: str, payload: dict = Body(...), user: dict = Depends(require_permission("manage_users"))):
    """F-28: admin-only. Persists criticality (1-5); the risk engine and topology read the saved value."""
    if set(payload) != {"criticality"}:
        raise HTTPException(status_code=422, detail="Body must contain only 'criticality'.")
    list_protected_assets()  # ensure demo assets exist
    try:
        result = asset_criticality.set_criticality(asset_id, payload["criticality"])
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    except KeyError as error:
        raise HTTPException(status_code=404, detail="Protected asset not found.") from error
    if result["changed"]:
        persist_security_event({
            "user_id": user["id"], "request_path": f"/api/assets/{asset_id}/criticality", "http_method": "PUT",
            "event_category": "policy_change", "risk_indicators": ["policy:asset_criticality"],
            "event_payload": {"actor": f"user:{user['id']}", "asset_id": asset_id,
                              "from": result["previous"], "to": result["criticality"]},
        })
        await broadcast_dashboard_update("asset_criticality_changed")
    return result


@router.get("/hr/records")
async def read_synthetic_hr_records(request: Request, user: dict = Depends(get_current_user)):
    """Return synthetic HR records only to roles allowed by the protected-asset policy."""
    asset_id = "hr-records"
    access = authorize_asset_read(user["role"], asset_id)
    device_id = str(user.get("token_claims", {}).get("device_id") or "unknown")
    device = get_device(device_id) if device_id != "unknown" else None
    allowed = bool(access and access["allowed"])
    persist_security_event({
        "user_id": user["id"], "ip_address": _client_ip(request),
        "device_fingerprint_hash": (device or {}).get("fingerprint_hash"),
        "request_path": "/api/hr/records", "http_method": "GET",
        "status_code": 200 if allowed else 403, "session_id": None,
        "event_category": "protected_asset_access",
        "risk_indicators": ["protected_asset_access", "sensitive_asset", *( ["access_denied"] if not allowed else [] )],
        "event_payload": {"asset_id": asset_id, "role": user["role"], "device_id": device_id, "allowed": allowed},
    })
    if not allowed:
        raise HTTPException(status_code=403, detail="Role is not authorized to read synthetic HR records.")
    return {"records": [
        {"employee_id": "SYN-HR-001", "department": "Engineering", "status": "active"},
        {"employee_id": "SYN-HR-002", "department": "Operations", "status": "active"},
    ], "synthetic_data": True, "sensitive": True}


@router.get("/files/export")
async def export_synthetic_file_metadata(request: Request, user: dict = Depends(get_current_user)):
    """Return synthetic export metadata, never real files or customer data."""
    asset_id = "file-export-log"
    access = authorize_asset_read(user["role"], asset_id)
    device_id = str(user.get("token_claims", {}).get("device_id") or "unknown")
    device = get_device(device_id) if device_id != "unknown" else None
    allowed = bool(access and access["allowed"])
    persist_security_event({
        "user_id": user["id"], "ip_address": _client_ip(request),
        "device_fingerprint_hash": (device or {}).get("fingerprint_hash"),
        "request_path": "/api/files/export", "http_method": "GET",
        "status_code": 200 if allowed else 403, "session_id": None,
        "event_category": "protected_asset_access",
        "risk_indicators": ["protected_asset_access", "sensitive_asset", *( ["access_denied"] if not allowed else [] )],
        "event_payload": {"asset_id": asset_id, "role": user["role"], "device_id": device_id, "allowed": allowed},
    })
    if not allowed:
        raise HTTPException(status_code=403, detail="Role is not authorized to export files.")
    return {"export": {"export_id": "SYN-EXPORT-001", "format": "json", "status": "demo_only"},
            "synthetic_data": True, "sensitive": True, "file_content_included": False}


@router.get("/protected-assets/{asset_id}")
async def read_protected_asset_endpoint(asset_id: str, request: Request, user: dict = Depends(get_current_user)):
    access = authorize_asset_read(user["role"], asset_id)
    if access is None:
        raise HTTPException(status_code=404, detail="Protected asset not found.")
    device_id = str(user.get("token_claims", {}).get("device_id") or "unknown")
    device = get_device(device_id) if device_id != "unknown" else None
    allowed = bool(access["allowed"])
    # Log the attempted access (including denied attempts) as evidence. This endpoint
    # returns metadata only; it never exposes database rows or real HR/finance data.
    asset_event = persist_security_event({
        "user_id": user["id"], "ip_address": _client_ip(request),
        "device_fingerprint_hash": (device or {}).get("fingerprint_hash"),
        "request_path": f"/api/protected-assets/{asset_id}", "http_method": "GET",
        "status_code": 200 if allowed else 403, "session_id": None,
        "event_category": "protected_asset_access",
        "risk_indicators": ["protected_asset_access", *( ["sensitive_asset"] if access["asset"]["classification"] in {"confidential", "restricted"} else [] ), *( ["access_denied"] if not allowed else [] )],
        "event_payload": {"asset_id": asset_id, "asset_label": access["asset"]["label"], "role": user["role"], "device_id": device_id, "allowed": allowed},
    })
    if asset_id in {"admin-db", "finance-db", "hr-records", "file-export-log"}:
        trust = (device or {}).get("trust_status", "unknown")
        sensitive_attempt = not allowed or trust != "trusted"
        risk = record_signals(
            user["id"], behavioral_score=90.0 if sensitive_attempt else 45.0,
            anomaly_score=90.0 if sensitive_attempt else 18.0,
            classifier_label="unauthorized_sensitive_access" if not allowed else "sensitive_asset_access",
            classifier_confidence=95.0 if sensitive_attempt else 20.0,
            device_id=device_id if device else None, device_trust_status=trust,
        )
        incident = await open_incident(
            risk,
            evidence=[f"Sensitive demo asset access {'denied' if not allowed else 'allowed'}: {asset_id}",
                      f"Device trust status: {trust}", f"Source IP: {_client_ip(request)}"],
            event_ids=[asset_event["id"]], trigger="protected_asset_access",
        )
        if incident:
            await broadcast_dashboard_update(f"protected_asset_risk:{asset_id}")
    if not allowed:
        # The attempted access remains logged and may create a correlated incident,
        # but a caller receives no asset content.
        raise HTTPException(status_code=403, detail="Role is not authorized to read this protected asset.")
    return {"asset": access["asset"], "access": "allowed", "synthetic_metadata_only": True}


@router.post("/demo/reset", dependencies=[Depends(require_permission("manage_users"))])
async def reset_demo_endpoint(request: Request):
    """Reset demo activity only; never delete identities or the append-only audit history.

    Available only when DEMO_MODE is explicitly enabled. This intentionally keeps
    security_events/audit_entries, users, login history, protected assets and policy
    configuration so the reset cannot erase evidence or undo access policy.
    """
    if os.environ.get("DEMO_MODE", "").strip().lower() not in {"1", "true", "yes", "on"} or os.environ.get("TRUSTNET_ENV", "development").strip().lower() == "production":
        raise HTTPException(status_code=404, detail="Demo reset is disabled.")

    # Stop the simulator first so it cannot repopulate state during the reset.
    attack_chain_module.stop()
    reset_live_threat()
    reset_all_baselines()
    reset_devices()
    reset_risk_state()
    reset_incidents()
    reset_network_state()
    reset_agent_state()

    connection = get_db_connection()
    try:
        connection.execute("DELETE FROM risk_assessments")
        demo_user_ids = [row[0] for row in connection.execute("SELECT id FROM users WHERE id LIKE 'demo-%'").fetchall()]
        connection.commit()
    finally:
        connection.close()
    for demo_user_id in demo_user_ids:
        clear_mfa_state(demo_user_id)

    agent_audit("demo", "demo_reset", incident=None,
                actor=f"user:{request.state.authenticated_user['id']}",
                payload={"preserved": ["users", "login_attempts", "security_events", "audit_entries", "protected_assets", "asset_policies"]})
    await broadcast_dashboard_update("demo_reset")
    return {
        "status": "reset",
        "message": "Demo activity reset. Accounts, access policies and audit history were preserved.",
        "preserved": ["users", "login_attempts", "security_events", "audit_entries", "protected_assets", "asset_policies"],
    }




@router.post("/demo/scenarios/{scenario_id}/replay", dependencies=[Depends(require_permission("manage_users"))])
async def replay_demo_scenario(scenario_id: str, request: Request):
    """Replay one harmless synthetic scenario through TrustNet's real risk/incident/agent pipeline.

    This endpoint is deliberately disabled unless DEMO_MODE is explicitly enabled and
    requires the existing manage_users permission. It never sends network traffic or
    executes an attack. Agent response controls and approval safeguards remain in force.
    """
    if os.environ.get("DEMO_MODE", "").strip().lower() not in {"1", "true", "yes", "on"} or os.environ.get("TRUSTNET_ENV", "development").strip().lower() == "production":
        raise HTTPException(status_code=404, detail="Demo scenario replay is disabled.")
    try:
        plan = build_replay_plan(scenario_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="Unknown demo scenario.") from error
    # Synthetic incidents use real database identities so response actions (including
    # step-up MFA) have a concrete target. The generated password is never returned.
    if get_user_by_id(plan["user_id"]) is None:
        from models.security_auth import create_user
        import secrets
        create_user(f"{plan['user_id']}@trustnet.local", secrets.token_urlsafe(24), "viewer", user_id=plan["user_id"])

    # Persist one synthetic request-activity event, then link it to any incident created
    # from the fused score. The TEST-NET IP is documentation-only and no traffic is sent.
    synthetic_event, _ = record_request(
        ip="198.51.100.10",
        user_id=plan["user_id"],
        endpoint=f"/api/demo/replay/{scenario_id}",
        method="GET",
        status_code=200,
        response_time_ms=0,
    )
    # Persist a small, explicit synthetic evidence story so the read-only
    # Investigator can classify the scenario from the same tables used by real
    # request telemetry. No password, token, payload contents, or real traffic is stored.
    scenario = plan["scenario"]
    signals = scenario["signals"]
    event_ids = [synthetic_event["id"]]
    event_path = "/api/demo/synthetic-session"
    if scenario_id in {"brute_force", "stolen_credentials"}:
        event_path = "/api/auth/login"
    elif scenario_id == "data_exfiltration":
        event_path = "/api/protected-assets/file-export-log"
    elif scenario_id == "after_hours_sensitive_access":
        event_path = "/api/protected-assets/hr-records"
    now = datetime.now(timezone.utc)
    evidence_timestamp = now.replace(hour=22, minute=15, second=0, microsecond=0).isoformat() if scenario_id == "after_hours_sensitive_access" else now.isoformat()
    step_event = persist_security_event({
        "id": f"DEMO-{uuid4().hex[:12].upper()}", "timestamp": evidence_timestamp,
        "user_id": plan["user_id"], "ip_address": "198.51.100.10", "device_fingerprint_hash": None,
        "request_path": event_path, "http_method": "GET" if "protected-assets" in event_path else "POST",
        "status_code": 200, "session_id": f"synthetic-{scenario_id}",
        "event_category": "demo_scenario_step", "risk_indicators": ["synthetic_demo", scenario_id],
        "event_payload": {"synthetic": True, "scenario_id": scenario_id, "signals": signals},
    })
    event_ids.append(step_event["id"])
    if signals["failed_logins"] or signals["successful_logins"]:
        conn = get_db_connection()
        try:
            for attempt_index in range(int(signals["failed_logins"])):
                conn.execute(
                    "INSERT INTO login_attempts (attempt_id,user_id,timestamp,success,ip,device_id,reason) VALUES (?,?,?,?,?,?,?)",
                    (f"DEMO-LOGIN-{uuid4().hex}", plan["user_id"], now.isoformat(), 0,
                     f"198.51.100.{10 + (attempt_index % 10)}", plan["device_id"], "synthetic_demo_failed_login"),
                )
            for attempt_index in range(int(signals["successful_logins"])):
                conn.execute(
                    "INSERT INTO login_attempts (attempt_id,user_id,timestamp,success,ip,device_id,reason) VALUES (?,?,?,?,?,?,?)",
                    (f"DEMO-LOGIN-{uuid4().hex}", plan["user_id"], now.isoformat(), 1,
                     "198.51.100.10", plan["device_id"], "synthetic_demo_successful_login"),
                )
            conn.commit()
        finally:
            conn.close()
    risk = record_signals(
        plan["user_id"],
        behavioral_score=plan["behavioral_score"],
        anomaly_score=plan["anomaly_score"],
        classifier_label=plan["classifier_label"],
        classifier_confidence=plan["classifier_confidence"],
        device_id=plan["device_id"],
        device_trust_status=plan["device_trust_status"],
    )
    incident = await open_incident(
        risk,
        evidence=plan["evidence"],
        event_ids=event_ids,
        trigger=f"demo_scenario:{scenario_id}",
    )
    # Benign records intentionally stay below the incident threshold; report the score
    # and telemetry but do not manufacture an incident for the baseline case.
    await broadcast_dashboard_update(f"demo_scenario_replayed:{scenario_id}")
    return {
        "status": "replayed",
        "scenario_id": scenario_id,
        "scenario_title": plan["scenario"]["title"],
        "synthetic_only": True,
        "notice": "Synthetic scenario data was fed through the risk pipeline; results are not live telemetry.",
        "synthetic_event": synthetic_event,
        "scenario_evidence_event": step_event,
        "linked_event_ids": event_ids,
        "risk": risk,
        "incident": incident,
        "investigation": (incident or {}).get("investigator_findings"),
        "response_action": (incident or {}).get("response_action"),
    }


@router.get("/audit/verify", dependencies=[Depends(require_permission("view_dashboard"))])
async def verify_audit_chain_endpoint():
    """Internal hash-chain check plus signed external checkpoints (status: ok, unconfigured, no_checkpoints, failed)."""
    result = verify_audit_chain()
    anchors = verify_audit_anchors()
    return {**result, "anchors": anchors, "valid_with_anchors": bool(result.get("valid")) and anchors["status"] in {"ok", "no_checkpoints", "unconfigured"}}


@router.get("/network/anomalies", dependencies=[Depends(require_permission("view_dashboard"))])
async def get_network_anomalies_endpoint(ip: str | None = None, user_id: str | None = None, limit: int = 200):
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 1000")
    events = list_network_events(ip=ip, user_id=user_id, anomalies_only=True, limit=limit)
    return {"anomalies": events, "count": len(events)}


@router.get("/baselines", dependencies=[Depends(require_permission("view_dashboard"))])
async def get_baselines():
    """Get all stored user baselines (for admin view)."""
    result = {}
    for username, b in user_baselines.items():
        result[username] = {
            "fingerprint_hash": b.get("fingerprint_hash"),
            "device_type": b.get("fingerprint", {}).get("deviceType"),
            "location": f"{b['geo']['city']}, {b['geo']['country']}",
            "normal_login_hour": b.get("normal_login_hour"),
            "created_at": b.get("created_at"),
        }
    return {"baselines": result, "count": len(result)}


@router.post("/baselines/reset", dependencies=[Depends(require_permission("reset_baselines"))])
async def reset_baselines_endpoint(payload: dict = Body(default={})):
    """Reset baselines. Optionally pass {"username": "..."} for single user."""
    username = payload.get("username")
    if username:
        ok = reset_baseline(username)
        if ok:
            reset_user_devices(username)
            reset_user_risk(username)
            await broadcast_dashboard_update("user_baseline_recalibrated")
        return {"status": "reset" if ok else "not_found", "username": username}
    reset_all_baselines()
    reset_devices()
    reset_risk_state()
    await broadcast_dashboard_update("all_baselines_recalibrated")
    return {"status": "all_cleared"}


# ── Attack Chain Simulation Endpoints ──

@router.post("/attack-chain/start", dependencies=[Depends(require_permission("approve_incidents"))])
async def start_attack_chain():
    """Start the 6-phase simulated attack chain."""
    global live_threat_state
    if not models_ready:
        raise HTTPException(status_code=503, detail="ML models are not ready yet.")
    if attack_chain_module.is_running():
        return {"status": "already_running"}

    reset_live_threat()

    def update_live(event: dict):
        global live_threat_state
        target_user = str(event.get("target_user", "unknown"))
        devices = list_devices(target_user)
        device = devices[0] if devices else None
        ml_result = event.get("ml_result", {})
        prediction = event.get("prediction", {})
        fused = record_signals(
            target_user,
            behavioral_score=float(ml_result.get("overall_score", event.get("risk_score", 0))),
            anomaly_score=min(100.0, float(ml_result.get("isolation_forest_score", 0)) * 100),
            classifier_label=prediction.get("attack_type", "unknown"),
            classifier_confidence=prediction.get("confidence", 0),
            device_id=device["device_id"] if device else None,
            device_trust_status=device["trust_status"] if device else "unknown",
        )
        event["risk_score"] = fused["score"]
        event["threat_level"] = fused["level"]
        event["fused_risk"] = fused
        incident = maybe_create_risk_incident(
            fused,
            evidence=event.get("anomalies", [])[:4] + [f"Attack chain: {event.get('attack_type', event.get('step_name', 'step'))}"],
        )
        if incident:
            try:
                agent_orchestrator.process_incident(incident["id"], "attack_chain")
            except Exception as error:  # agent failure must not break the simulation
                print(f"Agent pipeline error for {incident['id']}: {error}")
            event["incident"] = {
                "id": incident["id"],
                "timestamp": incident["created_at"],
                "userId": "u1",
                "userName": target_user,
                "type": incident["title"],
                "description": "; ".join(incident["evidence"]),
                "riskScore": incident["risk_score"],
                "threatLevel": incident["severity"].lower(),
                "status": "active",
                "response": "Analyst review required",
                "deviation": max(ml_result.get("deviations", {}).values(), default=0),
            }
        live_threat_state = event

    async def broadcast_attack_event(event: dict):
        await ws_manager.broadcast_to_admins(event)
        await broadcast_dashboard_update("attack_chain_step")

    asyncio.create_task(
        attack_chain_module.run_attack_chain(
            broadcast_fn=broadcast_attack_event,
            update_live_state=update_live,
        )
    )
    return {"status": "started", "phases": 6, "total_steps": sum(len(p['steps']) for p in attack_chain_module.PHASES)}


@router.post("/attack-chain/stop", dependencies=[Depends(require_permission("approve_incidents"))])
async def stop_attack_chain():
    """Stop the running attack chain."""
    attack_chain_module.stop()
    reset_live_threat()
    await ws_manager.broadcast_to_admins({"type": "attack_chain_stopped", "active": False})
    return {"status": "stopped"}


@router.get("/attack-chain/status", dependencies=[Depends(require_permission("view_dashboard"))])
async def attack_chain_status():
    """Check if attack chain is currently running."""
    return {"running": attack_chain_module.is_running()}


# Include router
app.include_router(router)

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "TrustNet AI Guardian ML Backend",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "openapi": "/openapi.json"
    }

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=int(os.environ.get("TRUSTNET_PORT", "8010")),
        reload=os.environ.get("TRUSTNET_ENV", "development").lower() != "production",
    )
