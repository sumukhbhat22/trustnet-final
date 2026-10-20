"""Optional, off-by-default export of incidents and approvals: signed webhook and JSON-lines file.

Configured only by environment variables; nothing is sent unless TRUSTNET_EXPORT_ENABLED=1.
Standard library only. Wiring into the incident/approval code paths is NOT done yet (see docs/STATUS.md);
callers pass an ``audit`` callback so every export attempt can be written to the audit chain.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Callable

SIGNATURE_HEADER = "X-TrustNet-Signature"
TIMESTAMP_HEADER = "X-TrustNet-Timestamp"
ALLOWED_KINDS = {"incident", "approval"}


def config_from_env(env: dict[str, str] | None = None) -> dict[str, Any]:
    env = os.environ if env is None else env
    enabled = env.get("TRUSTNET_EXPORT_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}
    return {"enabled": enabled, "webhook_url": env.get("TRUSTNET_EXPORT_WEBHOOK_URL", "").strip(),
            "webhook_secret": env.get("TRUSTNET_EXPORT_WEBHOOK_SECRET", ""),
            "jsonl_path": env.get("TRUSTNET_EXPORT_JSONL_PATH", "").strip()}


def sign(body: bytes, secret: str, timestamp: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()


def verify_signature(body: bytes, secret: str, timestamp: str, signature: str, tolerance: int = 300, now: float | None = None) -> bool:
    """Receiver-side check, including a replay window on the timestamp."""
    try:
        if abs((now if now is not None else time.time()) - float(timestamp)) > tolerance:
            return False
    except ValueError:
        return False
    return hmac.compare_digest(sign(body, secret, timestamp), signature or "")


def build_event(kind: str, record: dict[str, Any]) -> dict[str, Any]:
    if kind not in ALLOWED_KINDS:
        raise ValueError(f"unknown export kind: {kind}")
    return {"kind": kind, "exported_at": time.time(), "record": record}


def export_event(kind: str, record: dict[str, Any], cfg: dict[str, Any], audit: Callable[[str, dict], None] | None = None,
                 timeout: float = 3.0) -> dict[str, Any]:
    """Export one event. Never raises on delivery problems; the result says what happened."""
    if not cfg.get("enabled"):
        return {"status": "disabled"}
    event = build_event(kind, record)
    line = json.dumps(event, sort_keys=True)
    results: dict[str, Any] = {"status": "ok"}
    if cfg.get("jsonl_path"):
        try:
            with open(cfg["jsonl_path"], "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            results["jsonl"] = "written"
        except OSError as exc:
            results["jsonl"], results["status"] = f"error: {type(exc).__name__}", "partial"
    if cfg.get("webhook_url"):
        if not cfg.get("webhook_secret") or len(cfg["webhook_secret"]) < 16:
            results["webhook"], results["status"] = "error: webhook secret missing or too short", "partial"
        else:
            body, ts = line.encode(), str(int(time.time()))
            req = urllib.request.Request(cfg["webhook_url"], data=body, method="POST", headers={
                "Content-Type": "application/json", SIGNATURE_HEADER: sign(body, cfg["webhook_secret"], ts), TIMESTAMP_HEADER: ts})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (URL is operator-configured)
                    results["webhook"] = f"http {resp.status}"
            except (urllib.error.URLError, OSError, ValueError) as exc:
                results["webhook"], results["status"] = f"error: {type(exc).__name__}", "partial"
    if audit:
        audit("event_export", {"kind": kind, "status": results["status"], "targets": [k for k in ("jsonl", "webhook") if k in results]})
    return results
