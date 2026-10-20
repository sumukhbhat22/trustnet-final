"""Signed audit-chain checkpoints written to an append-only file OUTSIDE the database.

A checkpoint is (count, head_hash, time) signed with HMAC-SHA256 using a key from the environment.
Deleting the tail of the audit table, or editing a row so the head hash changes, no longer matches
the latest checkpoints, so ``verify_checkpoints`` reports it. Checkpoints make deletion DETECTABLE,
not impossible: someone holding both the database and the checkpoint file and key can rewrite both.
Standard library only. Wiring into /api/audit/verify and the Verify button is NOT done yet.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Callable

MIN_KEY_LENGTH = 32


def key_from_env(value: str | None) -> bytes | None:
    """Return the key bytes, or None if unset or too short (callers must then report 'unconfigured')."""
    if not value or len(value) < MIN_KEY_LENGTH:
        return None
    return value.encode()


def _sign(key: bytes, count: int, head: str, at: str) -> str:
    return hmac.new(key, f"{count}|{head}|{at}".encode(), hashlib.sha256).hexdigest()


def write_checkpoint(path: str, key: bytes | None, count: int, head_hash: str, now: datetime | None = None) -> dict:
    if key is None:
        raise ValueError("Audit checkpoint key is not configured")
    at = (now or datetime.now(timezone.utc)).isoformat()
    record = {"count": int(count), "head": head_hash, "at": at, "sig": _sign(key, int(count), head_hash, at)}
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:  # append-only
        handle.write(json.dumps(record, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return record


def should_checkpoint(count: int, last_count: int | None, every: int) -> bool:
    return every > 0 and count - (last_count or 0) >= every


def read_checkpoints(path: str) -> list[dict]:
    if not os.path.isfile(path):
        return []
    out = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    out.append({"corrupt": True})
    return out


def verify_checkpoints(path: str, key: bytes | None, head_at: Callable[[int], str | None], total: int,
                       latest: int = 5) -> dict:
    """Check the newest ``latest`` checkpoints against the live chain.

    ``head_at(n)`` must return the chain's hash after the n-th entry (or None if the table has fewer
    than n entries); ``total`` is the current entry count. Returns {"status", "checked", "problems"}.
    status is one of: ok, unconfigured, no_checkpoints, failed.
    """
    if key is None:
        return {"status": "unconfigured", "checked": 0, "problems": ["checkpoint key is not configured"]}
    records = read_checkpoints(path)
    if not records:
        return {"status": "no_checkpoints", "checked": 0, "problems": []}
    problems, checked = [], 0
    for rec in records[-latest:]:
        if rec.get("corrupt") or not all(k in rec for k in ("count", "head", "at", "sig")):
            problems.append("unreadable checkpoint line")
            continue
        checked += 1
        if not hmac.compare_digest(_sign(key, rec["count"], rec["head"], rec["at"]), str(rec["sig"])):
            problems.append(f"bad signature on checkpoint at count {rec['count']}")
            continue
        if total < rec["count"]:
            problems.append(f"audit table has {total} entries but a checkpoint recorded {rec['count']} (tail deleted?)")
        elif head_at(rec["count"]) != rec["head"]:
            problems.append(f"chain head at entry {rec['count']} no longer matches the checkpoint (row edited or replaced)")
    return {"status": "failed" if problems else "ok", "checked": checked, "problems": problems}
