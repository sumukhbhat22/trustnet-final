"""RFC 6238 TOTP, backup codes and secret-at-rest encryption. Standard library plus `cryptography`.

Pure functions only (no database, no web framework). Secrets are never logged by this module.
Integration into the MFA endpoints and the MFA dialog is NOT done yet; see docs/STATUS.md.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken

STEP_SECONDS = 30
DIGITS = 6
DRIFT_STEPS = 1
BACKUP_CODE_COUNT = 10


def generate_secret() -> str:
    """160-bit random secret, base32 without padding (authenticator-app format)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret_b32: str) -> bytes:
    padded = secret_b32.strip().replace(" ", "").upper()
    padded += "=" * (-len(padded) % 8)
    return base64.b32decode(padded)


def hotp(secret_b32: str, counter: int, digits: int = DIGITS) -> str:
    digest = hmac.new(_key(secret_b32), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(value).zfill(digits)


def counter_for(timestamp: float, step: int = STEP_SECONDS) -> int:
    return int(timestamp // step)


def totp(secret_b32: str, timestamp: float, step: int = STEP_SECONDS, digits: int = DIGITS) -> str:
    return hotp(secret_b32, counter_for(timestamp, step), digits)


def verify(secret_b32: str, code: str, timestamp: float, last_used_counter: int | None = None,
           drift: int = DRIFT_STEPS) -> tuple[bool, int | None]:
    """Check ``code`` against the window [now-drift, now+drift] steps.

    Returns (ok, matched_counter). A counter at or below ``last_used_counter`` is rejected, so a code
    cannot be replayed. The caller must persist the returned counter as the new last_used_counter.
    """
    code = str(code or "").strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return False, None
    now_counter = counter_for(timestamp)
    matched = None
    for candidate in range(now_counter - drift, now_counter + drift + 1):
        if hmac.compare_digest(hotp(secret_b32, candidate), code):  # no early exit on first match
            matched = candidate
    if matched is None:
        return False, None
    if last_used_counter is not None and matched <= last_used_counter:
        return False, None
    return True, matched


def provisioning_uri(secret_b32: str, account: str, issuer: str = "TrustNet AI") -> str:
    """otpauth:// URI for QR rendering (render client-side; the secret should not go to third parties)."""
    label = quote(f"{issuer}:{account}")
    return f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"


# ---- backup codes: shown once, stored only as salted hashes, single use
def _hash_backup(code: str, salt: bytes) -> str:
    return hashlib.scrypt(code.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32).hex()


def generate_backup_codes(count: int = BACKUP_CODE_COUNT) -> tuple[list[str], list[dict]]:
    """Return (plain codes to show once, records to store). Records hold salt and hash only."""
    plain, records = [], []
    for _ in range(count):
        code = "-".join(secrets.token_hex(2) for _ in range(2))  # e.g. 3fa9-0c71
        salt = secrets.token_bytes(16)
        plain.append(code)
        records.append({"salt": salt.hex(), "hash": _hash_backup(code, salt)})
    return plain, records


def consume_backup_code(records: list[dict], code: str) -> list[dict] | None:
    """Return the records without the matched one, or None if the code matches nothing (single use)."""
    code = str(code or "").strip().lower()
    found = None
    for index, record in enumerate(records):
        if hmac.compare_digest(_hash_backup(code, bytes.fromhex(record["salt"])), record["hash"]):
            found = index
    if found is None:
        return None
    return records[:found] + records[found + 1:]


# ---- secret at rest
def encryption_key_from_env(value: str | None) -> bytes:
    """Derive a Fernet key from TRUSTNET_TOTP_KEY (any string of 32+ characters). Raises if missing/short."""
    if not value or len(value) < 32:
        raise ValueError("TRUSTNET_TOTP_KEY must be set to a string of at least 32 characters")
    return base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest())


def encrypt_secret(secret_b32: str, key: bytes) -> str:
    return Fernet(key).encrypt(secret_b32.encode()).decode()


def decrypt_secret(token: str, key: bytes) -> str | None:
    try:
        return Fernet(key).decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        return None
