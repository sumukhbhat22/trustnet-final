"""Security regression tests for the database-backed MFA step-up flow."""
import os
from pathlib import Path
import tempfile
import unittest
from fastapi import HTTPException

_DIR = tempfile.TemporaryDirectory(prefix="trustnet-mfa-tests-")
os.environ["TRUSTNET_DB_PATH"] = str(Path(_DIR.name) / "mfa-test.db")

from models.database import initialize_database
from models.mfa import clear_mfa_state, create_mfa_challenge, enforce_mfa, require_mfa_for_user, verify_mfa_challenge


class MFATests(unittest.TestCase):
    def setUp(self):
        initialize_database()
        clear_mfa_state()

    def test_required_user_is_blocked_until_correct_code(self):
        require_mfa_for_user("u1", "account")
        with self.assertRaises(HTTPException) as raised:
            enforce_mfa("u1", "device-a")
        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(raised.exception.detail["code"], "MFA_REQUIRED")
        challenge = create_mfa_challenge("u1", "account")
        verified = verify_mfa_challenge("u1", "account", challenge["code"])
        self.assertIn("verified_at", verified)
        enforce_mfa("u1", "device-a")
        with self.assertRaises(ValueError):
            verify_mfa_challenge("u1", "account", challenge["code"])

    def test_sixth_invalid_attempt_is_locked_and_challenge_expiry_is_checked(self):
        challenge = create_mfa_challenge("u2", "account")
        wrong = "000000" if challenge["code"] != "000000" else "000001"
        for _ in range(5):
            with self.assertRaises(ValueError):
                verify_mfa_challenge("u2", "account", wrong)
        # Five failed attempts are permitted; the sixth wrong code locks the flow.
        with self.assertRaises(ValueError):
            verify_mfa_challenge("u2", "account", wrong)
        with self.assertRaises(ValueError):
            create_mfa_challenge("u2", "account")

    def test_expired_challenge_cannot_be_used(self):
        challenge = create_mfa_challenge("u3", "account")
        conn = __import__("models.database", fromlist=["get_db_connection"]).get_db_connection()
        conn.execute("UPDATE mfa_state SET challenge_expires_at='2000-01-01T00:00:00+00:00' WHERE user_id='u3' AND device_id='account'")
        conn.commit(); conn.close()
        with self.assertRaisesRegex(ValueError, "expired"):
            verify_mfa_challenge("u3", "account", challenge["code"])


if __name__ == "__main__":
    unittest.main()
