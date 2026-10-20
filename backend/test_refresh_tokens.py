"""Focused regression tests for refresh-token rotation and reuse detection."""
import os
from pathlib import Path
import tempfile
import unittest

_TMP = tempfile.TemporaryDirectory(prefix="trustnet-refresh-tests-")
os.environ["TRUSTNET_DB_PATH"] = str(Path(_TMP.name) / "refresh.db")

from models.database import initialize_database, get_db_connection
from models.refresh_tokens import issue_refresh_token, rotate_refresh_token, revoke_refresh_token

class RefreshTokenTests(unittest.TestCase):
    def setUp(self):
        initialize_database()
        conn = get_db_connection()
        try:
            conn.execute("DELETE FROM refresh_sessions")
            conn.commit()
        finally: conn.close()

    def test_token_rotates_and_old_token_reuse_revokes_family(self):
        raw, family = issue_refresh_token("user-1", "device-1")
        rotated = rotate_refresh_token(raw)
        self.assertIsNotNone(rotated)
        self.assertEqual(rotated["family_id"], family)
        self.assertEqual(rotated["user_id"], "user-1")
        self.assertTrue(rotated["token"])
        reused = rotate_refresh_token(raw)
        self.assertTrue(reused["reuse_detected"])
        self.assertTrue(rotate_refresh_token(rotated["token"])["reuse_detected"])

    def test_logout_revokes_entire_family(self):
        raw, _ = issue_refresh_token("user-2", "device-2")
        rotated = rotate_refresh_token(raw)
        revoke_refresh_token(rotated["token"])
        result = rotate_refresh_token(rotated["token"])
        self.assertTrue(result["reuse_detected"])

    def test_unknown_and_empty_tokens_are_rejected(self):
        self.assertIsNone(rotate_refresh_token(""))
        self.assertIsNone(rotate_refresh_token("not-a-real-token"))

    def test_tokens_stored_only_as_sha256_digests(self):
        import hashlib
        raw, _ = issue_refresh_token("user-3", "device-3")
        conn = get_db_connection()
        try:
            hashes = [r["token_hash"] for r in conn.execute("SELECT token_hash FROM refresh_sessions")]
        finally: conn.close()
        self.assertNotIn(raw, hashes)
        self.assertIn(hashlib.sha256(raw.encode()).hexdigest(), hashes)

    def test_expired_token_is_rejected_and_revoked(self):
        raw, _ = issue_refresh_token("user-4", "device-4")
        conn = get_db_connection()
        try:
            conn.execute("UPDATE refresh_sessions SET expires_at=?", ("2000-01-01T00:00:00+00:00",))
            conn.commit()
        finally: conn.close()
        self.assertIsNone(rotate_refresh_token(raw))
        # Presenting it again is now a replay of a revoked token.
        self.assertTrue(rotate_refresh_token(raw)["reuse_detected"])

    def test_concurrent_rotation_allows_exactly_one_winner(self):
        import threading
        raw, family = issue_refresh_token("user-5", "device-5")
        results, barrier = [], threading.Barrier(8)
        def worker():
            barrier.wait()
            results.append(rotate_refresh_token(raw))
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=30)
        self.assertEqual(len(results), 8)
        winners = [r for r in results if r and r.get("token")]
        replays = [r for r in results if r and r.get("reuse_detected")]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(replays), 7)
        # Replay detection revokes the whole family, including the winner's new token.
        conn = get_db_connection()
        try:
            active = conn.execute("SELECT COUNT(*) c FROM refresh_sessions WHERE family_id=? AND revoked_at IS NULL", (family,)).fetchone()["c"]
        finally: conn.close()
        self.assertEqual(active, 0)

if __name__ == "__main__":
    unittest.main()
