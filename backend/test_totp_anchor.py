"""Tests for the standalone TOTP and audit-checkpoint cores (no database, no web framework)."""
import base64, hashlib, os, tempfile, unittest
from datetime import datetime, timezone

from models import audit_anchor, totp

RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()  # RFC 6238 appendix B, SHA-1


class TotpTests(unittest.TestCase):
    def test_rfc6238_vectors(self):
        for t, expected in [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                            (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]:
            with self.subTest(t=t):
                self.assertEqual(totp.totp(RFC_SECRET, t, digits=8), expected)

    def test_valid_expired_drifted_wrong(self):
        now = 1_700_000_000
        code = totp.totp(RFC_SECRET, now)
        self.assertEqual(totp.verify(RFC_SECRET, code, now)[0], True)
        self.assertTrue(totp.verify(RFC_SECRET, totp.totp(RFC_SECRET, now - 30), now)[0])      # one step behind
        self.assertTrue(totp.verify(RFC_SECRET, totp.totp(RFC_SECRET, now + 30), now)[0])      # one step ahead
        self.assertFalse(totp.verify(RFC_SECRET, totp.totp(RFC_SECRET, now - 90), now)[0])     # expired (3 steps)
        self.assertFalse(totp.verify(RFC_SECRET, totp.totp(RFC_SECRET, now + 90), now)[0])
        wrong = "000000" if code != "000000" else "111111"
        self.assertFalse(totp.verify(RFC_SECRET, wrong, now)[0])
        for bad in ("", "12345", "1234567", "abcdef", None):
            self.assertFalse(totp.verify(RFC_SECRET, bad, now)[0])

    def test_replay_is_rejected(self):
        now = 1_700_000_000
        code = totp.totp(RFC_SECRET, now)
        ok, counter = totp.verify(RFC_SECRET, code, now)
        self.assertTrue(ok)
        self.assertFalse(totp.verify(RFC_SECRET, code, now, last_used_counter=counter)[0])
        self.assertFalse(totp.verify(RFC_SECRET, totp.totp(RFC_SECRET, now - 30), now, last_used_counter=counter)[0])
        self.assertTrue(totp.verify(RFC_SECRET, totp.totp(RFC_SECRET, now + 30), now, last_used_counter=counter)[0])

    def test_secret_and_uri(self):
        secret = totp.generate_secret()
        self.assertEqual(len(secret), 32)
        self.assertNotEqual(secret, totp.generate_secret())
        uri = totp.provisioning_uri(secret, "a.b@example.test")
        self.assertTrue(uri.startswith("otpauth://totp/TrustNet%20AI%3Aa.b%40example.test?secret=" + secret))
        self.assertIn("period=30", uri)

    def test_backup_codes_single_use_and_hashed(self):
        plain, records = totp.generate_backup_codes()
        self.assertEqual((len(plain), len(set(plain))), (10, 10))
        self.assertTrue(all(code not in str(records) for code in plain))
        remaining = totp.consume_backup_code(records, plain[3])
        self.assertEqual(len(remaining), 9)
        self.assertIsNone(totp.consume_backup_code(remaining, plain[3]))      # second use fails
        self.assertIsNone(totp.consume_backup_code(records, "ffff-ffff"))
        self.assertIsNotNone(totp.consume_backup_code(remaining, plain[0]))

    def test_secret_encryption_roundtrip_and_wrong_key(self):
        key = totp.encryption_key_from_env("k" * 40)
        token = totp.encrypt_secret(RFC_SECRET, key)
        self.assertNotIn(RFC_SECRET, token)
        self.assertEqual(totp.decrypt_secret(token, key), RFC_SECRET)
        self.assertIsNone(totp.decrypt_secret(token, totp.encryption_key_from_env("z" * 40)))
        for bad in (None, "", "short"):
            with self.assertRaises(ValueError):
                totp.encryption_key_from_env(bad)


class AnchorTests(unittest.TestCase):
    KEY = b"x" * 40

    def chain(self, n):
        heads = ["0" * 64]
        for i in range(n):
            heads.append(hashlib.sha256((heads[-1] + f"row{i}").encode()).hexdigest())
        return heads  # heads[k] = hash after k entries

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "audit-checkpoints.jsonl")

    def verify(self, heads, key=KEY):
        return audit_anchor.verify_checkpoints(self.path, key, lambda n: heads[n] if n < len(heads) else None, len(heads) - 1)

    def test_valid_checkpoints_verify(self):
        heads = self.chain(30)
        audit_anchor.write_checkpoint(self.path, self.KEY, 10, heads[10])
        audit_anchor.write_checkpoint(self.path, self.KEY, 30, heads[30], now=datetime(2026, 1, 1, tzinfo=timezone.utc))
        result = self.verify(heads)
        self.assertEqual((result["status"], result["checked"]), ("ok", 2))

    def test_tail_deletion_is_detected(self):
        heads = self.chain(30)
        audit_anchor.write_checkpoint(self.path, self.KEY, 30, heads[30])
        result = self.verify(heads[:21])          # last 10 rows deleted from the table
        self.assertEqual(result["status"], "failed")
        self.assertIn("tail deleted", result["problems"][0])

    def test_row_edit_is_detected(self):
        heads = self.chain(30)
        audit_anchor.write_checkpoint(self.path, self.KEY, 20, heads[20])
        edited = self.chain(30)
        edited[20] = hashlib.sha256(b"edited").hexdigest()
        self.assertEqual(self.verify(edited)["status"], "failed")

    def test_forged_or_wrong_key_signature_is_detected(self):
        heads = self.chain(5)
        audit_anchor.write_checkpoint(self.path, self.KEY, 5, heads[5])
        self.assertEqual(self.verify(heads, key=b"y" * 40)["status"], "failed")
        text = open(self.path).read().replace(heads[5], heads[4])
        open(self.path, "w").write(text)
        self.assertEqual(self.verify(heads)["status"], "failed")

    def test_missing_key_and_missing_file_are_handled_safely(self):
        self.assertIsNone(audit_anchor.key_from_env(None))
        self.assertIsNone(audit_anchor.key_from_env("short"))
        self.assertEqual(self.verify(self.chain(3), key=None)["status"], "unconfigured")
        self.assertEqual(self.verify(self.chain(3))["status"], "no_checkpoints")
        with self.assertRaises(ValueError):
            audit_anchor.write_checkpoint(self.path, None, 1, "h")

    def test_corrupt_line_and_cadence(self):
        open(self.path, "w").write("not json\n")
        self.assertEqual(self.verify(self.chain(3))["status"], "failed")
        self.assertTrue(audit_anchor.should_checkpoint(100, 0, 100))
        self.assertFalse(audit_anchor.should_checkpoint(99, 0, 100))
        self.assertFalse(audit_anchor.should_checkpoint(500, 0, 0))

    def test_file_is_append_only_in_practice(self):
        heads = self.chain(12)
        audit_anchor.write_checkpoint(self.path, self.KEY, 5, heads[5])
        audit_anchor.write_checkpoint(self.path, self.KEY, 10, heads[10])
        self.assertEqual(len(audit_anchor.read_checkpoints(self.path)), 2)


if __name__ == "__main__":
    unittest.main()
