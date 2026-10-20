"""F-16: events touching protected resources are flagged `sensitive_path` automatically."""
import tempfile
import unittest
from pathlib import Path

from models import database
from models.security_events import is_sensitive_path, persist_security_event, validate_security_event, verify_audit_chain


class SensitivePathTests(unittest.TestCase):
    def test_classification(self):
        for path in ("/api/protected-assets/admin-db", "/api/protected-assets/hr-records?x=1", "/api/audit/verify",
                     "/api/baselines/reset", "/api/protected-assets/finance-db/"):
            self.assertTrue(is_sensitive_path(path), path)
        for path in ("/api/protected-assets/asset-people-api", "/api/dashboard/summary", "/api/protected-assets/admin-db-x", ""):
            self.assertFalse(is_sensitive_path(path), path)

    def test_validation_adds_flag_once_and_keeps_existing_indicators(self):
        ev = {"request_path": "/api/protected-assets/finance-db", "http_method": "GET", "event_category": "x",
              "risk_indicators": ["access_denied", "sensitive_path"]}
        out = validate_security_event(ev)["event"]["risk_indicators"]
        self.assertEqual(out.count("sensitive_path"), 1)
        self.assertIn("access_denied", out)
        plain = validate_security_event({"request_path": "/api/dashboard/summary", "http_method": "GET", "event_category": "x"})
        self.assertEqual(plain["event"]["risk_indicators"], [])

    def test_persisted_flag_and_chain_valid(self):
        tmp = tempfile.TemporaryDirectory(); orig = database._DB_PATH
        database._DB_PATH = str(Path(tmp.name) / "t.db"); database.initialize_database()
        try:
            persist_security_event({"request_path": "/api/protected-assets/hr-records", "http_method": "GET", "event_category": "ingest"})
            conn = database.get_db_connection()
            row = conn.execute("SELECT risk_indicators FROM security_events").fetchone(); conn.close()
            self.assertIn("sensitive_path", row["risk_indicators"])
            self.assertTrue(verify_audit_chain()["valid"])
        finally:
            database._DB_PATH = orig; tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
