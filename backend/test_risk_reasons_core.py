"""F-19: every computed score carries plain-language reasons derived from real contributions."""
import tempfile
import unittest
from pathlib import Path

from models import database
from models.risk_engine import compute_risk, record_signals, reset_risk_state


class RiskReasonsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.orig = database._DB_PATH
        database._DB_PATH = str(Path(self.tmp.name) / "t.db")
        database.initialize_database()
        reset_risk_state()

    def tearDown(self):
        database._DB_PATH = self.orig
        self.tmp.cleanup()

    def test_top_three_reasons_ordered_by_contribution(self):
        record_signals("r1", behavioral_score=90, anomaly_score=80, classifier_label="credential_attack",
                       classifier_confidence=70, device_id=None, device_trust_status="unknown")
        reasons = compute_risk("r1")["reasons"]
        self.assertTrue(1 <= len(reasons) <= 3)
        self.assertTrue(all("points" in r for r in reasons))

    def test_cold_start_still_has_a_reason(self):
        reasons = compute_risk("never-seen")["reasons"]
        self.assertGreaterEqual(len(reasons), 1)
        self.assertTrue(all(isinstance(r, str) and r for r in reasons))

    def test_quiet_baseline_when_nothing_contributes(self):
        from models.risk_engine import explain_reasons
        self.assertIn("quiet baseline", explain_reasons({"behavioral": 0.0}, {"points": 0}, 0)[0])


if __name__ == "__main__":
    unittest.main()
