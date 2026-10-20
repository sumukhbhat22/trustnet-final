"""Regression tests: analyst-confirmed bad devices affect live risk scoring."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agents import learning
from models import database
from models import risk_engine


class KnownBadScoringTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp.name) / "trustnet-test.db")
        self.path_patch = patch.object(database, "_DB_PATH", self.db_path)
        self.path_patch.start()
        risk_engine._SIGNALS_DATABASE_PATH = None
        risk_engine._latest_signals.clear()
        database.initialize_database()

    def tearDown(self):
        risk_engine._SIGNALS_DATABASE_PATH = None
        risk_engine._latest_signals.clear()
        self.path_patch.stop()
        self.temp.cleanup()

    def test_confirmed_bad_device_is_flagged_in_live_score(self):
        learning.update_behavior_profile(
            {"id": "INC-KB-1", "user_id": "user-kb", "risk_score": 95,
             "device_id": "device-confirmed-bad", "ip_address": "192.0.2.55"},
            "true_positive",
        )
        risk_engine.record_signals(
            "user-kb", behavioral_score=0, anomaly_score=0, classifier_label="benign",
            classifier_confidence=0, device_id="device-confirmed-bad",
            device_trust_status="trusted", geo_score=0,
        )
        result = risk_engine.compute_risk("user-kb")
        self.assertTrue(result["known_bad_indicators"]["device_flagged"])
        self.assertEqual(result["breakdown"]["device_trust"]["status"], "flagged")
        self.assertEqual(result["breakdown"]["device_trust"]["penalty"], 100.0)
        self.assertTrue(any("known-bad" in reason for reason in result["reasons"]))

    def test_confirmed_bad_ip_adds_bounded_points_and_survives_database_reload(self):
        learning.update_behavior_profile(
            {"id": "INC-IP-1", "user_id": "user-ip", "risk_score": 95,
             "device_id": "ordinary-device", "ip_address": "192.0.2.77"},
            "true_positive",
        )
        clean = risk_engine.record_signals(
            "user-ip", behavioral_score=0, anomaly_score=0, classifier_label="benign",
            classifier_confidence=0, device_id="ordinary-device",
            device_trust_status="trusted", geo_score=0, ip_address="192.0.2.77",
        )
        self.assertTrue(clean["known_bad_indicators"]["ip_flagged"])
        self.assertEqual(clean["adjustments"]["known_bad_ip_points"], 25.0)
        self.assertGreaterEqual(clean["score"], 25.0)
        # Force a reload to ensure the observed IP is persisted in risk_signals.
        risk_engine._SIGNALS_DATABASE_PATH = None
        reloaded = risk_engine.compute_risk("user-ip")
        self.assertEqual(reloaded["ip_address"], "192.0.2.77")
        self.assertTrue(reloaded["known_bad_indicators"]["ip_flagged"])

    def test_ip_indicators_match_canonical_ipv6_and_ipv4_mapped_forms(self):
        learning.update_behavior_profile(
            {"id": "INC-IPV6-1", "user_id": "user-ipv6", "risk_score": 90,
             "device_id": "device-v6", "ip_address": "2001:0db8:0:0:0:0:0:1"},
            "true_positive",
        )
        self.assertTrue(learning.is_known_bad_indicator("ip", "2001:db8::1"))
        self.assertFalse(learning.is_known_bad_indicator("ip", "2001:db8::2"))

        learning.update_behavior_profile(
            {"id": "INC-MAPPED-1", "user_id": "user-mapped", "risk_score": 90,
             "device_id": "device-mapped", "ip_address": "::ffff:192.0.2.99"},
            "true_positive",
        )
        self.assertTrue(learning.is_known_bad_indicator("ip", "192.0.2.99"))

    def test_unlisted_ip_does_not_add_indicator_points(self):
        result = risk_engine.record_signals(
            "user-clean-ip", behavioral_score=0, anomaly_score=0, classifier_label="benign",
            classifier_confidence=0, device_id=None, device_trust_status="trusted",
            ip_address="198.51.100.20",
        )
        self.assertFalse(result["known_bad_indicators"]["ip_flagged"])
        self.assertEqual(result["adjustments"]["known_bad_ip_points"], 0.0)

    def test_unlisted_device_does_not_receive_known_bad_penalty(self):
        risk_engine.record_signals(
            "user-clean", behavioral_score=0, anomaly_score=0, classifier_label="benign",
            classifier_confidence=0, device_id="device-not-listed",
            device_trust_status="trusted", geo_score=0,
        )
        result = risk_engine.compute_risk("user-clean")
        self.assertFalse(result["known_bad_indicators"]["device_flagged"])
        self.assertEqual(result["breakdown"]["device_trust"]["status"], "trusted")


if __name__ == "__main__":
    unittest.main()
