"""F-28 core tests: persistence, validation and risk-engine use of saved criticality (isolated SQLite DB)."""
import json
import tempfile
import unittest
from pathlib import Path

from models import database
from models import asset_criticality as ac
from models.network_topology import list_protected_assets, build_network_topology
from models.risk_engine import compute_risk, record_signals, reset_risk_state
from models.security_events import persist_security_event


class AssetCriticalityCoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="trustnet-crit-")
        self.orig = database._DB_PATH
        database._DB_PATH = str(Path(self.tmp.name) / "t.db")
        database.initialize_database()
        list_protected_assets()  # seed demo assets
        reset_risk_state()

    def tearDown(self):
        database._DB_PATH = self.orig
        self.tmp.cleanup()

    def _denied_access(self, user_id, asset_id):
        persist_security_event({
            "user_id": user_id, "request_path": f"/api/protected-assets/{asset_id}", "http_method": "GET",
            "status_code": 403, "event_category": "protected_asset_access",
            "risk_indicators": ["access_denied"],
            "event_payload": {"asset_id": asset_id, "allowed": False, "role": "viewer"},
        })

    def test_validation_rejects_bad_values(self):
        for bad in (0, 6, -1, 2.5, "3", None, True, [3]):
            with self.assertRaises(ValueError, msg=repr(bad)):
                ac.validate_criticality(bad)
        for good in (1, 2, 3, 4, 5):
            self.assertEqual(ac.validate_criticality(good), good)

    def test_set_persists_across_connections_and_is_listed(self):
        result = ac.set_criticality("asset-people-api", 5)
        self.assertEqual((result["previous"], result["criticality"], result["changed"]), (3, 5, True))
        self.assertEqual(ac.get_criticality("asset-people-api"), 5)
        listed = {a["asset_id"]: a["criticality"] for a in list_protected_assets()}
        self.assertEqual(listed["asset-people-api"], 5)  # re-seeding must not overwrite the saved value

    def test_same_value_is_idempotent_and_unknown_asset_raises(self):
        self.assertFalse(ac.set_criticality("asset-people-api", 3)["changed"])
        with self.assertRaises(KeyError):
            ac.set_criticality("nope", 3)
        with self.assertRaises(ValueError):
            ac.set_criticality("asset-people-api", 99)
        self.assertEqual(ac.get_criticality("asset-people-api"), 3)

    def test_database_constraint_still_enforced(self):
        conn = database.get_db_connection()
        try:
            with self.assertRaises(Exception):
                conn.execute("UPDATE protected_assets SET criticality = 9 WHERE asset_id='asset-people-api'")
        finally:
            conn.close()

    def test_risk_engine_uses_saved_criticality(self):
        record_signals("u1", behavioral_score=20, anomaly_score=20, classifier_label="benign",
                       classifier_confidence=0, device_id=None, device_trust_status="trusted")
        base = compute_risk("u1")
        self.assertEqual(base["adjustments"]["asset_criticality_points"], 0.0)
        self._denied_access("u1", "asset-people-api")
        ac.set_criticality("asset-people-api", 1)
        low = compute_risk("u1")
        ac.set_criticality("asset-people-api", 5)
        high = compute_risk("u1")
        self.assertEqual(low["adjustments"]["asset_criticality_points"], 0.0)
        self.assertEqual(high["adjustments"]["asset_criticality_points"], 10.0)
        self.assertEqual(high["adjustments"]["asset_criticality_source"], "asset-people-api")
        self.assertAlmostEqual(high["score"] - low["score"], 10.0, places=2)

    def test_allowed_access_and_other_users_add_nothing(self):
        record_signals("u2", behavioral_score=10, anomaly_score=10, classifier_label="benign",
                       classifier_confidence=0, device_id=None, device_trust_status="trusted")
        persist_security_event({"user_id": "u2", "request_path": "/api/protected-assets/admin-db", "http_method": "GET",
                                "status_code": 200, "event_category": "protected_asset_access",
                                "event_payload": {"asset_id": "admin-db", "allowed": True}})
        self._denied_access("someone-else", "admin-db")
        self.assertEqual(compute_risk("u2")["adjustments"]["asset_criticality_points"], 0.0)

    def test_topology_exposes_criticality_and_blast_radius(self):
        ac.set_criticality("asset-analytics-db", 2)
        nodes = {n["id"]: n for n in build_network_topology()["nodes"]}
        node = nodes["asset:asset-analytics-db"]
        self.assertEqual(node["criticality"], 2)
        self.assertEqual(node["blastRadius"], round(node["propagationRisk"] * 2 / 5))


if __name__ == "__main__":
    unittest.main()
