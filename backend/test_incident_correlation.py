"""Tests for time-bounded incident correlation using an isolated SQLite database."""
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from models import database
from models.incident_store import maybe_create_risk_incident, list_incidents


class IncidentCorrelationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="trustnet-correlation-")
        self.original_db_path = database._DB_PATH
        database._DB_PATH = str(Path(self.temp_dir.name) / "test.db")
        database.initialize_database()
        self.original_window = os.environ.get("TRUSTNET_INCIDENT_CORRELATION_MINUTES")
        os.environ["TRUSTNET_INCIDENT_CORRELATION_MINUTES"] = "15"

    def tearDown(self):
        database._DB_PATH = self.original_db_path
        if self.original_window is None:
            os.environ.pop("TRUSTNET_INCIDENT_CORRELATION_MINUTES", None)
        else:
            os.environ["TRUSTNET_INCIDENT_CORRELATION_MINUTES"] = self.original_window
        self.temp_dir.cleanup()

    @staticmethod
    def risk(score=75):
        return {
            "score": score,
            "level": "restrict",
            "user_id": "demo-user",
            "device_id": "demo-device",
            "breakdown": {"test": score},
            "thresholds": {"restrict": 60},
        }

    def test_same_user_device_within_window_updates_same_incident(self):
        first = maybe_create_risk_incident(self.risk(), evidence=["first signal"], event_ids=["evt-1"])
        second = maybe_create_risk_incident(self.risk(82), evidence=["second signal"], event_ids=["evt-2"])
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(second["risk_score"], 82)
        self.assertEqual(set(second["event_ids"]), {"evt-1", "evt-2"})
        self.assertEqual(len(list_incidents()), 1)

    def test_old_open_incident_does_not_absorb_a_new_attack_burst(self):
        first = maybe_create_risk_incident(self.risk(), evidence=["old signal"], event_ids=["evt-old"])
        connection = database.get_db_connection()
        try:
            old_timestamp = (datetime.now(timezone.utc) - timedelta(minutes=16)).isoformat()
            connection.execute("UPDATE incidents SET created_at = ? WHERE id = ?", (old_timestamp, first["id"]))
            connection.commit()
        finally:
            connection.close()

        second = maybe_create_risk_incident(self.risk(88), evidence=["new signal"], event_ids=["evt-new"])
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(len(list_incidents()), 2)

    def test_invalid_window_configuration_falls_back_safely(self):
        os.environ["TRUSTNET_INCIDENT_CORRELATION_MINUTES"] = "not-a-number"
        from models.incident_store import _correlation_window_minutes
        self.assertEqual(_correlation_window_minutes(), 15)


if __name__ == "__main__":
    unittest.main()
