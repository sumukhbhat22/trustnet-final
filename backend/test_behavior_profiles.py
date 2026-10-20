import unittest
from unittest.mock import patch
from models.behavior_profiles import build_user_profile


class BehaviorProfileTests(unittest.TestCase):
    def test_sparse_user_is_cold_start_and_uses_persisted_data(self):
        rows = [
            {"timestamp": "2026-10-19T02:15:00+00:00", "event_category": "login_success", "device_fingerprint_hash": "hash-a", "ip_address": "192.0.2.10"},
            {"timestamp": "2026-10-19T02:16:00+00:00", "event_category": "api_request", "device_fingerprint_hash": "hash-a", "ip_address": "192.0.2.10"},
        ]
        with patch("models.behavior_profiles.list_security_events", return_value=rows):
            profile = build_user_profile("user-1")
        self.assertEqual(profile["event_count"], 2)
        self.assertTrue(profile["cold_start"])
        self.assertEqual(profile["mode"], "rules")
        self.assertEqual(profile["login_hour_histogram"][2], 1)
        self.assertEqual(profile["known_devices"][0]["device_hash"], "hash-a")
        self.assertEqual(profile["request_volume"]["p95_events_per_minute"], 1)

    def test_mature_profile_switches_out_of_cold_start(self):
        rows = [{"timestamp": f"2026-10-19T02:{i % 60:02d}:00+00:00", "event_category": "login_success", "device_fingerprint_hash": f"hash-{i % 2}", "ip_address": "192.0.2.10"} for i in range(30)]
        with patch("models.behavior_profiles.list_security_events", return_value=rows):
            profile = build_user_profile("user-2")
        self.assertEqual(profile["event_count"], 30)
        self.assertFalse(profile["cold_start"])
        self.assertEqual(profile["mode"], "profile")
        self.assertEqual(sum(profile["login_hour_histogram"]), 30)
        self.assertEqual(len(profile["known_devices"]), 2)


if __name__ == "__main__":
    unittest.main()
