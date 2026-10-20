import os
import unittest
from unittest.mock import patch
from models.geo_policy import evaluate_country_policy

class GeoPolicyTests(unittest.TestCase):
    def test_policy_disabled_when_allowlist_empty(self):
        with patch.dict(os.environ, {"TRUSTNET_ALLOWED_COUNTRIES": ""}, clear=False):
            self.assertTrue(evaluate_country_policy("8.8.8.8", {"country": "US"})["allowed"])

    def test_allowlisted_country(self):
        with patch.dict(os.environ, {"TRUSTNET_ALLOWED_COUNTRIES": "US,GB", "TRUSTNET_ENV": "development", "DEMO_MODE": "0"}, clear=False):
            result = evaluate_country_policy("8.8.8.8", {"country": "US"})
            self.assertTrue(result["allowed"])
            self.assertEqual(result["source"], "geoip")

    def test_non_allowlisted_country_denied(self):
        with patch.dict(os.environ, {"TRUSTNET_ALLOWED_COUNTRIES": "US,GB", "TRUSTNET_ENV": "development", "DEMO_MODE": "0"}, clear=False):
            result = evaluate_country_policy("8.8.8.8", {"country": "IN"})
            self.assertFalse(result["allowed"])
            self.assertEqual(result["reason"], "country_not_allowlisted")

    def test_demo_override_only_works_in_demo_mode(self):
        env = {"TRUSTNET_ALLOWED_COUNTRIES": "US", "TRUSTNET_ENV": "development", "DEMO_MODE": "1"}
        with patch.dict(os.environ, env, clear=False):
            self.assertTrue(evaluate_country_policy("8.8.8.8", {"country": "IN"}, {"X-Demo-Country": "US"})["allowed"])
        with patch.dict(os.environ, {**env, "TRUSTNET_ENV": "production"}, clear=False):
            self.assertFalse(evaluate_country_policy("8.8.8.8", {"country": "IN"}, {"X-Demo-Country": "US"})["allowed"])

    def test_private_address_always_bypasses_geo_policy(self):
        with patch.dict(os.environ, {"TRUSTNET_ALLOWED_COUNTRIES": "US"}, clear=False):
            result = evaluate_country_policy("192.168.1.20", {"country": "Unknown"})
            self.assertTrue(result["allowed"])
            self.assertEqual(result["reason"], "private_network_bypass")

if __name__ == "__main__":
    unittest.main()
