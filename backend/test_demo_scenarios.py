"""Tests for the harmless, deterministic synthetic demo scenario catalogue."""
import unittest

from demo_scenarios import SCENARIOS, get_scenario


class DemoScenarioTests(unittest.TestCase):
    def test_scenario_ids_are_unique(self):
        ids = [item["id"] for item in SCENARIOS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_catalog_covers_expected_story_types(self):
        kinds = {item["expected_attack_type"] for item in SCENARIOS}
        self.assertTrue({"unknown", "brute_force", "stolen_credentials", "data_exfiltration", "after_hours_insider"}.issubset(kinds))

    def test_get_scenario_returns_independent_copy(self):
        first = get_scenario("brute_force")
        first["signals"]["failed_logins"] = 0
        self.assertEqual(get_scenario("brute_force")["signals"]["failed_logins"], 8)

    def test_unknown_scenario_is_rejected(self):
        with self.assertRaises(KeyError):
            get_scenario("not-a-scenario")


if __name__ == "__main__":
    unittest.main()
