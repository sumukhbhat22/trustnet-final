"""Tests for translating harmless scenario definitions into bounded replay inputs."""
import unittest

from demo_scenarios import SCENARIOS, build_replay_plan


class DemoReplayPlanTests(unittest.TestCase):
    def test_every_catalogue_scenario_has_a_replay_plan(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario["id"]):
                plan = build_replay_plan(scenario["id"])
                self.assertTrue(plan["synthetic_only"])
                self.assertEqual(plan["scenario"]["id"], scenario["id"])
                self.assertTrue(plan["user_id"].startswith("demo-"))
                self.assertTrue(plan["device_id"].startswith("DEMO-DEVICE-"))
                self.assertTrue(0 <= plan["behavioral_score"] <= 100)
                self.assertTrue(0 <= plan["anomaly_score"] <= 100)
                self.assertTrue(0 <= plan["classifier_confidence"] <= 100)
                self.assertTrue(plan["evidence"])

    def test_benign_baseline_stays_low_risk(self):
        plan = build_replay_plan("benign_baseline")
        self.assertLess(plan["behavioral_score"], 30)
        self.assertLess(plan["anomaly_score"], 30)
        self.assertEqual(plan["classifier_label"], "unknown")
        self.assertEqual(plan["device_trust_status"], "trusted")

    def test_every_malicious_plan_can_cross_the_documented_restrict_threshold(self):
        # Lower-bound fused score with a zero network contribution. The production risk
        # engine adds the classifier and unknown-device contributions as configured.
        for scenario in SCENARIOS:
            if scenario["id"] == "benign_baseline":
                continue
            with self.subTest(scenario=scenario["id"]):
                plan = build_replay_plan(scenario["id"])
                fused_lower_bound = (
                    plan["behavioral_score"] * 0.30
                    + plan["anomaly_score"] * 0.20
                    + plan["classifier_confidence"] * 0.10
                    + 50.0 * 0.20
                )
                self.assertGreaterEqual(fused_lower_bound, 60.0)

    def test_malicious_scenarios_have_evidence_and_non_unknown_label(self):
        for scenario in SCENARIOS:
            if scenario["id"] == "benign_baseline":
                continue
            with self.subTest(scenario=scenario["id"]):
                plan = build_replay_plan(scenario["id"])
                self.assertNotEqual(plan["classifier_label"], "unknown")
                self.assertEqual(plan["classifier_confidence"], 90.0)
                self.assertTrue(any(scenario["title"] in item for item in plan["evidence"]))

    def test_unknown_scenario_is_rejected(self):
        with self.assertRaises(KeyError):
            build_replay_plan("external-target")


if __name__ == "__main__":
    unittest.main()
