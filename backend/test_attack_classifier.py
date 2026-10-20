"""Focused stdlib tests for the deterministic Investigator attack classifier."""

import unittest

from agents.investigator import classify_attack_type


class AttackClassifierTests(unittest.TestCase):
    def classify(self, fired=(), attempts=(), events=(), evidence=()):
        return classify_attack_type(
            {"id": "INC-TEST", "evidence": list(evidence)}, list(fired),
            list(attempts), list(events),
        )

    def test_repeated_failures_without_success_are_brute_force(self):
        attempts = [{"success": 0} for _ in range(6)]
        result = self.classify(["credential_attack"], attempts=attempts)
        self.assertEqual(result["type"], "brute_force")
        self.assertGreaterEqual(result["confidence"], 0.7)

    def test_credential_attack_with_success_and_unknown_device_is_stolen_credentials(self):
        attempts = [{"success": 0}, {"success": 1}]
        result = self.classify(["credential_attack", "untrusted_device"], attempts=attempts)
        self.assertEqual(result["type"], "stolen_credentials")
        self.assertIn("mfa", result["recommended_action"])

    def test_sensitive_export_is_data_exfiltration(self):
        events = [{"request_path": "/api/files/export", "timestamp": "2026-10-18T14:00:00+00:00"}]
        result = self.classify(events=events)
        self.assertEqual(result["type"], "data_exfiltration")

    def test_sensitive_access_after_hours_is_after_hours_insider(self):
        events = [{"request_path": "/api/finance-db/export", "timestamp": "2026-10-18T23:00:00+00:00"}]
        result = self.classify(events=events)
        self.assertEqual(result["type"], "after_hours_insider")

    def test_insufficient_evidence_stays_unknown(self):
        result = self.classify()
        self.assertEqual(result["type"], "unknown")
        self.assertEqual(result["method"], "deterministic_evidence_rules")


if __name__ == "__main__":
    unittest.main()
