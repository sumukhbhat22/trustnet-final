"""Tests for backend/evaluate.py. Synthetic data only; verifies mechanics, not detector quality."""
import json, os, tempfile, unittest
import numpy as np
import evaluate


class MetricTests(unittest.TestCase):
    def test_classification_metrics_hand_made_example(self):
        labels = np.array([1, 1, 1, 0, 0, 0, 0, 0])
        alerts = np.array([1, 1, 0, 1, 0, 0, 0, 0])
        m = evaluate.classification_metrics(labels, alerts)
        self.assertEqual((m["tp"], m["fp"], m["fn"], m["tn"]), (2, 1, 1, 4))
        self.assertAlmostEqual(m["precision"], 2 / 3)
        self.assertAlmostEqual(m["recall"], 2 / 3)
        self.assertAlmostEqual(m["f1"], 2 / 3)
        self.assertAlmostEqual(m["false_positive_rate"], 1 / 5)

    def test_metrics_with_no_alerts_do_not_divide_by_zero(self):
        m = evaluate.classification_metrics(np.array([1, 0]), np.array([0, 0]))
        self.assertEqual((m["precision"], m["recall"], m["f1"]), (0.0, 0.0, 0.0))

    def test_correlation_and_response_time(self):
        rows = [{"user": 1, "minute": 0.0, "attack_id": 0}, {"user": 1, "minute": 30.0, "attack_id": 0},
                {"user": 1, "minute": 3000.0, "attack_id": None}, {"user": 2, "minute": 10.0, "attack_id": 1}]
        alerts = np.array([0, 1, 1, 0])
        self.assertEqual(evaluate.correlate(rows, alerts), 2)           # 30 and 3000 min are separate incidents
        times, detected, total = evaluate.response_times(rows, alerts)
        self.assertEqual((times, detected, total), ([30.0], 1, 2))      # campaign 1 never alerted


class SplitAndSeedTests(unittest.TestCase):
    def test_split_never_leaks_and_attacks_only_in_test(self):
        rows = evaluate.generate(11)["rows"]
        train, test = evaluate.split(rows)
        self.assertEqual(len(train) + len(test), len(rows))
        self.assertLess(max(r["minute"] for r in train), min(r["minute"] for r in test))
        self.assertTrue(all(r["label"] == 0 for r in train))
        self.assertGreaterEqual(sum(r["label"] for r in test), 30)
        self.assertEqual({r["scenario"] for r in test if r["label"]}, set(evaluate.SCENARIOS))

    def test_generation_is_deterministic_and_seed_sensitive(self):
        self.assertEqual(evaluate.generate(5), evaluate.generate(5))
        self.assertNotEqual(evaluate.generate(5), evaluate.generate(6))

    def test_fixed_seed_gives_identical_full_run(self):
        a = json.dumps(evaluate.run_seed(11), sort_keys=True)
        b = json.dumps(evaluate.run_seed(11), sort_keys=True)
        self.assertEqual(a, b)

    def test_outputs_state_data_origin_and_blocked_real_part(self):
        with tempfile.TemporaryDirectory() as d:
            evaluate.SEEDS, saved = [11, 12], evaluate.SEEDS
            try:
                self.assertEqual(evaluate.main(["--out-dir", d]), 0)
            finally:
                evaluate.SEEDS = saved
            report = json.load(open(os.path.join(d, "EVALUATION.json")))
            md = open(os.path.join(d, "EVALUATION.md")).read()
        self.assertEqual(report["real_data"]["status"], "blocked")
        self.assertIn("fictional generated users", md)
        for name in ("rules_only_baseline", "isolation_forest_alone", "full_pipeline", "ablation_no_correlation"):
            self.assertIn(name, report["synthetic"])


if __name__ == "__main__":
    unittest.main()
