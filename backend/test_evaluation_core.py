"""F-50: the committed synthetic evaluation is reproducible, labelled synthetic, and includes a rules-only baseline."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


class EvaluationTests(unittest.TestCase):
    def test_rerun_matches_committed_report_and_is_labelled(self):
        out = subprocess.run([sys.executable, "evaluate_synthetic.py"], cwd=HERE, capture_output=True, text=True, timeout=250)
        self.assertEqual(out.returncode, 0, out.stderr)
        fresh = json.loads(out.stdout)
        committed = json.loads((HERE.parent / "docs" / "SYNTHETIC_EVALUATION.json").read_text())
        self.assertEqual(fresh, committed)
        self.assertIn("Fictional generated records only", fresh["data_notice"])
        self.assertIn("rules_only_baseline", fresh["comparisons"])
        self.assertIn("isolation_forest", fresh["comparisons"])
        self.assertEqual(fresh["train_count"] + fresh["test_count"], fresh["sample_count"])


if __name__ == "__main__":
    unittest.main()
