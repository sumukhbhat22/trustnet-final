"""Tests for the real-data training pipeline. All rows here are fabricated by the tests themselves;
no real dataset is read and nothing touches the network."""
import contextlib, io, json, os, subprocess, tempfile, unittest

import numpy as np
import pandas as pd

from ml import data_loader, registry, train_real
from models.optimized_models import OptimizedAnomalyDetector

RBA_COLS = ["Login Timestamp", "User ID", "Round-Trip Time [ms]", "IP Address", "Country", "Region", "City", "ASN",
            "User Agent String", "Browser Name and Version", "OS Name and Version", "Device Type",
            "Login Successful", "Is Attack IP", "Is Account Takeover"]


def fake_rows(n=600, seed=1):
    rng = np.random.default_rng(seed)
    start = pd.Timestamp("2020-01-01", tz="UTC")
    rows = []
    for i in range(n):
        ts = start + pd.Timedelta(minutes=30 * i)
        user = f"u{rng.integers(0, 12)}"
        attack = bool(rng.random() < 0.05)
        country = "XX" if attack else "NO"
        rows.append([ts.strftime("%Y-%m-%d %H:%M:%S.%f"), user, "100", "192.0.2.1", country, "r", "c", "1",
                     "FakeAgent", "b", "o", "desktop", "True", str(attack), str(attack)])
    return pd.DataFrame(rows, columns=RBA_COLS)


def write_csv(df, directory):
    path = os.path.join(directory, "fake_rba.csv")
    df.to_csv(path, index=False)
    return path


class LoaderTests(unittest.TestCase):
    def test_loader_maps_tiny_sample_and_hashes_identifiers(self):
        with tempfile.TemporaryDirectory() as d:
            rows = fake_rows(40)
            rows.loc[0, ["User ID", "Country", "Login Timestamp"]] = ["alice", "NO", "2020-01-01 13:00:00.000"]
            rows.loc[1, ["User ID", "Country", "Login Timestamp"]] = ["alice", "NO", "2020-01-01 14:00:00.000"]
            rows.loc[2, ["User ID", "Country", "Login Timestamp"]] = ["alice", "BR", "2020-01-01 15:00:00.000"]
            raw = data_loader.read_sample(write_csv(rows, d), sample_frac=1.0, salt="s")
        self.assertEqual(len(raw), 40)
        self.assertNotIn("alice", set(raw["user"]))
        self.assertEqual(set(raw.columns), {"timestamp", "user", "country", "success", "attack_ip", "ato"})
        feats = data_loader.to_features(raw)
        alice = feats[feats["user"] == data_loader.hash_identifier("alice", "s")].reset_index(drop=True)
        self.assertEqual(alice["login_hour"].tolist(), [13.0, 14.0, 15.0])
        self.assertEqual(alice["geo_distance"].tolist(), [50.0, 50.0, 100.0])  # first login and seen country normal; new country flagged
        for name, value in data_loader.NEUTRAL.items():
            self.assertTrue((feats[name] == value).all())
        self.assertEqual(list(feats[data_loader.FEATURES].columns), data_loader.FEATURES)

    def test_missing_required_column_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_csv(fake_rows(10).drop(columns=["Country"]), d)
            with self.assertRaises(ValueError):
                data_loader.read_sample(path, sample_frac=1.0)

    def test_sampling_is_reproducible_and_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            path = write_csv(fake_rows(500), d)
            a = data_loader.read_sample(path, sample_frac=0.2, chunksize=100, seed=3, salt="s")
            b = data_loader.read_sample(path, sample_frac=0.2, chunksize=100, seed=3, salt="s")
        pd.testing.assert_frame_equal(a, b)
        self.assertLess(len(a), 500)
        self.assertEqual(a.attrs["rows_scanned"], 500)

    def test_time_split_never_leaks(self):
        feats = data_loader.to_features(data_loader.read_sample(self._csv(), sample_frac=1.0, salt="s"))
        train, test, info = data_loader.time_split(feats, 0.7)
        self.assertLess(train["ts"].max(), test["ts"].min())
        self.assertEqual(len(train) + len(test), len(feats))
        self.assertEqual(info["train_rows"] + info["test_rows"], len(feats))
        with self.assertRaises(ValueError):
            data_loader.time_split(feats, 1.5)

    def _csv(self):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return write_csv(fake_rows(600), d)


class TrainAndRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        raw = data_loader.read_sample(write_csv(fake_rows(900), cls.dir), sample_frac=1.0, salt="s")
        feats = data_loader.to_features(raw)
        cls.detector, cls.split, cls.metrics, cls.n_train = train_real.train(feats)
        cls.model_path = os.path.join(cls.dir, "m", "real_model.joblib")
        cls.meta = {"name": "isolation_forest_real", "version": "real-test", "dataset": "fake test rows",
                    "rows": 900, "features": data_loader.FEATURES, "date_range": ["a", "b"], "trained_at": "now"}
        train_real.save_with_metadata(cls.detector, cls.model_path, cls.meta)

    def test_training_excludes_attack_rows_and_reports_test_metrics(self):
        self.assertGreater(self.n_train, 50)
        self.assertTrue(self.detector.trained)
        self.assertIn("roc_auc", self.metrics)
        self.assertGreater(self.metrics["roc_auc"], 0.5)  # attacks come from an unseen country by construction
        self.assertLess(self.split["train_end"], self.split["test_start"])

    def test_metadata_saved_and_loaded(self):
        det = OptimizedAnomalyDetector()
        det.feature_names = list(data_loader.FEATURES)
        info = registry.try_load_real_model(det, self.model_path)
        self.assertEqual(info["source"], "real")
        self.assertTrue(info["trained_on_real_data"])
        self.assertEqual(info["version"], "real-test")
        self.assertTrue(det.trained)
        preds, scores = det.predict(np.array([[4.5, 150, 200, 50, 10]]))
        self.assertEqual(scores.shape, (1,))

    def test_fallback_when_model_missing(self):
        det = OptimizedAnomalyDetector()
        with contextlib.redirect_stdout(io.StringIO()):
            det.train()
        before = det.model
        info = registry.try_load_real_model(det, os.path.join(self.dir, "nope.joblib"))
        self.assertEqual(info["source"], "synthetic")
        self.assertFalse(info["trained_on_real_data"])
        self.assertIn("degraded_note", info)
        self.assertIs(det.model, before)

    def test_fallback_when_feature_list_mismatches_or_file_corrupt(self):
        det = OptimizedAnomalyDetector()
        det.feature_names = ["a", "b"]
        self.assertEqual(registry.try_load_real_model(det, self.model_path)["source"], "synthetic")
        bad = os.path.join(self.dir, "bad.joblib")
        open(bad, "wb").write(b"not a model")
        json.dump({"features": data_loader.FEATURES}, open(registry.metadata_path(bad), "w"))
        det2 = OptimizedAnomalyDetector()
        det2.feature_names = list(data_loader.FEATURES)
        info = registry.try_load_real_model(det2, bad)
        self.assertEqual(info["source"], "synthetic")
        self.assertIn("degraded_note", info)

    def test_cli_reports_blocked_when_dataset_missing(self):
        self.assertEqual(train_real.main(["--data", os.path.join(self.dir, "missing.csv")]), 2)


class GitIgnoreTests(unittest.TestCase):
    def test_raw_data_paths_are_ignored(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        text = open(os.path.join(root, ".gitignore"), encoding="utf-8").read().splitlines()
        self.assertIn("data/", text)
        self.assertIn("backend/data/*", text)


if __name__ == "__main__":
    unittest.main()
