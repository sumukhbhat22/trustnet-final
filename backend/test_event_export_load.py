"""Tests for event export (local receiver only) and the load-test script's own arithmetic."""
import json, os, sys, tempfile, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import event_export

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import load_test  # noqa: E402

SECRET = "s" * 32


class Receiver(BaseHTTPRequestHandler):
    received = []
    status = 200

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        Receiver.received.append((body, self.headers.get(event_export.TIMESTAMP_HEADER), self.headers.get(event_export.SIGNATURE_HEADER)))
        self.send_response(Receiver.status); self.end_headers(); self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


class ExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Receiver)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/hook"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close()

    def setUp(self):
        Receiver.received.clear(); Receiver.status = 200

    def test_off_by_default(self):
        cfg = event_export.config_from_env({})
        self.assertFalse(cfg["enabled"])
        self.assertEqual(event_export.export_event("incident", {"id": "i1"}, cfg), {"status": "disabled"})
        self.assertEqual(Receiver.received, [])

    def test_signed_webhook_verifies_and_is_audited(self):
        audits = []
        cfg = {"enabled": True, "webhook_url": self.url, "webhook_secret": SECRET, "jsonl_path": ""}
        result = event_export.export_event("approval", {"id": "a1", "decision": "approved"}, cfg, lambda a, d: audits.append((a, d)))
        self.assertEqual(result["webhook"], "http 200")
        body, ts, sig = Receiver.received[0]
        self.assertTrue(event_export.verify_signature(body, SECRET, ts, sig))
        self.assertFalse(event_export.verify_signature(body + b" ", SECRET, ts, sig))          # tampered body
        self.assertFalse(event_export.verify_signature(body, "o" * 32, ts, sig))                # wrong secret
        self.assertFalse(event_export.verify_signature(body, SECRET, ts, sig, now=float(ts) + 1000))  # replay window
        self.assertEqual(json.loads(body)["kind"], "approval")
        self.assertEqual(audits, [("event_export", {"kind": "approval", "status": "ok", "targets": ["webhook"]})])

    def test_jsonl_export_and_failures_never_raise(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "events.jsonl")
            cfg = {"enabled": True, "webhook_url": "http://127.0.0.1:1/x", "webhook_secret": SECRET, "jsonl_path": path}
            result = event_export.export_event("incident", {"id": "i2"}, cfg)
            self.assertEqual(result["jsonl"], "written")
            self.assertTrue(result["webhook"].startswith("error"))
            self.assertEqual(result["status"], "partial")
            self.assertEqual(json.loads(open(path).read().splitlines()[0])["record"]["id"], "i2")
        bad = {"enabled": True, "webhook_url": self.url, "webhook_secret": "short", "jsonl_path": ""}
        self.assertEqual(event_export.export_event("incident", {}, bad)["status"], "partial")
        self.assertEqual(Receiver.received, [])
        with self.assertRaises(ValueError):
            event_export.build_event("secret_dump", {})


class LoadScriptTests(unittest.TestCase):
    def test_percentile_and_summary(self):
        self.assertEqual(load_test.percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95), 10)
        self.assertEqual(load_test.percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 50), 5)
        s = load_test.summarize([0.01, 0.02, 0.03, 0.04], 1, 2.0)
        self.assertEqual((s["requests"], s["errors"], s["error_rate"], s["achieved_rps"]), (5, 1, 0.2, 2.5))
        self.assertEqual(load_test.summarize([], 0, 1.0)["latency_ms"]["p95"], None)

    def test_run_against_local_stub_counts_requests_and_errors(self):
        Receiver.received.clear(); Receiver.status = 200
        server = HTTPServer(("127.0.0.1", 0), Receiver)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            out = load_test.run(f"http://127.0.0.1:{server.server_port}/x", None, rate=40, seconds=1.0, workers=4, make_body=load_test.synthetic_event)
        finally:
            server.shutdown(); server.server_close()
        self.assertGreaterEqual(out["requests"], 20)
        self.assertEqual(out["errors"], 0)
        self.assertEqual(len(Receiver.received), out["requests"])


if __name__ == "__main__":
    unittest.main()
