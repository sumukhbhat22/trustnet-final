"""F-32 core tests: real PDF bytes generated from a real incident row in an isolated DB."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from models import database
from models.incident_report import build_report_data, generate_incident_pdf, render_pdf
from models.incident_store import maybe_create_risk_incident
from models.security_events import persist_security_event


class IncidentReportCoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="trustnet-pdf-")
        self.orig = database._DB_PATH
        database._DB_PATH = str(Path(self.tmp.name) / "t.db")
        database.initialize_database()

    def tearDown(self):
        database._DB_PATH = self.orig
        self.tmp.cleanup()

    def _incident(self):
        event = persist_security_event({"user_id": "demo-user", "request_path": "/api/protected-assets/admin-db",
                                        "http_method": "GET", "status_code": 403,
                                        "event_category": "protected_asset_access",
                                        "event_payload": {"asset_id": "admin-db", "allowed": False, "source": "synthetic"}})
        incident = maybe_create_risk_incident(
            {"score": 82, "level": "high", "user_id": "demo-user", "device_id": "dev-1",
             "breakdown": {"device_trust": {"status": "unknown", "contribution": 20}},
             "thresholds": {"restrict": 60}},
            evidence=["Denied access to admin-db <script>alert(1)</script>"], event_ids=[event["id"]])
        self.assertIsNotNone(incident)
        return incident

    def test_pdf_is_valid_and_contains_incident_data(self):
        incident = self._incident()
        pdf = generate_incident_pdf(incident["id"])
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertIn(b"%%EOF", pdf[-64:])
        self.assertGreater(len(pdf), 1500)
        path = Path(self.tmp.name) / "r.pdf"
        path.write_bytes(pdf)
        if subprocess.run(["which", "pdftotext"], capture_output=True).returncode == 0:
            text = subprocess.run(["pdftotext", str(path), "-"], capture_output=True, text=True).stdout
            self.assertIn(incident["id"], text)
            self.assertIn("admin-db", text)
            self.assertIn("Analyst verdicts", text)
            self.assertIn("&lt;script&gt;", text.replace("<", "&lt;").replace(">", "&gt;"))

    def test_unknown_incident_returns_none(self):
        self.assertIsNone(generate_incident_pdf("INC-DOES-NOT-EXIST"))

    def test_missing_fields_render_safely(self):
        pdf = render_pdf({"incident": {"id": "X"}, "agent": {}, "events": [], "assets": []})
        self.assertTrue(pdf.startswith(b"%PDF-"))
        pdf = render_pdf({})
        self.assertTrue(pdf.startswith(b"%PDF-"))

    def test_hostile_markup_does_not_break_rendering(self):
        pdf = render_pdf({"incident": {"id": "<b>unclosed", "evidence": ["<para>&&", "x" * 5000]},
                          "agent": {"responses": [{"action": "<i>", "status": None}]}})
        self.assertTrue(pdf.startswith(b"%PDF-"))

    def test_reasons_are_stored_on_incident_and_in_pdf(self):
        incident = maybe_create_risk_incident(
            {"score": 80, "level": "high", "user_id": "u-r", "device_id": None, "breakdown": {},
             "reasons": ["The device is not trusted (+20.0 points)"], "thresholds": {"restrict": 60}}, evidence=["e"])
        self.assertEqual(incident["risk_breakdown"]["reasons"], ["The device is not trusted (+20.0 points)"])
        path = Path(self.tmp.name) / "r2.pdf"
        path.write_bytes(generate_incident_pdf(incident["id"]))
        text = subprocess.run(["pdftotext", str(path), "-"], capture_output=True, text=True).stdout
        self.assertIn("device is not trusted", text)

    def test_report_data_collects_events_and_assets(self):
        incident = self._incident()
        data = build_report_data(incident["id"])
        self.assertEqual(data["assets"], ["admin-db"])
        self.assertEqual(len(data["events"]), 1)


if __name__ == "__main__":
    unittest.main()
