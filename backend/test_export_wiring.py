"""Export is wired into incident/approval paths: off by default, summary only, audited, never breaks the caller."""
import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest

_DIR = tempfile.TemporaryDirectory(prefix="trustnet-export-wiring-")
os.environ["TRUSTNET_DB_PATH"] = str(Path(_DIR.name) / "export-wiring.db")

import main
from models.database import get_db_connection, initialize_database

JSONL = str(Path(_DIR.name) / "export.jsonl")
KEYS = ("TRUSTNET_EXPORT_ENABLED", "TRUSTNET_EXPORT_JSONL_PATH", "TRUSTNET_EXPORT_WEBHOOK_URL", "TRUSTNET_EXPORT_WEBHOOK_SECRET")


def _export_audits():
    conn = get_db_connection()
    try:
        return [r[0] for r in conn.execute("SELECT event_payload FROM security_events WHERE request_path LIKE '/agents/export/%'").fetchall()]
    finally:
        conn.close()


class ExportWiringTests(unittest.TestCase):
    def setUp(self):
        initialize_database()
        for k in KEYS:
            os.environ.pop(k, None)
        Path(JSONL).unlink(missing_ok=True)

    def tearDown(self):
        for k in KEYS:
            os.environ.pop(k, None)

    def test_disabled_by_default_writes_nothing_and_audits_nothing(self):
        before = len(_export_audits())
        asyncio.run(main.export_record("incident", {"id": "INC-1"}))
        self.assertFalse(Path(JSONL).exists())
        self.assertEqual(len(_export_audits()), before)

    def test_enabled_writes_summary_and_audit_entry(self):
        os.environ.update({"TRUSTNET_EXPORT_ENABLED": "1", "TRUSTNET_EXPORT_JSONL_PATH": JSONL})
        before = len(_export_audits())
        asyncio.run(main.export_record("approval", {"decision": "approved", "incident_id": "INC-2", "approver": "u1"}))
        line = json.loads(Path(JSONL).read_text().splitlines()[-1])
        self.assertEqual(line["kind"], "approval")
        self.assertEqual(line["record"]["decision"], "approved")
        self.assertEqual(len(_export_audits()), before + 1)

    def test_incident_summary_drops_evidence_and_unknown_fields(self):
        summary = main._incident_summary({"id": "INC-3", "status": "open", "risk_score": 88, "evidence": ["secret-ish detail"], "investigator_findings": {"x": 1}})
        self.assertEqual(set(summary), {"id", "status", "risk_score"})

    def test_unreachable_webhook_never_raises_and_is_audited_as_partial(self):
        os.environ.update({"TRUSTNET_EXPORT_ENABLED": "1", "TRUSTNET_EXPORT_WEBHOOK_URL": "http://127.0.0.1:9/hook",
                           "TRUSTNET_EXPORT_WEBHOOK_SECRET": "x" * 24})
        before = len(_export_audits())
        asyncio.run(main.export_record("incident", {"id": "INC-4"}))
        audits = _export_audits()
        self.assertEqual(len(audits), before + 1)
        self.assertIn("partial", audits[-1])


if __name__ == "__main__":
    unittest.main()
