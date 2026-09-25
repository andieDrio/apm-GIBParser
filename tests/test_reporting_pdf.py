"""Tests for Phase 6 one-command PDF report generation."""

from __future__ import annotations

from datetime import datetime, timezone
import tempfile
import unittest
from pathlib import Path

from groupib.normalizer import normalize_record
from reporting.pdf import generate_daily_report, mask_account
from reporting.summary import build_quick_view
from storage.classifier import classify_record
from storage.history import HistoryStore


OBSERVED_AT = datetime(2026, 9, 25, 2, 0, tzinfo=timezone.utc)


def make_record(*, record_id: str, login: str, first_seen: str) -> object:
    return normalize_record(
        {
            "id": record_id,
            "login": login,
            "dateFirstSeen": first_seen,
            "dateLastSeen": first_seen,
            "events": [{"id": f"event-{record_id}"}],
            "sourceType": ["stealer-log"],
            "malware": [{"id": "malware-1", "name": "ExampleStealer"}],
            "parsedLogin": {"domain": "example.test"},
        }
    )


class PdfReportTests(unittest.TestCase):
    def test_account_identifier_is_reportable_in_full(self) -> None:
        masked = mask_account("alice@example.test")
        self.assertEqual(masked, "alice@example.test")

    def test_generates_dated_pdf_without_secret_fields(self) -> None:
        records = (
            make_record(
                record_id="new-001",
                login="alice@example.test",
                first_seen="2026-09-25T01:00:00Z",
            ),
            make_record(
                record_id="old-001",
                login="bob@example.test",
                first_seen="2026-09-20T01:00:00Z",
            ),
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with HistoryStore(root / "history.db") as store:
                classifications = tuple(
                    classify_record(
                        store,
                        record,
                        observed_at=OBSERVED_AT,
                        newness_window_days=1,
                    )
                    for record in records
                )

            metrics = build_quick_view(
                "2026-09-25",
                classifications,
                records,
            )
            output = root / "reports" / "GroupIB_Daily_Report_2026-09-25.pdf"
            generated = generate_daily_report(
                output,
                report_date="2026-09-25",
                metrics=metrics,
                classifications=classifications,
                records=records,
            )

            self.assertEqual(generated, output)
            self.assertTrue(output.is_file())
            self.assertGreater(output.stat().st_size, 0)

            payload = output.read_bytes()
            self.assertTrue(payload.startswith(b"%PDF-"))
            self.assertNotIn(b"password", payload.lower())


if __name__ == "__main__":
    unittest.main()
