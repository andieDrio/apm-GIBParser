"""Tests for Phase 6 one-command PDF report generation."""

from __future__ import annotations

from datetime import datetime, timezone
import tempfile
import unittest
from pathlib import Path

from groupib.normalizer import normalize_record
from reporting.pdf import (
    format_ph_datetime,
    format_ph_time,
    generate_daily_report,
    mask_account,
)
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
            "dateDetected": first_seen,
            "events": [
                {
                    "id": f"event-{record_id}",
                    "dateCompromised": first_seen,
                    "dateDetected": first_seen,
                    "source": {"name": "Private channel", "type": "Telegram"},
                    "client": {
                        "ipv4": {
                            "ip": "192.0.2.10",
                            "countryName": "Philippines",
                            "city": "Quezon City",
                            "provider": "Example ISP",
                        }
                    },
                }
            ],
            "sourceType": ["stealer-log"],
            "source": [
                {
                    "id": "https://t.me/example/123",
                    "type": "Private channel",
                }
            ],
            "malware": [{"id": "malware-1", "name": "ExampleStealer"}],
            "parsedLogin": {"domain": "example.test"},
            "password": "plaintext-secret-must-not-be-rendered",
            "service": {"url": "https://example.test/login"},
        }
    )


class PdfReportTests(unittest.TestCase):
    def test_account_identifier_is_reportable_in_full(self) -> None:
        masked = mask_account("alice@example.test")
        self.assertEqual(masked, "alice@example.test")

    def test_report_window_is_formatted_in_philippines_time(self) -> None:
        self.assertEqual(
            format_ph_datetime(datetime(2026, 9, 24, 3, 13, tzinfo=timezone.utc)),
            "Sep 24, 2026 11:13 AM",
        )
        self.assertEqual(
            format_ph_datetime(datetime(2026, 9, 25, 3, 13, tzinfo=timezone.utc)),
            "Sep 25, 2026 11:13 AM",
        )

    def test_provider_timestamp_is_converted_to_philippines_time(self) -> None:
        self.assertEqual(
            format_ph_time("2026-09-25T01:00:00Z"),
            "Sep 25, 2026 09:00 AM",
        )

    def test_generates_dated_pdf_with_operational_credentials(self) -> None:
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
            output = root / "reports" / "GIB_DailyReport_2026-09-25_1000.pdf"
            generated = generate_daily_report(
                output,
                report_date="2026-09-25",
                window_start=datetime(2026, 9, 24, 10, 0, tzinfo=timezone.utc),
                window_end=datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc),
                metrics=metrics,
                classifications=classifications,
                records=records,
            )

            self.assertEqual(generated, output)
            self.assertTrue(output.is_file())
            self.assertGreater(output.stat().st_size, 0)

            payload = output.read_bytes()
            self.assertTrue(payload.startswith(b"%PDF-"))
            self.assertEqual(records[0].password, "plaintext-secret-must-not-be-rendered")
            self.assertEqual(records[1].password, "plaintext-secret-must-not-be-rendered")


if __name__ == "__main__":
    unittest.main()
