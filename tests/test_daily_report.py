"""Tests for the rolling 24-hour monitoring window."""

from __future__ import annotations

from datetime import datetime, timezone
import unittest
from zoneinfo import ZoneInfo

from daily_report import build_monitoring_window, filter_records_to_window
from groupib.normalizer import normalize_record


OBSERVED_AT = datetime(2026, 9, 25, 3, 13, tzinfo=timezone.utc)
PHILIPPINES_TZ = ZoneInfo("Asia/Manila")


def make_record(*, record_id: str, last_seen: str) -> object:
    return normalize_record(
        {
            "id": record_id,
            "login": f"{record_id}@example.test",
            "dateFirstSeen": last_seen,
            "dateLastSeen": last_seen,
            "events": [{"id": f"event-{record_id}"}],
        }
    )


class DailyReportWindowTests(unittest.TestCase):
    def test_window_is_previous_24_hours_ending_at_run_time(self) -> None:
        window = build_monitoring_window(OBSERVED_AT)

        self.assertEqual(
            window.start,
            datetime(2026, 9, 24, 11, 13, tzinfo=PHILIPPINES_TZ),
        )
        self.assertEqual(
            window.end,
            datetime(2026, 9, 25, 11, 13, tzinfo=PHILIPPINES_TZ),
        )
        self.assertEqual(window.sequence_bootstrap_date, "2026-09-24")

    def test_filter_keeps_only_records_inside_window(self) -> None:
        window = build_monitoring_window(OBSERVED_AT)
        records = (
            make_record(record_id="before", last_seen="2026-09-24T03:12:59Z"),
            make_record(record_id="start", last_seen="2026-09-24T03:13:00Z"),
            make_record(record_id="inside", last_seen="2026-09-24T12:00:00Z"),
            make_record(record_id="end", last_seen="2026-09-25T03:13:00Z"),
            make_record(record_id="after", last_seen="2026-09-25T03:13:01Z"),
        )

        filtered = filter_records_to_window(records, window)

        self.assertEqual(
            tuple(record.provider_record_id for record in filtered),
            ("start", "inside", "end"),
        )


if __name__ == "__main__":
    unittest.main()
