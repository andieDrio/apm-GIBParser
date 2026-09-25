"""Tests for Phase 5 Quick View metrics."""

from __future__ import annotations

from datetime import datetime, timezone
import tempfile
import unittest
from pathlib import Path

from groupib.normalizer import normalize_record
from reporting.summary import build_quick_view
from storage.classifier import classify_record
from storage.history import HistoryStore


OBSERVED_AT = datetime(2026, 9, 25, 2, 0, tzinfo=timezone.utc)


def make_record(
    *,
    record_id: str,
    login: str,
    first_seen: str,
    event_id: str,
    source_type: str,
    stealer_name: str | None = None,
    domain: str | None = None,
) -> object:
    payload = {
        "id": record_id,
        "login": login,
        "dateFirstSeen": first_seen,
        "dateLastSeen": first_seen,
        "events": [{"id": event_id}],
        "sourceType": [source_type],
    }
    if domain:
        payload["parsedLogin"] = {"domain": domain}
    if stealer_name:
        payload["malware"] = [{"id": f"id-{stealer_name}", "name": stealer_name}]
    return normalize_record(payload)


class QuickViewTests(unittest.TestCase):
    def test_metrics_follow_classification_and_actual_fields(self) -> None:
        records = (
            make_record(
                record_id="new-001",
                login="new@example.test",
                first_seen="2026-09-25T01:00:00Z",
                event_id="event-new",
                source_type="stealer-log",
                stealer_name="ExampleStealer",
                domain="example.test",
            ),
            make_record(
                record_id="old-001",
                login="old@example.test",
                first_seen="2026-09-20T01:00:00Z",
                event_id="event-old",
                source_type="darkweb",
                domain="old.example.test",
            ),
        )

        with tempfile.TemporaryDirectory() as directory:
            with HistoryStore(Path(directory) / "history.db") as store:
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
            report_end=datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(metrics.total_records, 2)
        self.assertEqual(metrics.new_compromises, 1)
        self.assertEqual(
            metrics.new_compromise_7d_daily_counts,
            (
                ("2026-09-19", 0),
                ("2026-09-20", 0),
                ("2026-09-21", 0),
                ("2026-09-22", 0),
                ("2026-09-23", 0),
                ("2026-09-24", 0),
                ("2026-09-25", 1),
            ),
        )
        self.assertEqual(metrics.newly_detected_7d, 0)
        self.assertEqual(metrics.new_compromise_7d_total, 1)
        self.assertEqual(metrics.new_compromise_7d_average, 1 / 7)
        self.assertEqual(metrics.newly_affected_domain_counts, (("example.test", 1),))
        self.assertIsNone(metrics.previous_run)
        self.assertEqual(metrics.old_historical, 1)
        self.assertEqual(metrics.reseen_recycled, 0)
        self.assertEqual(metrics.repeat_records, 0)
        self.assertEqual(metrics.infostealer_records, 1)
        self.assertEqual(metrics.stealer_family_counts, (("ExampleStealer", 1),))
        self.assertEqual(metrics.source_counts, (("darkweb", 1), ("stealer-log", 1)))
        self.assertEqual(
            metrics.target_domain_counts,
            (("example.test", 1), ("old.example.test", 1)),
        )

    def test_daily_delta_and_new_domains_use_previous_successful_run(self) -> None:
        records = (
            make_record(
                record_id="new-002",
                login="new2@example.test",
                first_seen="2026-09-25T01:00:00Z",
                event_id="event-new-2",
                source_type="stealer-log",
                domain="new.example.test",
            ),
        )
        previous = __import__("storage.history", fromlist=["DailyRunSummary"]).DailyRunSummary(
            run_id="2026-09-24_1000",
            report_start="2026-09-23T10:00:00+00:00",
            report_end="2026-09-24T10:00:00+00:00",
            total_records=5,
            new_compromises=3,
            newly_detected_7d=2,
            historical_records=2,
            target_domains=("old.example.test",),
        )
        with tempfile.TemporaryDirectory() as directory:
            with HistoryStore(Path(directory) / "history.db") as store:
                classifications = tuple(
                    classify_record(
                        store,
                        record,
                        observed_at=OBSERVED_AT,
                        newness_window_days=7,
                    )
                    for record in records
                )
        metrics = build_quick_view(
            "2026-09-25",
            classifications,
            records,
            report_end=OBSERVED_AT,
            previous_run=previous,
        )
        self.assertEqual(metrics.delta_new_compromises, -2)
        self.assertEqual(metrics.delta_newly_detected_7d, -2)
        self.assertEqual(metrics.delta_total_records, -4)
        self.assertEqual(metrics.newly_affected_domain_counts, (("new.example.test", 1),))

    def test_metrics_reject_misaligned_inputs(self) -> None:
        record = make_record(
            record_id="record-001",
            login="user@example.test",
            first_seen="2026-09-25T01:00:00Z",
            event_id="event-001",
            source_type="example-source",
        )

        with self.assertRaises(ValueError):
            build_quick_view("2026-09-25", tuple(), (record,))


if __name__ == "__main__":
    unittest.main()
