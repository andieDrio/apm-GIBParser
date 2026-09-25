"""Tests for durable history and deterministic classification."""

from __future__ import annotations

from datetime import datetime, timezone
import tempfile
import unittest
from pathlib import Path

from groupib.normalizer import normalize_record
from storage.classifier import NEW, OLD, REPEAT, RESEEN, classify_record
from storage.history import HistoryStore


OBSERVED_AT = datetime(2026, 9, 25, 2, 0, tzinfo=timezone.utc)


def make_record(
    *,
    record_id: str = "record-001",
    first_seen: str | None = "2026-09-25T01:00:00Z",
    last_seen: str | None = "2026-09-25T01:30:00Z",
    compromised: str | None = None,
    detected: str | None = None,
    event_id: str = "event-001",
) -> object:
    return normalize_record(
        {
            "id": record_id,
            "login": "user@example.test",
            "dateFirstSeen": first_seen,
            "dateLastSeen": last_seen,
            "dateFirstCompromised": compromised,
            "dateDetected": detected,
            "events": [{"id": event_id}],
            "sourceType": ["example-source"],
        }
    )


class HistoryClassificationTests(unittest.TestCase):
    def test_successful_daily_run_summary_is_durable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with HistoryStore(Path(directory) / "history.db") as store:
                stored = store.record_daily_run(
                    run_id="2026-09-25_1000",
                    report_start=datetime(2026, 9, 24, 10, 0, tzinfo=timezone.utc),
                    report_end=datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc),
                    total_records=10,
                    new_compromises=4,
                    newly_detected_7d=3,
                    historical_records=6,
                    target_domains=("b.example.test", "a.example.test"),
                )
                latest = store.get_latest_daily_run()

                self.assertEqual(stored.run_id, "2026-09-25_1000")
                self.assertIsNotNone(latest)
                self.assertEqual(latest.target_domains, ("a.example.test", "b.example.test"))
                self.assertEqual(latest.new_compromises, 4)

    def test_first_observation_is_new_and_persists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with HistoryStore(Path(directory) / "history.db") as store:
                result = classify_record(
                    store,
                    make_record(),
                    observed_at=OBSERVED_AT,
                )

                self.assertEqual(result.classification, NEW)
                self.assertIsNotNone(store.get("provider:record-001"))

    def test_same_observation_is_repeat(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with HistoryStore(Path(directory) / "history.db") as store:
                record = make_record()
                first = classify_record(store, record, observed_at=OBSERVED_AT)
                second = classify_record(store, record, observed_at=OBSERVED_AT)

                self.assertEqual(first.classification, NEW)
                self.assertEqual(second.classification, REPEAT)

    def test_changed_known_observation_is_reseen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with HistoryStore(Path(directory) / "history.db") as store:
                first = classify_record(
                    store, make_record(), observed_at=OBSERVED_AT
                )
                second = classify_record(
                    store,
                    make_record(event_id="event-002"),
                    observed_at=OBSERVED_AT,
                )

                self.assertEqual(first.classification, NEW)
                self.assertEqual(second.classification, RESEEN)

    def test_history_preserves_provider_timeline_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with HistoryStore(Path(directory) / "history.db") as store:
                record = make_record(
                    first_seen="2026-09-25T01:00:00Z",
                    last_seen="2026-09-25T02:00:00Z",
                )
                classify_record(store, record, observed_at=OBSERVED_AT)
                classify_record(
                    store,
                    make_record(
                        first_seen="2026-09-24T01:00:00Z",
                        last_seen="2026-09-26T02:00:00Z",
                    ),
                    observed_at=OBSERVED_AT,
                )

                history = store.get("provider:record-001")
                self.assertIsNotNone(history)
                self.assertEqual(
                    history.first_provider_seen,
                    "2026-09-24T01:00:00Z",
                )
                self.assertEqual(
                    history.last_provider_seen,
                    "2026-09-26T02:00:00Z",
                )

    def test_recent_compromise_is_new_even_when_first_seen_is_older(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with HistoryStore(Path(directory) / "history.db") as store:
                result = classify_record(
                    store,
                    make_record(
                        first_seen="2026-09-10T01:00:00Z",
                        compromised="2026-09-24T01:00:00Z",
                    ),
                    observed_at=OBSERVED_AT,
                    newness_window_days=7,
                )

                self.assertEqual(result.classification, NEW)

    def test_old_provider_timeline_is_not_new(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with HistoryStore(Path(directory) / "history.db") as store:
                result = classify_record(
                    store,
                    make_record(first_seen="2026-09-20T01:00:00Z"),
                    observed_at=OBSERVED_AT,
                    newness_window_days=1,
                )

                self.assertEqual(result.classification, OLD)


if __name__ == "__main__":
    unittest.main()
