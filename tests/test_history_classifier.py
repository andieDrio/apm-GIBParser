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
    event_id: str = "event-001",
) -> object:
    return normalize_record(
        {
            "id": record_id,
            "login": "user@example.test",
            "dateFirstSeen": first_seen,
            "dateLastSeen": last_seen,
            "events": [{"id": event_id}],
            "sourceType": ["example-source"],
        }
    )


class HistoryClassificationTests(unittest.TestCase):
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
