"""Tests for deterministic daily threat assessment."""

from __future__ import annotations

from datetime import datetime, timezone
import tempfile
import unittest
from pathlib import Path

from groupib.normalizer import normalize_record
from reporting.assessment import build_assessment
from reporting.summary import build_quick_view
from storage.classifier import classify_record
from storage.history import DailyRunSummary, HistoryStore


OBSERVED_AT = datetime(2026, 9, 25, 2, 0, tzinfo=timezone.utc)


def make_record(
    *,
    record_id: str,
    first_seen: str,
    domain: str,
    detected: str | None = None,
    source_link: str | None = None,
) -> object:
    payload = {
        "id": record_id,
        "login": f"{record_id}@example.test",
        "dateFirstSeen": first_seen,
        "dateLastSeen": first_seen,
        "events": [{"id": f"event-{record_id}"}],
        "sourceType": ["stealer-log"],
        "parsedLogin": {"domain": domain},
        "malware": [{"id": "m1", "name": "ExampleStealer"}],
    }
    if detected:
        payload["dateDetected"] = detected
    if source_link:
        payload["source"] = [{"id": source_link, "type": "Private channel"}]
    return normalize_record(payload)


class AssessmentTests(unittest.TestCase):
    def _metrics(self, records: tuple[object, ...], previous=None):
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
        return build_quick_view(
            "2026-09-25",
            classifications,
            records,
            report_end=datetime(2026, 9, 25, 10, 0, tzinfo=timezone.utc),
            previous_run=previous,
        )

    def test_first_run_is_limited_confidence(self) -> None:
        records = (
            make_record(
                record_id="new-1",
                first_seen="2026-09-25T01:00:00Z",
                domain="new.example.test",
                detected="2026-09-25T01:00:00Z",
                source_link="https://t.me/example/1",
            ),
        )
        result = build_assessment(self._metrics(records), records)
        self.assertEqual(result.activity_level, "OBSERVED ACTIVITY")
        self.assertEqual(result.confidence, "LIMITED")
        self.assertIn("first successful baseline", result.observations[-1].lower())

    def test_new_domain_and_recent_detection_are_elevated(self) -> None:
        records = (
            make_record(
                record_id="new-2",
                first_seen="2026-09-25T01:00:00Z",
                domain="new.example.test",
                detected="2026-09-25T01:00:00Z",
                source_link="https://t.me/example/2",
            ),
        )
        previous = DailyRunSummary(
            run_id="2026-09-24_1000",
            report_start="2026-09-23T10:00:00+00:00",
            report_end="2026-09-24T10:00:00+00:00",
            total_records=1,
            new_compromises=0,
            newly_detected_7d=0,
            historical_records=1,
            target_domains=("old.example.test",),
        )
        result = build_assessment(self._metrics(records, previous), records)
        self.assertEqual(result.activity_level, "ELEVATED ACTIVITY")
        self.assertEqual(result.confidence, "HIGH")
        self.assertTrue(result.analyst_attention)

    def test_no_new_activity_is_explicit(self) -> None:
        records = (
            make_record(
                record_id="old-1",
                first_seen="2026-09-01T01:00:00Z",
                domain="old.example.test",
            ),
        )
        previous = DailyRunSummary(
            run_id="2026-09-24_1000",
            report_start="2026-09-23T10:00:00+00:00",
            report_end="2026-09-24T10:00:00+00:00",
            total_records=1,
            new_compromises=0,
            newly_detected_7d=0,
            historical_records=1,
            target_domains=("old.example.test",),
        )
        result = build_assessment(self._metrics(records, previous), records)
        self.assertEqual(result.activity_level, "NO NEW ACTIVITY")
        self.assertEqual(result.confidence, "MODERATE")
        self.assertIn("No compromise records met", result.assessment)


if __name__ == "__main__":
    unittest.main()
