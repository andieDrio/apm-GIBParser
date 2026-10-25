"""Tests for the Group-IB dashboard API serialization and query safety."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from config import AppConfig
from web_dashboard import (
    _classification_matches,
    _record_view,
    _source_category,
    _timestamp,
    _validate_range,
    build_health_payload,
)
from groupib.normalizer import normalize_record


class DashboardHealthTests(unittest.TestCase):
    def test_health_payload_reports_missing_credentials_without_values(self) -> None:
        with patch.dict(
            "os.environ",
            {"GROUP_IB_USERNAME": "", "GROUP_IB_API_TOKEN": "", "GROUP_IB_API_KEY": ""},
        ):
            payload = build_health_payload(AppConfig.from_environment())

        self.assertFalse(payload["credentials_configured"])
        self.assertNotIn("username", payload)
        self.assertNotIn("api_token", payload)
        self.assertNotIn("api_key", payload)

    def test_health_payload_never_returns_configured_secret_values(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "GROUP_IB_USERNAME": "analyst@example.invalid",
                "GROUP_IB_API_TOKEN": "test-token-value-not-a-real-secret",
                "GROUP_IB_API_KEY": "",
            },
        ):
            payload = build_health_payload(AppConfig.from_environment())

        self.assertTrue(payload["credentials_configured"])
        self.assertNotIn("analyst@example.invalid", str(payload))
        self.assertNotIn("test-token-value-not-a-real-secret", str(payload))

    def test_source_category_only_maps_exact_provider_labels(self) -> None:
        unique = normalize_record({"id": "1", "login": "a@example.test", "sourceType": ["Unique"]})
        combo = normalize_record({"id": "2", "login": "b@example.test", "sourceType": ["Combolist"]})
        nested_unique = normalize_record({"id": "4", "login": "d@example.test", "source": [{"name": "Unique"}]})
        string_unique = normalize_record({"id": "5", "login": "e@example.test", "sourceType": "Unique"})
        unknown = normalize_record({"id": "3", "login": "c@example.test", "sourceType": ["Leak site"]})
        self.assertEqual(_source_category(unique), "Unique")
        self.assertEqual(_source_category(nested_unique), "Unique")
        self.assertEqual(_source_category(string_unique), "Unique")
        self.assertEqual(_source_category(combo), "Combolist")
        self.assertEqual(_source_category(unknown), "Unmapped")

    def test_dashboard_metric_cards_are_not_tied_to_table_drilldown_filters(self) -> None:
        from pathlib import Path

        source = (Path(__file__).resolve().parents[1] / "web_dashboard.py").read_text(encoding="utf-8")
        self.assertIn("metric_pairs = []", source)
        self.assertIn("metric_pairs.append((record, classification))", source)
        self.assertIn("metric_classifications,", source)
        self.assertIn("for category in (\"Unique\", \"Combolist\", \"Unmapped\")", source)

    def test_clickable_metric_filter_matches_recycled_old_and_repeat(self) -> None:
        self.assertTrue(_classification_matches("recycled-old", "RESEEN/RECYCLED"))
        self.assertTrue(_classification_matches("recycled-old", "OLD/HISTORICAL"))
        self.assertTrue(_classification_matches("recycled-old", "REPEAT"))
        self.assertFalse(_classification_matches("recycled-old", "NEW"))
        self.assertTrue(_classification_matches("all", "NEW"))

    def test_date_filter_timestamp_uses_compromise_date_not_recent_last_seen(self) -> None:
        record = normalize_record({
            "id": "old-compromise",
            "login": "user@example.test",
            "dateFirstCompromised": "6/8/2023, 4:30:47 AM",
            "dateFirstSeen": "7/20/2023, 7:37:25 AM",
            "dateLastSeen": "10/24/2026, 7:13:20 PM",
        })

        timestamp = _timestamp(record)

        self.assertIsNotNone(timestamp)
        self.assertEqual(timestamp.year, 2023)
        self.assertEqual(timestamp.month, 6)
        self.assertEqual(timestamp.day, 8)

    def test_date_filter_falls_back_when_compromise_date_is_missing(self) -> None:
        record = normalize_record({
            "id": "detected-recently",
            "login": "user@example.test",
            "dateDetected": "2026-10-24T10:00:00Z",
            "dateFirstSeen": "2026-10-20T10:00:00Z",
            "dateLastSeen": "2026-10-24T11:00:00Z",
        })

        timestamp = _timestamp(record)

        self.assertIsNotNone(timestamp)
        self.assertEqual(timestamp.year, 2026)
        self.assertEqual(timestamp.month, 10)
        self.assertEqual(timestamp.day, 24)

    def test_date_range_rejects_more_than_30_calendar_days(self) -> None:
        with self.assertRaises(ValueError):
            _validate_range("2026-09-01", "2026-10-01")

    def test_date_range_accepts_same_day(self) -> None:
        start, end = _validate_range("2026-10-24", "2026-10-24")
        self.assertLessEqual(start, end)

    def test_record_view_includes_compromise_timeline_and_unmasked_credentials(self) -> None:
        from pathlib import Path
        from datetime import datetime, timezone
        import tempfile
        from storage.classifier import classify_record
        from storage.history import HistoryStore

        record = normalize_record({
            "id": "sensitive-test",
            "login": "person@example.test",
            "password": "local-test-password",
            "dateFirstCompromised": "2026-10-20T01:00:00Z",
            "dateFirstSeen": "2026-10-21T01:00:00Z",
            "dateLastSeen": "2026-10-22T01:00:00Z",
            "dateDetected": "2026-10-22T01:00:00Z",
        })
        with tempfile.TemporaryDirectory() as directory:
            with HistoryStore(Path(directory) / "history.db") as store:
                result = classify_record(store, record, observed_at=datetime(2026, 10, 24, tzinfo=timezone.utc))
        view = _record_view(record, result)
        self.assertEqual(view["login"], "person@example.test")
        self.assertEqual(view["password"], "local-test-password")
        self.assertEqual(view["date_first_compromised"], "2026-10-20T01:00:00Z")
        self.assertEqual(view["first_seen"], "2026-10-21T01:00:00Z")
        self.assertEqual(view["last_seen"], "2026-10-22T01:00:00Z")

    def test_dashboard_has_fixed_footer_export_and_small_page_sizes(self) -> None:
        from pathlib import Path

        html = (Path(__file__).resolve().parents[1] / "web" / "index.html").read_text(encoding="utf-8")
        self.assertIn('class="dashboard-scroll"', html)
        self.assertIn('id="export-csv"', html)
        self.assertIn('id="export-pdf"', html)
        self.assertIn('<option>10</option><option selected>15</option><option>25</option>', html)
        self.assertIn('Compromised date', html)
        self.assertIn('td.className="credential"', html)

    def test_dashboard_uses_automatic_filters_and_new_compromise_alert(self) -> None:
        from pathlib import Path

        html = (Path(__file__).resolve().parents[1] / "web" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="new-alert"', html)
        self.assertEqual(html.count('class="card metric-card"'), 4)
        self.assertIn('data-metric-filter="new"', html)
        self.assertIn('data-metric-filter="recycled-old"', html)
        self.assertIn('data-metric-filter="unique"', html)
        self.assertIn('data-metric-filter="combolist"', html)
        self.assertIn('function selectMetricFilter(filter)', html)
        self.assertIn('class="sidebar"', html)
        self.assertIn('data-section="overview"', html)
        self.assertIn('data-section="new-accounts"', html)
        self.assertIn('data-section="accounts"', html)
        self.assertIn('data-section="domains-section"', html)
        self.assertIn('data-section="malware-section"', html)
        self.assertIn('id="new-account-list"', html)
        self.assertIn('id="domain-summary-list"', html)
        self.assertIn('id="malware-summary-list"', html)
        self.assertIn('function scheduleDateLoad(){clearTimeout(dateLoadTimer);currentPage=1;dateLoadTimer=setTimeout(()=>load(true),350)}', html)
        self.assertIn('setInterval(()=>{if(!document.hidden)load(true)},300000)', html)
        self.assertIn('class="top-nav"', html)
        self.assertIn('id="notification-bell"', html)
        self.assertIn('id="enable-notifications"', html)
        self.assertIn('new Notification("Group-IB: New compromise accounts"', html)
        self.assertIn('id="notification-popover"', html)
        self.assertIn('el("date-from").addEventListener("change"', html)
        self.assertIn('addEventListener("change",applyFilter)', html)
        self.assertIn('load(true)', html)
        self.assertNotIn('id="refresh"', html)
        self.assertNotIn('id="apply"', html)
        self.assertLess(html.index('const selectedDomain=el("domain").value;'), html.index('if(payload.domains.includes(selectedDomain))'))


if __name__ == "__main__":
    unittest.main()
