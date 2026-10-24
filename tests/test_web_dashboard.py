"""Tests for the Group-IB dashboard API serialization and query safety."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from config import AppConfig
from web_dashboard import (
    _masked_login,
    _source_category,
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

    def test_login_masking_never_returns_plain_login(self) -> None:
        masked = _masked_login("administrator@example.test")
        self.assertNotEqual(masked, "administrator@example.test")
        self.assertIn("@example.test", masked)

    def test_source_category_only_maps_exact_provider_labels(self) -> None:
        unique = normalize_record({"id": "1", "login": "a@example.test", "sourceType": ["Unique"]})
        combo = normalize_record({"id": "2", "login": "b@example.test", "sourceType": ["Combolist"]})
        unknown = normalize_record({"id": "3", "login": "c@example.test", "sourceType": ["Leak site"]})
        self.assertEqual(_source_category(unique), "Unique")
        self.assertEqual(_source_category(combo), "Combolist")
        self.assertEqual(_source_category(unknown), "Unmapped")

    def test_date_range_rejects_more_than_30_calendar_days(self) -> None:
        with self.assertRaises(ValueError):
            _validate_range("2026-09-01", "2026-10-01")

    def test_date_range_accepts_same_day(self) -> None:
        start, end = _validate_range("2026-10-24", "2026-10-24")
        self.assertLessEqual(start, end)

    def test_dashboard_uses_automatic_filters_and_new_compromise_alert(self) -> None:
        from pathlib import Path

        html = (Path(__file__).resolve().parents[1] / "web" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="new-alert"', html)
        self.assertIn('el("date-from").addEventListener("change"', html)
        self.assertIn('addEventListener("change",applyFilter)', html)
        self.assertIn('load(true)', html)
        self.assertNotIn('id="refresh"', html)
        self.assertNotIn('id="apply"', html)
        self.assertLess(html.index('const selectedDomain=el("domain").value;'), html.index('if(payload.domains.includes(selectedDomain))'))


if __name__ == "__main__":
    unittest.main()
