"""Tests for the local dashboard shell's non-secret readiness contract."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from config import AppConfig
from web_dashboard import build_health_payload


class DashboardHealthTests(unittest.TestCase):
    def test_health_payload_reports_missing_credentials_without_values(self) -> None:
        with patch.dict(
            "os.environ",
            {"GROUP_IB_USERNAME": "", "GROUP_IB_API_TOKEN": "", "GROUP_IB_API_KEY": ""},
        ):
            payload = build_health_payload(AppConfig.from_environment())

        self.assertFalse(payload["credentials_configured"])
        self.assertFalse(payload["provider_api_connected"])
        self.assertEqual(payload["status"], "ok")
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
        self.assertFalse(payload["provider_api_connected"])
        serialized = str(payload)
        self.assertNotIn("analyst@example.invalid", serialized)
        self.assertNotIn("test-token-value-not-a-real-secret", serialized)


if __name__ == "__main__":
    unittest.main()
