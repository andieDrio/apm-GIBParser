"""Tests for the verified Group-IB response boundary."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from groupib.client import (
    GroupIBClient,
    GroupIBConfigurationError,
    GroupIBSchemaError,
)


class GroupIBClientTests(unittest.TestCase):
    def test_parses_verified_response_shape(self) -> None:
        response = GroupIBClient._parse_response(
            {
                "count": 1,
                "seqUpdate": 42,
                "items": [{"id": "record-001"}],
            }
        )

        self.assertEqual(response.count, 1)
        self.assertEqual(response.seq_update, 42)
        self.assertEqual(len(response.items), 1)
        self.assertEqual(response.items[0]["id"], "record-001")

    def test_parses_sequence_list_cursor(self) -> None:
        sequence = GroupIBClient._parse_sequence_update(
            {"list": {"compromised/account_group": 123456789}}
        )
        self.assertEqual(sequence, 123456789)

    def test_formats_provider_date_bounds_as_utc(self) -> None:
        self.assertEqual(
            GroupIBClient._format_api_datetime(
                datetime(2026, 9, 25, 11, 13, tzinfo=timezone(timedelta(hours=8)))
            ),
            "2026-09-25T03:13:00Z",
        )

    def test_rejects_invalid_top_level_contract(self) -> None:
        with self.assertRaises(GroupIBSchemaError):
            GroupIBClient._parse_response({"count": "1", "seqUpdate": 42, "items": []})

    def test_requires_verified_credentials(self) -> None:
        with self.assertRaises(GroupIBConfigurationError):
            GroupIBClient("", "token")

        with self.assertRaises(GroupIBConfigurationError):
            GroupIBClient("user@example.test", "")


if __name__ == "__main__":
    unittest.main()
