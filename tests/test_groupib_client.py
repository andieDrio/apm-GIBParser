"""Tests for the verified Group-IB response boundary."""

from __future__ import annotations

import unittest

import httpx

from groupib.client import (
    GroupIBClient,
    GroupIBConfigurationError,
    GroupIBRateLimitError,
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

    def test_parses_date_bounded_slice_response(self) -> None:
        response = GroupIBClient._parse_slice_response(
            {
                "count": 1,
                "resultId": "slice-001",
                "items": [{"id": "record-001"}],
            }
        )

        self.assertEqual(response.count, 1)
        self.assertEqual(response.result_id, "slice-001")
        self.assertEqual(response.items[0]["id"], "record-001")

    def test_rate_limit_respects_retry_after_header(self) -> None:
        response = httpx.Response(429, headers={"Retry-After": "120"})
        with self.assertRaises(GroupIBRateLimitError) as caught:
            GroupIBClient._raise_for_status(response)
        self.assertEqual(caught.exception.retry_after_seconds, 120)

    def test_rate_limit_uses_safe_default_for_invalid_retry_after(self) -> None:
        response = httpx.Response(429, headers={"Retry-After": "later"})
        with self.assertRaises(GroupIBRateLimitError) as caught:
            GroupIBClient._raise_for_status(response)
        self.assertEqual(caught.exception.retry_after_seconds, 60)

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
