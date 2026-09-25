"""Tests for the verified Group-IB response boundary."""

from __future__ import annotations

import unittest

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
