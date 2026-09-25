"""Contract-driven tests for the Group-IB Phase 3 normalizer."""

from __future__ import annotations

import unittest

from groupib.normalizer import normalize_record


class GroupIBNormalizerTests(unittest.TestCase):
    def test_normalizes_verified_shape_for_operational_reporting(self) -> None:
        item = {
            "id": "record-001",
            "login": "user@example.test",
            "dateFirstCompromised": None,
            "dateFirstSeen": "2026-09-25T08:00:00Z",
            "dateDetected": "2026-09-25T08:01:00Z",
            "dateLastCompromised": None,
            "dateLastSeen": "2026-09-25T08:00:00Z",
            "eventCount": 1,
            "events": [
                {
                    "id": "event-001",
                    "dateCompromised": "2026-09-24T23:00:00Z",
                    "dateDetected": "2026-09-25T08:01:00Z",
                    "source": {"name": "Private channel", "type": "Telegram"},
                    "client": {
                        "ipv4": {
                            "ip": "192.0.2.10",
                            "countryName": "Philippines",
                            "city": "Quezon City",
                            "provider": "Example ISP",
                        }
                    },
                    "cnc": {"domain": "example.test", "url": "https://example.test"},
                    "malware": {
                        "id": "stealer-id",
                        "name": "ExampleStealer",
                        "stixGuid": "stix-guid",
                    },
                }
            ],
            "malware": [
                {
                    "id": "stealer-id",
                    "name": "ExampleStealer",
                    "stixGuid": "stix-guid",
                }
            ],
            "parsedLogin": {"domain": "example.test", "ip": None},
            "sourceType": ["example-source"],
            "service": {
                "domain": "example.test",
                "host": "portal.example.test",
                "ip": None,
                "url": "https://portal.example.test/login",
            },
            "password": "must-never-enter-canonical-model",
            "source": [
                {
                    "id": "https://t.me/example/123",
                    "name": "TG bot",
                    "type": "Private channel",
                }
            ],
            "threatActor": [],
        }

        record = normalize_record(item)

        self.assertEqual(record.provider_record_id, "record-001")
        self.assertEqual(record.compromise_identity, "provider:record-001")
        self.assertEqual(record.account, "user@example.test")
        self.assertEqual(record.username, "user@example.test")
        self.assertEqual(record.password, "must-never-enter-canonical-model")
        self.assertEqual(record.domain, "example.test")
        self.assertEqual(record.stealer_families, ("ExampleStealer",))
        self.assertEqual(record.event_ids, ("event-001",))
        self.assertEqual(record.source_types, ("example-source",))
        self.assertEqual(record.service_url, "https://portal.example.test/login")
        self.assertEqual(record.login_url, "https://portal.example.test/login")
        self.assertEqual(record.date_first_compromised, "2026-09-24T23:00:00Z")
        self.assertEqual(record.date_detected, "2026-09-25T08:01:00Z")
        self.assertEqual(record.victim_ips, ("192.0.2.10",))
        self.assertEqual(record.victim_countries, ("Philippines",))
        self.assertEqual(record.victim_cities, ("Quezon City",))
        self.assertEqual(record.victim_providers, ("Example ISP",))
        self.assertEqual(record.source_links, ("https://t.me/example/123",))
        self.assertEqual(record.source_names, ("Private channel",))
        self.assertTrue(record.credential_present)

    def test_fallback_identity_is_deterministic(self) -> None:
        item = {
            "login": "user@example.test",
            "parsedLogin": {"domain": "example.test"},
            "dateFirstSeen": "2026-09-25T08:00:00Z",
            "dateLastSeen": "2026-09-25T08:00:00Z",
            "sourceType": ["example-source"],
            "events": [{"id": "event-001"}],
        }

        first = normalize_record(item)
        second = normalize_record(dict(item))

        self.assertEqual(first.compromise_identity, second.compromise_identity)
        self.assertTrue(first.compromise_identity.startswith("sha256:"))
        self.assertEqual(first.observation_fingerprint, second.observation_fingerprint)


if __name__ == "__main__":
    unittest.main()
