"""Canonical normalization for the verified Group-IB account-update feed."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping


def _text(value: Any) -> str | None:
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return None


def _object(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, dict) else {}


def _strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item.strip() for item in value if isinstance(item, str) and item.strip())


def _objects(value: Any) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, dict))


@dataclass(frozen=True, slots=True)
class CanonicalGroupIBRecord:
    """Stable internal representation of one provider compromise record.

    Sensitive provider fields such as passwords are deliberately absent.
    """

    provider_record_id: str | None
    compromise_identity: str
    account: str | None
    username: str | None
    domain: str | None
    date_first_compromised: str | None
    date_last_compromised: str | None
    date_first_seen: str | None
    date_last_seen: str | None
    event_count: int
    stealer_families: tuple[str, ...]
    stealer_builds: tuple[str, ...]
    victim_ips: tuple[str, ...]
    target_urls: tuple[str, ...]
    source_types: tuple[str, ...]
    source_ids: tuple[str, ...]
    threat_actors: tuple[str, ...]
    service_domain: str | None
    service_host: str | None
    service_url: str | None
    event_ids: tuple[str, ...]
    observation_fingerprint: str


def _fallback_identity(
    *,
    account: str | None,
    domain: str | None,
    first_seen: str | None,
    last_seen: str | None,
    source_types: tuple[str, ...],
    event_ids: tuple[str, ...],
) -> str:
    material = {
        "account": account,
        "domain": domain,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "source_types": source_types,
        "event_ids": event_ids,
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def normalize_record(item: Mapping[str, Any]) -> CanonicalGroupIBRecord:
    """Normalize one verified provider item without retaining secret fields."""
    events = _objects(item.get("events"))
    parsed_login = _object(item.get("parsedLogin"))
    service = _object(item.get("service"))

    provider_record_id = _text(item.get("id"))
    account = _text(item.get("login"))
    username = _text(item.get("login"))
    domain = _text(parsed_login.get("domain"))

    first_seen = _text(item.get("dateFirstSeen"))
    last_seen = _text(item.get("dateLastSeen"))
    first_compromised = _text(item.get("dateFirstCompromised"))
    last_compromised = _text(item.get("dateLastCompromised"))

    source_types = _strings(item.get("sourceType"))
    source_objects = _objects(item.get("source"))
    source_ids = tuple(
        value
        for value in (_text(source.get("id")) for source in source_objects)
        if value
    )

    malware_objects = _objects(item.get("malware"))
    event_malware = tuple(
        _object(event.get("malware"))
        for event in events
        if isinstance(event.get("malware"), dict)
    )
    stealer_families = tuple(
        dict.fromkeys(
            value
            for value in (
                _text(malware.get("name"))
                for malware in (*malware_objects, *event_malware)
            )
            if value
        )
    )
    stealer_builds = tuple(
        dict.fromkeys(
            value
            for value in (
                _text(malware.get("id"))
                for malware in (*malware_objects, *event_malware)
            )
            if value
        )
    )

    victim_ips = tuple(
        dict.fromkeys(
            value
            for value in (
                _text(_object(_object(event.get("client")).get("ipv4")).get("ip"))
                for event in events
            )
            if value
        )
    )
    target_urls = tuple(
        dict.fromkeys(
            value
            for value in (
                _text(_object(event.get("cnc")).get("url"))
                for event in events
            )
            if value
        )
    )

    threat_actor_values = _strings(item.get("threatActor"))
    event_threat_actors = tuple(
        value
        for value in (_text(event.get("threatActor")) for event in events)
        if value
    )
    threat_actors = tuple(dict.fromkeys((*threat_actor_values, *event_threat_actors)))

    event_ids = tuple(
        dict.fromkeys(
            value
            for value in (_text(event.get("id")) for event in events)
            if value
        )
    )

    compromise_identity = (
        f"provider:{provider_record_id}"
        if provider_record_id
        else _fallback_identity(
            account=account,
            domain=domain,
            first_seen=first_seen,
            last_seen=last_seen,
            source_types=source_types,
            event_ids=event_ids,
        )
    )

    raw_event_count = item.get("eventCount")
    event_count = (
        raw_event_count
        if isinstance(raw_event_count, int) and not isinstance(raw_event_count, bool)
        else len(events)
    )

    observation_material = {
        "compromise_identity": compromise_identity,
        "account": account,
        "domain": domain,
        "first_compromised": first_compromised,
        "last_compromised": last_compromised,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "event_count": event_count,
        "event_ids": event_ids,
        "stealer_families": stealer_families,
        "source_types": source_types,
        "source_ids": source_ids,
        "threat_actors": threat_actors,
        "service_domain": _text(service.get("domain")),
        "service_host": _text(service.get("host")),
        "service_url": _text(service.get("url")),
    }
    encoded = json.dumps(
        observation_material,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    return CanonicalGroupIBRecord(
        provider_record_id=provider_record_id,
        compromise_identity=compromise_identity,
        account=account,
        username=username,
        domain=domain,
        date_first_compromised=first_compromised,
        date_last_compromised=last_compromised,
        date_first_seen=first_seen,
        date_last_seen=last_seen,
        event_count=event_count,
        stealer_families=stealer_families,
        stealer_builds=stealer_builds,
        victim_ips=victim_ips,
        target_urls=target_urls,
        source_types=source_types,
        source_ids=source_ids,
        threat_actors=threat_actors,
        service_domain=_text(service.get("domain")),
        service_host=_text(service.get("host")),
        service_url=_text(service.get("url")),
        event_ids=event_ids,
        observation_fingerprint="sha256:" + hashlib.sha256(encoded).hexdigest(),
    )


def normalize_response(
    items: tuple[Mapping[str, Any], ...],
) -> tuple[CanonicalGroupIBRecord, ...]:
    """Normalize a verified provider batch in provider order."""
    return tuple(normalize_record(item) for item in items)
