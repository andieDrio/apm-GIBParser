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

    Passwords are retained only because the project owner explicitly requested
    credential visibility in the operational PDF report.
    """

    provider_record_id: str | None
    compromise_identity: str
    account: str | None
    username: str | None
    password: str | None
    domain: str | None
    date_first_compromised: str | None
    date_last_compromised: str | None
    date_detected: str | None
    date_first_seen: str | None
    date_last_seen: str | None
    event_count: int
    stealer_families: tuple[str, ...]
    malware_ids: tuple[str, ...]
    victim_ips: tuple[str, ...]
    target_urls: tuple[str, ...]
    source_types: tuple[str, ...]
    source_ids: tuple[str, ...]
    threat_actors: tuple[str, ...]
    service_domain: str | None
    service_host: str | None
    service_url: str | None
    login_url: str | None
    victim_countries: tuple[str, ...]
    victim_cities: tuple[str, ...]
    victim_providers: tuple[str, ...]
    source_links: tuple[str, ...]
    source_names: tuple[str, ...]
    credential_present: bool
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
    """Normalize one verified provider item for operational reporting."""
    events = _objects(item.get("events"))
    parsed_login = _object(item.get("parsedLogin"))
    service = _object(item.get("service"))

    provider_record_id = _text(item.get("id"))
    account = _text(item.get("login"))
    username = _text(item.get("login"))
    password = _text(item.get("password"))
    if password is None:
        password = next(
            (
                value
                for value in (_text(event.get("password")) for event in events)
                if value
            ),
            None,
        )
    domain = _text(parsed_login.get("domain"))

    first_seen = _text(item.get("dateFirstSeen"))
    last_seen = _text(item.get("dateLastSeen"))

    detected = _text(item.get("dateDetected")) or _text(item.get("detectedAt"))
    event_detected_dates = tuple(
        value
        for value in (
            _text(event.get("dateDetected"))
            or _text(event.get("detectedAt"))
            for event in events
        )
        if value
    )
    if detected is None and event_detected_dates:
        detected = min(event_detected_dates)

    # Group-IB's current account_group contract exposes dateFirstCompromised /
    # dateLastCompromised at item level. Some provider records/legacy shapes can
    # instead expose dateCompromised (or compromisedAt) at the item/event level.
    # Normalize all verified compromise-date variants before rendering so the
    # PDF never loses an available Compromised Date merely because its location
    # differs in the returned record shape.
    first_compromised = _text(item.get("dateFirstCompromised"))
    last_compromised = _text(item.get("dateLastCompromised"))
    item_compromised = _text(item.get("dateCompromised")) or _text(item.get("compromisedAt"))
    if first_compromised is None and item_compromised:
        first_compromised = item_compromised
    if last_compromised is None and item_compromised:
        last_compromised = item_compromised

    event_compromised_dates = tuple(
        value
        for value in (
            _text(event.get("dateCompromised"))
            or _text(event.get("compromisedAt"))
            or _text(event.get("dateFirstCompromised"))
            or _text(event.get("dateLastCompromised"))
            for event in events
        )
        if value
    )
    if event_compromised_dates:
        if first_compromised is None:
            first_compromised = min(event_compromised_dates)
        if last_compromised is None:
            last_compromised = max(event_compromised_dates)

    source_types = _strings(item.get("sourceType"))
    source_objects = _objects(item.get("source"))
    source_ids = tuple(
        value
        for value in (_text(source.get("id")) for source in source_objects)
        if value
    )
    source_links = tuple(
        dict.fromkeys(
            value
            for value in (
                _text(source.get("id"))
                or _text(source.get("url"))
                or _text(source.get("link"))
                or _text(source.get("href"))
                for source in source_objects
            )
            if value
        )
    )
    event_source_objects = tuple(
        _object(event.get("source"))
        for event in events
        if isinstance(event.get("source"), dict)
    )
    event_source_names = tuple(
        dict.fromkeys(
            value
            for value in (
                _text(source.get("name"))
                or _text(source.get("type"))
                for source in event_source_objects
            )
            if value
        )
    )
    top_level_source_names = tuple(
        dict.fromkeys(
            value
            for value in (
                _text(source.get("name"))
                or _text(source.get("type"))
                for source in source_objects
            )
            if value
        )
    )
    source_names = (
        event_source_names
        if event_source_names
        else top_level_source_names
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
    malware_ids = tuple(
        dict.fromkeys(
            value
            for value in (
                _text(malware.get("id"))
                for malware in (*malware_objects, *event_malware)
            )
            if value
        )
    )

    client_ipv4 = tuple(
        _object(_object(event.get("client")).get("ipv4"))
        for event in events
        if _object(_object(event.get("client")).get("ipv4"))
    )
    victim_ips = tuple(
        dict.fromkeys(
            value
            for value in (_text(client.get("ip")) for client in client_ipv4)
            if value
        )
    )
    victim_countries = tuple(
        dict.fromkeys(
            value
            for value in (_text(client.get("countryName")) for client in client_ipv4)
            if value
        )
    )
    victim_cities = tuple(
        dict.fromkeys(
            value
            for value in (_text(client.get("city")) for client in client_ipv4)
            if value
        )
    )
    victim_providers = tuple(
        dict.fromkeys(
            value
            for value in (_text(client.get("provider")) for client in client_ipv4)
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
        "detected": detected,
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
        "login_url": _text(service.get("url")),
        "victim_ips": victim_ips,
        "victim_countries": victim_countries,
        "victim_cities": victim_cities,
        "victim_providers": victim_providers,
        "source_links": source_links,
        "source_names": source_names,
        "credential_present": password is not None,
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
        password=password,
        domain=domain,
        date_first_compromised=first_compromised,
        date_last_compromised=last_compromised,
        date_detected=detected,
        date_first_seen=first_seen,
        date_last_seen=last_seen,
        event_count=event_count,
        stealer_families=stealer_families,
        malware_ids=malware_ids,
        victim_ips=victim_ips,
        target_urls=target_urls,
        source_types=source_types,
        source_ids=source_ids,
        threat_actors=threat_actors,
        service_domain=_text(service.get("domain")),
        service_host=_text(service.get("host")),
        service_url=_text(service.get("url")),
        login_url=_text(service.get("url")),
        victim_countries=victim_countries,
        victim_cities=victim_cities,
        victim_providers=victim_providers,
        source_links=source_links,
        source_names=source_names,
        credential_present=password is not None,
        event_ids=event_ids,
        observation_fingerprint="sha256:" + hashlib.sha256(encoded).hexdigest(),
    )


def normalize_response(
    items: tuple[Mapping[str, Any], ...],
) -> tuple[CanonicalGroupIBRecord, ...]:
    """Normalize a verified provider batch in provider order."""
    return tuple(normalize_record(item) for item in items)
