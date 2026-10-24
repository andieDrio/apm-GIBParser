"""Deterministic NEW/OLD/REPEAT classification backed by local history."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from groupib.normalizer import CanonicalGroupIBRecord
from storage.history import HistoryRecord, HistoryStore


NEW = "NEW"
OLD = "OLD/HISTORICAL"
RESEEN = "RESEEN/RECYCLED"
REPEAT = "REPEAT"
UNVERIFIED = "UNVERIFIED"


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    classification: str
    compromise_identity: str
    history: HistoryRecord
    reason: str


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def classify_record(
    store: HistoryStore,
    record: CanonicalGroupIBRecord,
    *,
    observed_at: datetime | None = None,
    newness_window_days: int = 7,
) -> ClassificationResult:
    """Classify one record before atomically updating local history.

    NEW requires no durable identity match and a valid provider timeline within
    the configured newness window. An older valid timeline is OLD/HISTORICAL.
    If no valid timeline exists and the identity is unknown, the record is
    UNVERIFIED rather than being incorrectly promoted to NEW.

    Timeline precedence is Compromised Date, Last Compromised, Date Detected,
    then First Seen. A known identity is never NEW: unchanged observations are
    REPEAT and changed observations are RESEEN/RECYCLED.
    """
    if newness_window_days < 0:
        raise ValueError("newness_window_days cannot be negative.")

    now = (observed_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    existing = store.get(record.compromise_identity)
    provider_newness_time = next(
        (
            parsed
            for value in (
                record.date_first_compromised,
                record.date_last_compromised,
                record.date_detected,
                record.date_first_seen,
            )
            if (parsed := _parse_timestamp(value)) is not None
        ),
        None,
    )

    cutoff = now - timedelta(days=newness_window_days)
    if existing is not None:
        first_local_seen = _parse_timestamp(existing.first_local_seen)
        same_observation = existing.last_observation_fingerprint == record.observation_fingerprint
        if existing.last_classification == UNVERIFIED and provider_newness_time is None:
            classification = UNVERIFIED
            reason = "Identity has no valid provider timeline; manual review remains required."
        elif not same_observation:
            classification = RESEEN
            reason = "Durable identity exists but the provider observation changed."
        elif provider_newness_time is not None and provider_newness_time >= cutoff and first_local_seen is not None and first_local_seen >= cutoff:
            classification = NEW
            reason = "Identity was first discovered within the newness window; unchanged refreshes preserve NEW status."
        elif existing.last_classification == NEW and provider_newness_time is not None and provider_newness_time < cutoff:
            classification = OLD
            reason = "Previously new identity has aged beyond the configured timeline window."
        else:
            classification = REPEAT
            reason = "Durable identity exists and observation fingerprint is unchanged."
    else:
        if provider_newness_time is None:
            classification = UNVERIFIED
            reason = (
                "No durable identity exists and no valid provider compromise/"
                "detection/first-seen timestamp is available."
            )
        elif provider_newness_time < cutoff:
            classification = OLD
            reason = (
                "No durable identity exists, but the provider compromise/detection "
                "timeline predates the configured newness window."
            )
        else:
            classification = NEW
            reason = (
                "No durable identity exists and a valid provider compromise/"
                "detection timeline is within the configured newness policy."
            )

    history = store.record_observation(
        record,
        classification=classification,
        observed_at=now,
    )
    return ClassificationResult(
        classification=classification,
        compromise_identity=record.compromise_identity,
        history=history,
        reason=reason,
    )


def classify_records(
    store: HistoryStore,
    records: tuple[CanonicalGroupIBRecord, ...],
    *,
    observed_at: datetime | None = None,
    newness_window_days: int = 1,
) -> tuple[ClassificationResult, ...]:
    """Classify a batch in provider order with durable updates after each record."""
    return tuple(
        classify_record(
            store,
            record,
            observed_at=observed_at,
            newness_window_days=newness_window_days,
        )
        for record in records
    )
