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
    newness_window_days: int = 1,
) -> ClassificationResult:
    """Classify one record before atomically updating local history.

    NEW requires both:
    - no durable local identity match; and
    - the provider compromise/detection timeline is absent or falls within the configured window.

    Timeline precedence is Compromised Date, Last Compromised, Date Detected,
    then First Seen. This makes NEW represent recent compromise intelligence while
    still tolerating providers that omit individual timestamps.

    A known identity is never NEW. An unchanged known fingerprint is REPEAT;
    a changed observation of a known identity is RESEEN/RECYCLED.
    """
    if newness_window_days < 0:
        raise ValueError("newness_window_days cannot be negative.")

    now = (observed_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    existing = store.get(record.compromise_identity)

    if existing is not None:
        if existing.last_observation_fingerprint == record.observation_fingerprint:
            classification = REPEAT
            reason = "Durable identity exists and observation fingerprint is unchanged."
        else:
            classification = RESEEN
            reason = "Durable identity exists but the provider observation changed."
    else:
        provider_timeline = (
            record.date_first_compromised
            or record.date_last_compromised
            or record.date_detected
            or record.date_first_seen
        )
        provider_newness_time = _parse_timestamp(provider_timeline)
        cutoff = now - timedelta(days=newness_window_days)
        if (
            provider_newness_time is not None
            and provider_newness_time < cutoff
        ):
            classification = OLD
            reason = (
                "No durable identity exists, but the provider compromise/detection "
                "timeline predates the configured newness window."
            )
        else:
            classification = NEW
            reason = (
                "No durable identity exists and the provider compromise/detection "
                "timeline is within the configured newness policy."
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
