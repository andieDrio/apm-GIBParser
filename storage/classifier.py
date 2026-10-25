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
        # Group-IB/UI-shaped timestamps may arrive as e.g.
        # "6/8/2023, 4:30:47 AM". Parse these explicitly instead of silently
        # skipping the actual compromise date and falling back to recent
        # first-seen/last-seen timestamps.
        parsed = None
        for date_format in (
            "%m/%d/%Y, %I:%M:%S %p",
            "%m/%d/%Y, %I:%M %p",
            "%m/%d/%Y",
            "%Y-%m-%d",
        ):
            try:
                parsed = datetime.strptime(normalized, date_format)
                break
            except ValueError:
                continue
        if parsed is None:
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
    provider_compromise_time = next(
        (
            parsed
            for value in (record.date_first_compromised, record.date_last_compromised)
            if (parsed := _parse_timestamp(value)) is not None
        ),
        None,
    )

    cutoff = now - timedelta(days=newness_window_days)
    # A valid provider timeline outside the newness window always wins over
    # local-history state. In particular, a changed observation fingerprint
    # or a recent Last Seen value must never keep an old compromise classified
    # as NEW/RESEEN. Last Seen is activity metadata, not compromise age.
    if provider_compromise_time is not None and provider_compromise_time < cutoff:
        classification = OLD
        reason = "Provider compromise/detection timeline predates the configured newness window; recent last-seen activity does not make it new."
    elif existing is not None:
        first_local_seen = _parse_timestamp(existing.first_local_seen)
        same_observation = existing.last_observation_fingerprint == record.observation_fingerprint
        if existing.last_classification == UNVERIFIED and provider_compromise_time is None:
            classification = UNVERIFIED
            reason = "Identity has no valid provider timeline; manual review remains required."
        elif not same_observation:
            classification = RESEEN
            reason = "Durable identity exists but the provider observation changed."
        elif provider_compromise_time is not None and provider_compromise_time >= cutoff and first_local_seen is not None and first_local_seen >= cutoff:
            classification = NEW
            reason = "Identity was first discovered within the newness window; unchanged refreshes preserve NEW status."
        else:
            classification = REPEAT
            reason = "Durable identity exists and observation fingerprint is unchanged."
    else:
        if provider_compromise_time is None:
            classification = UNVERIFIED
            reason = (
                "No durable identity exists and no valid Compromised Date is available; "
                "Last Seen, Date Detected, and First Seen cannot qualify a record as NEW."
            )
        elif provider_compromise_time < cutoff:
            classification = OLD
            reason = (
                "The provider Compromised Date predates the configured newness window; "
                "recent Last Seen activity does not make it new."
            )
        else:
            classification = NEW
            reason = (
                "The provider Compromised Date is within the configured newness policy "
                "and no durable identity match exists."
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
