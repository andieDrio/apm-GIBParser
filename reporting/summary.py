"""Pure daily Quick View metrics derived from classified Group-IB records."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from typing import Iterable

from groupib.normalizer import CanonicalGroupIBRecord
from storage.classifier import NEW, OLD, REPEAT, RESEEN, ClassificationResult


@dataclass(frozen=True, slots=True)
class QuickViewMetrics:
    """Immutable metrics for one daily retrieval."""

    report_date: str
    total_records: int
    new_compromises: int
    new_compromise_7d_daily_counts: tuple[tuple[str, int], ...]
    newly_detected_7d: int
    old_historical: int
    reseen_recycled: int
    repeat_records: int
    infostealer_records: int
    stealer_family_counts: tuple[tuple[str, int], ...]
    source_counts: tuple[tuple[str, int], ...]
    target_domain_counts: tuple[tuple[str, int], ...]


def _sorted_counts(values: Iterable[str]) -> tuple[tuple[str, int], ...]:
    counts = Counter(value for value in values if value)
    return tuple(sorted(counts.items(), key=lambda item: (-item[1], item[0].casefold())))


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


def _timeline_timestamp(record: CanonicalGroupIBRecord) -> datetime | None:
    return _parse_timestamp(
        record.date_first_compromised
        or record.date_last_compromised
        or record.date_detected
        or record.date_first_seen
    )


def _detected_timestamp(record: CanonicalGroupIBRecord) -> datetime | None:
    return _parse_timestamp(record.date_detected)


def build_quick_view(
    report_date: str,
    classifications: tuple[ClassificationResult, ...],
    records: tuple[CanonicalGroupIBRecord, ...],
) -> QuickViewMetrics:
    """Build report metrics without mutating history or provider records.

    Classifications and records must be in the same provider order.
    """
    if len(classifications) != len(records):
        raise ValueError("classifications and records must have equal lengths.")

    new_count = sum(item.classification == NEW for item in classifications)
    old_count = sum(item.classification == OLD for item in classifications)
    reseen_count = sum(item.classification == RESEEN for item in classifications)
    repeat_count = sum(item.classification == REPEAT for item in classifications)
    historical_count = old_count + reseen_count + repeat_count

    report_end = datetime.fromisoformat(report_date).replace(tzinfo=timezone.utc)
    seven_day_start = report_end - timedelta(days=6)
    daily_counts = Counter(
        timestamp.date().isoformat()
        for result, record in zip(classifications, records)
        if result.classification == NEW
        and (timestamp := _timeline_timestamp(record)) is not None
        and seven_day_start <= timestamp <= report_end + timedelta(days=1)
    )
    new_compromise_7d_daily_counts = tuple(
        (
            (seven_day_start + timedelta(days=offset)).date().isoformat(),
            daily_counts.get(
                (seven_day_start + timedelta(days=offset)).date().isoformat(),
                0,
            ),
        )
        for offset in range(7)
    )
    newly_detected_7d = sum(
        1
        for record in records
        if (
            (timestamp := _detected_timestamp(record)) is not None
            and seven_day_start <= timestamp <= report_end + timedelta(days=1)
        )
    )

    stealer_families = [
        family for record in records for family in record.stealer_families
    ]
    source_types = [
        source for record in records for source in record.source_types
    ]
    target_domains = [
        record.domain or record.service_domain
        for record in records
        if record.domain or record.service_domain
    ]

    return QuickViewMetrics(
        report_date=report_date,
        total_records=len(records),
        new_compromises=new_count,
        new_compromise_7d_daily_counts=new_compromise_7d_daily_counts,
        newly_detected_7d=newly_detected_7d,
        old_historical=historical_count,
        reseen_recycled=reseen_count,
        repeat_records=repeat_count,
        infostealer_records=sum(bool(record.stealer_families) for record in records),
        stealer_family_counts=_sorted_counts(stealer_families),
        source_counts=_sorted_counts(source_types),
        target_domain_counts=_sorted_counts(target_domains),
    )
