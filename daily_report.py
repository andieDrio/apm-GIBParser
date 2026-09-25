"""One-command Group-IB rolling-window retrieval, classification and PDF reporting."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
import os
from pathlib import Path
import sys

from config import AppConfig
from groupib.client import GroupIBClient, GroupIBClientError
from groupib.normalizer import CanonicalGroupIBRecord, normalize_response
from reporting.assessment import build_assessment
from reporting.pdf import generate_daily_report
from reporting.summary import build_quick_view
from storage.classifier import classify_records
from storage.history import HistoryStore

DEFAULT_LIMIT = 500
DEFAULT_NEWNESS_WINDOW_DAYS = 7
DEFAULT_LATEST_LOOKBACK_DAYS = 30
DEFAULT_REPORT_DIRECTORY = Path("reports")
DEFAULT_HISTORY_PATH = Path("data/groupib_history.db")
PHILIPPINES_TZ = ZoneInfo("Asia/Manila")


@dataclass(frozen=True, slots=True)
class MonitoringWindow:
    """Exact rolling 24-hour reporting window in Philippines Time."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("Monitoring window timestamps must be timezone-aware.")
        if self.end <= self.start:
            raise ValueError("Monitoring window end must be after start.")
        if self.end - self.start != timedelta(days=1):
            raise ValueError("Monitoring window must be exactly 24 hours.")

    @property
    def sequence_bootstrap_date(self) -> str:
        """Return the report-window start calendar date for the provider cursor."""
        return self.start.astimezone(PHILIPPINES_TZ).date().isoformat()


def build_monitoring_window(observed_at: datetime) -> MonitoringWindow:
    """Build the previous 24 hours ending at the script execution time."""
    if observed_at.tzinfo is None:
        raise ValueError("observed_at must be timezone-aware.")
    end = observed_at.astimezone(PHILIPPINES_TZ)
    start = end - timedelta(days=1)
    return MonitoringWindow(start=start, end=end)


def _parse_provider_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.strip()
    if not normalized:
        return None
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(PHILIPPINES_TZ)


def _record_window_timestamp(record: CanonicalGroupIBRecord) -> datetime | None:
    """Use the provider's latest observation time, with first-seen fallback."""
    return _parse_provider_timestamp(
        record.date_last_seen or record.date_first_seen
    )


def filter_records_to_window(
    records: tuple[CanonicalGroupIBRecord, ...],
    window: MonitoringWindow,
) -> tuple[CanonicalGroupIBRecord, ...]:
    """Keep only provider records observed inside the exact rolling window."""
    return tuple(
        record
        for record in records
        if (
            (timestamp := _record_window_timestamp(record)) is not None
            and window.start <= timestamp <= window.end
        )
    )


def _positive_int(value: str | None, *, default: int, name: str) -> int:
    if value is None or not value.strip():
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer.") from exc
    if parsed <= 0:
        raise ValueError(f"{name} must be greater than zero.")
    return parsed


def run() -> Path:
    """Execute one complete rolling 24-hour Group-IB monitoring run."""
    config = AppConfig.from_environment()
    if not config.has_credentials():
        raise ValueError(
            "Group-IB credentials are missing. Set GROUP_IB_USERNAME and "
            "GROUP_IB_API_TOKEN in .env or the environment."
        )

    limit = _positive_int(
        os.getenv("GROUP_IB_DAILY_LIMIT"),
        default=DEFAULT_LIMIT,
        name="GROUP_IB_DAILY_LIMIT",
    )
    if limit > 500:
        raise ValueError("GROUP_IB_DAILY_LIMIT cannot exceed 500.")

    newness_window_days = _positive_int(
        os.getenv("GROUP_IB_NEWNESS_WINDOW_DAYS"),
        default=DEFAULT_NEWNESS_WINDOW_DAYS,
        name="GROUP_IB_NEWNESS_WINDOW_DAYS",
    )

    observed_at = datetime.now(timezone.utc)
    window = build_monitoring_window(observed_at)
    report_date = window.end.date().isoformat()
    output_stamp = window.end.strftime("%Y-%m-%d_%H%M")
    output_path = DEFAULT_REPORT_DIRECTORY / f"GIB_DailyReport_{output_stamp}.pdf"

    latest_lookback_days = _positive_int(
        os.getenv("GROUP_IB_LATEST_LOOKBACK_DAYS"),
        default=DEFAULT_LATEST_LOOKBACK_DAYS,
        name="GROUP_IB_LATEST_LOOKBACK_DAYS",
    )
    if latest_lookback_days > 30:
        raise ValueError("GROUP_IB_LATEST_LOOKBACK_DAYS cannot exceed 30.")

    provider_start = window.end - timedelta(days=latest_lookback_days)
    provider_start_utc = provider_start.astimezone(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    provider_end_utc = window.end.astimezone(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    with GroupIBClient(
        config.username,
        config.api_token,
        base_url=config.api_base_url,
        timeout_seconds=config.request_timeout_seconds,
    ) as client:
        response = client.get_compromised_account_slice(
            date_from=provider_start_utc,
            date_to=provider_end_utc,
            limit=limit,
        )

    provider_records = normalize_response(response.items)
    records = tuple(
        sorted(
            provider_records,
            key=lambda record: (
                _record_window_timestamp(record) or datetime.min.replace(
                    tzinfo=PHILIPPINES_TZ
                ),
                record.date_first_seen or "",
                record.provider_record_id,
            ),
            reverse=True,
        )
    )

    with HistoryStore(DEFAULT_HISTORY_PATH) as history:
        classifications = classify_records(
            history,
            records,
            observed_at=observed_at,
            newness_window_days=newness_window_days,
        )
        previous_run = history.get_latest_daily_run()
        metrics = build_quick_view(
            report_date,
            classifications,
            records,
            report_end=window.end,
            previous_run=previous_run,
        )
        assessment = build_assessment(metrics, records)
        generated = generate_daily_report(
            output_path,
            report_date=report_date,
            window_start=window.start,
            window_end=window.end,
            metrics=metrics,
            assessment=assessment,
            classifications=classifications,
            records=records,
            run_id=output_stamp,
            retrieved_count=len(response.items),
            normalized_count=len(records),
        )
        history.record_daily_run(
            run_id=output_stamp,
            report_start=window.start,
            report_end=window.end,
            total_records=len(records),
            new_compromises=metrics.new_compromises,
            newly_detected_7d=metrics.newly_detected_7d,
            historical_records=metrics.old_historical,
            target_domains=tuple(
                domain for domain, _ in metrics.target_domain_counts
            ),
        )
    return generated



def main() -> int:
    try:
        output = run()
    except (GroupIBClientError, ValueError, OSError) as exc:
        print(f"Daily Group-IB report failed: {exc}", file=sys.stderr)
        return 1

    print(f"Daily Group-IB report generated: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
