"""One-command Group-IB daily retrieval, classification and PDF reporting."""

from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import os
from pathlib import Path
import sys

from config import AppConfig
from groupib.client import GroupIBClient, GroupIBClientError
from groupib.normalizer import normalize_response
from reporting.pdf import generate_daily_report
from reporting.summary import build_quick_view
from storage.classifier import classify_records
from storage.history import HistoryStore

DEFAULT_LIMIT = 500
DEFAULT_NEWNESS_WINDOW_DAYS = 1
DEFAULT_REPORT_DIRECTORY = Path("reports")
DEFAULT_HISTORY_PATH = Path("data/groupib_history.db")
PHILIPPINES_TZ = ZoneInfo("Asia/Manila")


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
    """Execute one complete daily monitoring run."""
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
    report_date = observed_at.astimezone(PHILIPPINES_TZ).date().isoformat()
    output_path = DEFAULT_REPORT_DIRECTORY / f"GIB_DailyReport_{report_date}.pdf"

    with GroupIBClient(
        config.username,
        config.api_token,
        base_url=config.api_base_url,
        timeout_seconds=config.request_timeout_seconds,
    ) as client:
        response = client.get_compromised_account_updates(limit=limit)

    records = normalize_response(response.items)

    with HistoryStore(DEFAULT_HISTORY_PATH) as history:
        classifications = classify_records(
            history,
            records,
            observed_at=observed_at,
            newness_window_days=newness_window_days,
        )

    metrics = build_quick_view(report_date, classifications, records)
    return generate_daily_report(
        output_path,
        report_date=report_date,
        metrics=metrics,
        classifications=classifications,
        records=records,
    )


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
