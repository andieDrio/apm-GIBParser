"""Bounded diagnostic for the latest Group-IB compromised-account stream."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import sys
from zoneinfo import ZoneInfo

from config import AppConfig
from groupib.client import GroupIBClient, GroupIBClientError

PHILIPPINES_TZ = ZoneInfo("Asia/Manila")
LOOKBACK_DAYS = 2
DISPLAY_LIMIT = 10


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
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


def _record_timestamps(item: dict[str, object]) -> list[datetime]:
    timestamps: list[datetime] = []
    for key in (
        "dateFirstCompromised",
        "dateLastCompromised",
        "dateFirstSeen",
        "dateLastSeen",
    ):
        parsed = _parse_timestamp(item.get(key))
        if parsed is not None:
            timestamps.append(parsed)

    events = item.get("events")
    if isinstance(events, list):
        for event in events:
            if not isinstance(event, dict):
                continue
            for key in (
                "dateFirstCompromised",
                "dateLastCompromised",
                "dateFirstSeen",
                "dateLastSeen",
                "dateCompromised",
                "dateDetected",
                "dateUpdated",
                "updated",
            ):
                parsed = _parse_timestamp(event.get(key))
                if parsed is not None:
                    timestamps.append(parsed)
    return timestamps


def _latest_timestamp(items: tuple[dict[str, object], ...]) -> datetime | None:
    timestamps = [
        timestamp
        for item in items
        for timestamp in _record_timestamps(item)
    ]
    return max(timestamps) if timestamps else None


def run() -> int:
    config = AppConfig.from_environment()
    if not config.has_credentials():
        print(
            "Latest-data diagnostic failed: Group-IB credentials are missing.",
            file=sys.stderr,
        )
        return 1

    observed_at = datetime.now(timezone.utc)
    sequence_date = (
        observed_at.astimezone(PHILIPPINES_TZ).date() - timedelta(days=LOOKBACK_DAYS)
    ).isoformat()

    try:
        with GroupIBClient(
            config.username,
            config.api_token,
            base_url=config.api_base_url,
            timeout_seconds=config.request_timeout_seconds,
        ) as client:
            response = client.get_compromised_account_updates(
                limit=500,
                sequence_date=sequence_date,
            )
    except GroupIBClientError as exc:
        print(f"Latest-data diagnostic failed: {exc}", file=sys.stderr)
        return 1

    items = tuple(dict(item) for item in response.items)
    latest = _latest_timestamp(items)
    max_item_seq = max(
        (
            item.get("seqUpdate")
            for item in items
            if isinstance(item.get("seqUpdate"), int)
        ),
        default=None,
    )
    latest_pht = latest.astimezone(PHILIPPINES_TZ).strftime(
        "%Y-%m-%d %I:%M:%S %p %Z"
    ) if latest else "NO PROVIDER TIMESTAMP"

    print("Group-IB Latest Provider Data Diagnostic")
    print(f"Sequence bootstrap date: {sequence_date}")
    print(f"Provider records retrieved: {len(items)}")
    print(f"Final seqUpdate: {response.seq_update}")
    print(f"Max item seqUpdate: {max_item_seq if max_item_seq is not None else 'NO ITEM SEQUENCE'}")
    print(f"Latest compromise/event timestamp: {latest_pht}")
    print("")
    print("Latest records (metadata only; no account/password/cookie values):")

    ranked = sorted(
        items,
        key=lambda item: item.get("seqUpdate", -1)
        if isinstance(item.get("seqUpdate"), int)
        else -1,
        reverse=True,
    )
    for index, item in enumerate(ranked[:DISPLAY_LIMIT], start=1):
        print(
            f"{index:02d}. "
            f"seqUpdate={item.get('seqUpdate', '—')} "
            f"id={'present' if item.get('id') else 'absent'} "
            f"firstSeen={item.get('dateFirstSeen', '—')} "
            f"lastSeen={item.get('dateLastSeen', '—')} "
            f"eventCount={item.get('eventCount', '—')}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(run())
