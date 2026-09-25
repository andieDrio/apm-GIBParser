"""Durable local history for deterministic Group-IB daily classification."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import json

from groupib.normalizer import CanonicalGroupIBRecord

DEFAULT_HISTORY_PATH = Path("data/groupib_history.db")


@dataclass(frozen=True, slots=True)
class DailyRunSummary:
    """Durable summary of one successfully generated daily report."""

    run_id: str
    report_start: str
    report_end: str
    total_records: int
    new_compromises: int
    newly_detected_7d: int
    historical_records: int
    target_domains: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HistoryRecord:
    compromise_identity: str
    provider_record_id: str | None
    first_local_seen: str
    last_local_seen: str
    first_provider_seen: str | None
    last_provider_seen: str | None
    last_classification: str
    last_observation_fingerprint: str
    updated_at: str


class HistoryStore:
    """SQLite-backed single-operator history store."""

    def __init__(self, path: str | Path = DEFAULT_HISTORY_PATH) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.path)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "HistoryStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @staticmethod
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

    @classmethod
    def _earliest_timestamp(
        cls,
        current: str | None,
        candidate: str | None,
    ) -> str | None:
        if current is None:
            return candidate
        if candidate is None:
            return current
        current_dt = cls._parse_timestamp(current)
        candidate_dt = cls._parse_timestamp(candidate)
        if current_dt is None or candidate_dt is None:
            return min(current, candidate)
        return candidate if candidate_dt < current_dt else current

    @classmethod
    def _latest_timestamp(
        cls,
        current: str | None,
        candidate: str | None,
    ) -> str | None:
        if current is None:
            return candidate
        if candidate is None:
            return current
        current_dt = cls._parse_timestamp(current)
        candidate_dt = cls._parse_timestamp(candidate)
        if current_dt is None or candidate_dt is None:
            return max(current, candidate)
        return candidate if candidate_dt > current_dt else current

    def _create_schema(self) -> None:
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS compromises (
                compromise_identity TEXT PRIMARY KEY,
                provider_record_id TEXT,
                first_local_seen TEXT NOT NULL,
                last_local_seen TEXT NOT NULL,
                first_provider_seen TEXT,
                last_provider_seen TEXT,
                last_classification TEXT NOT NULL,
                last_observation_fingerprint TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_compromises_provider_record_id
            ON compromises(provider_record_id)
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS daily_runs (
                run_id TEXT PRIMARY KEY,
                report_start TEXT NOT NULL,
                report_end TEXT NOT NULL,
                total_records INTEGER NOT NULL,
                new_compromises INTEGER NOT NULL,
                newly_detected_7d INTEGER NOT NULL,
                historical_records INTEGER NOT NULL,
                target_domains_json TEXT NOT NULL
            )
            """
        )
        self._connection.commit()

    def get_latest_daily_run(self) -> DailyRunSummary | None:
        """Return the most recent successfully persisted report summary."""
        row = self._connection.execute(
            """
            SELECT run_id, report_start, report_end,
                   total_records, new_compromises, newly_detected_7d,
                   historical_records, target_domains_json
            FROM daily_runs
            ORDER BY report_end DESC, run_id DESC
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            return None
        try:
            domains = tuple(
                value
                for value in json.loads(row["target_domains_json"])
                if isinstance(value, str) and value
            )
        except (TypeError, json.JSONDecodeError):
            domains = ()
        return DailyRunSummary(
            run_id=row["run_id"],
            report_start=row["report_start"],
            report_end=row["report_end"],
            total_records=row["total_records"],
            new_compromises=row["new_compromises"],
            newly_detected_7d=row["newly_detected_7d"],
            historical_records=row["historical_records"],
            target_domains=domains,
        )

    def record_daily_run(
        self,
        *,
        run_id: str,
        report_start: datetime,
        report_end: datetime,
        total_records: int,
        new_compromises: int,
        newly_detected_7d: int,
        historical_records: int,
        target_domains: tuple[str, ...],
    ) -> DailyRunSummary:
        """Persist a successful report run only after PDF generation succeeds."""
        if report_end <= report_start:
            raise ValueError("report_end must be after report_start.")
        if total_records < 0 or new_compromises < 0 or newly_detected_7d < 0:
            raise ValueError("daily run counts cannot be negative.")
        if historical_records < 0:
            raise ValueError("historical_records cannot be negative.")

        normalized_domains = tuple(sorted(set(
            domain.strip() for domain in target_domains if domain and domain.strip()
        )))
        self._connection.execute(
            """
            INSERT INTO daily_runs (
                run_id, report_start, report_end,
                total_records, new_compromises, newly_detected_7d,
                historical_records, target_domains_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id) DO UPDATE SET
                report_start = excluded.report_start,
                report_end = excluded.report_end,
                total_records = excluded.total_records,
                new_compromises = excluded.new_compromises,
                newly_detected_7d = excluded.newly_detected_7d,
                historical_records = excluded.historical_records,
                target_domains_json = excluded.target_domains_json
            """,
            (
                run_id,
                report_start.astimezone(timezone.utc).isoformat(timespec="seconds"),
                report_end.astimezone(timezone.utc).isoformat(timespec="seconds"),
                total_records,
                new_compromises,
                newly_detected_7d,
                historical_records,
                json.dumps(normalized_domains, separators=(",", ":")),
            ),
        )
        self._connection.commit()
        stored = self._connection.execute(
            """
            SELECT run_id, report_start, report_end,
                   total_records, new_compromises, newly_detected_7d,
                   historical_records, target_domains_json
            FROM daily_runs
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()
        if stored is None:
            raise RuntimeError("Daily run could not be read after commit.")
        return DailyRunSummary(
            run_id=stored["run_id"],
            report_start=stored["report_start"],
            report_end=stored["report_end"],
            total_records=stored["total_records"],
            new_compromises=stored["new_compromises"],
            newly_detected_7d=stored["newly_detected_7d"],
            historical_records=stored["historical_records"],
            target_domains=tuple(json.loads(stored["target_domains_json"])),
        )

    def get(self, compromise_identity: str) -> HistoryRecord | None:
        row = self._connection.execute(
            """
            SELECT compromise_identity, provider_record_id,
                   first_local_seen, last_local_seen,
                   first_provider_seen, last_provider_seen,
                   last_classification, last_observation_fingerprint,
                   updated_at
            FROM compromises
            WHERE compromise_identity = ?
            """,
            (compromise_identity,),
        ).fetchone()
        if row is None:
            return None
        return HistoryRecord(**dict(row))

    def record_observation(
        self,
        record: CanonicalGroupIBRecord,
        *,
        classification: str,
        observed_at: datetime | None = None,
    ) -> HistoryRecord:
        """Insert or update one logical compromise atomically."""
        now = (observed_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
        timestamp = now.isoformat(timespec="seconds")
        existing = self.get(record.compromise_identity)

        if existing is None:
            first_local_seen = timestamp
        else:
            first_local_seen = existing.first_local_seen

        first_provider_seen = self._earliest_timestamp(
            existing.first_provider_seen if existing else None,
            record.date_first_seen,
        )
        last_provider_seen = self._latest_timestamp(
            existing.last_provider_seen if existing else None,
            record.date_last_seen,
        )

        self._connection.execute(
            """
            INSERT INTO compromises (
                compromise_identity, provider_record_id,
                first_local_seen, last_local_seen,
                first_provider_seen, last_provider_seen,
                last_classification, last_observation_fingerprint,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(compromise_identity) DO UPDATE SET
                provider_record_id = excluded.provider_record_id,
                last_local_seen = excluded.last_local_seen,
                first_provider_seen = excluded.first_provider_seen,
                last_provider_seen = excluded.last_provider_seen,
                last_classification = excluded.last_classification,
                last_observation_fingerprint = excluded.last_observation_fingerprint,
                updated_at = excluded.updated_at
            """,
            (
                record.compromise_identity,
                record.provider_record_id,
                first_local_seen,
                timestamp,
                first_provider_seen,
                last_provider_seen,
                classification,
                record.observation_fingerprint,
                timestamp,
            ),
        )
        self._connection.commit()

        stored = self.get(record.compromise_identity)
        if stored is None:
            raise RuntimeError("History record could not be read after commit.")
        return stored
