"""Durable local history for deterministic Group-IB daily classification."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from groupib.normalizer import CanonicalGroupIBRecord

DEFAULT_HISTORY_PATH = Path("data/groupib_history.db")


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
        self._connection.commit()

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

        first_provider_seen = (
            existing.first_provider_seen if existing else None
        ) or record.date_first_seen

        last_provider_seen = record.date_last_seen or (
            existing.last_provider_seen if existing else None
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
                first_provider_seen = COALESCE(
                    compromises.first_provider_seen,
                    excluded.first_provider_seen
                ),
                last_provider_seen = COALESCE(
                    excluded.last_provider_seen,
                    compromises.last_provider_seen
                ),
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
