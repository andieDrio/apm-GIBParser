"""Loopback-only local web dashboard for Group-IB account intelligence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit
from zoneinfo import ZoneInfo
import json
import threading

from config import AppConfig
from groupib.client import GroupIBClient, GroupIBClientError
from groupib.normalizer import CanonicalGroupIBRecord, normalize_response
from reporting.assessment import build_assessment
from reporting.summary import build_quick_view
from storage.classifier import ClassificationResult, classify_records
from storage.history import DEFAULT_HISTORY_PATH, HistoryStore

HOST = "127.0.0.1"
PORT = 8765
WEB_ROOT = Path(__file__).resolve().parent / "web"
INDEX_FILE = WEB_ROOT / "index.html"
PHILIPPINES_TZ = ZoneInfo("Asia/Manila")
MAX_COLLECTION_DAYS = 30
DEFAULT_PAGE_SIZE = 100

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'self'; connect-src 'self'; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}

_snapshot_lock = threading.Lock()
_snapshot: dict[str, Any] | None = None


def build_health_payload(config: AppConfig | None = None) -> dict[str, Any]:
    """Return non-secret local readiness metadata."""
    current = config or AppConfig.from_environment()
    return {
        "status": "ok",
        "credentials_configured": current.has_credentials(),
        "provider_api_connected": bool(_snapshot and _snapshot.get("provider_connected")),
        "last_refresh": _snapshot.get("refreshed_at") if _snapshot else None,
        "record_count": len(_snapshot["records"]) if _snapshot else 0,
        "next_gate": "W4 - source category semantics, pagination and filter validation.",
    }


def _parse_date(value: str, name: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must use YYYY-MM-DD format.") from exc
    return parsed.replace(tzinfo=PHILIPPINES_TZ)


def _validate_range(date_from: str, date_to: str) -> tuple[datetime, datetime]:
    start = _parse_date(date_from, "date_from")
    end = _parse_date(date_to, "date_to") + timedelta(days=1) - timedelta(microseconds=1)
    if end < start:
        raise ValueError("date_to must be on or after date_from.")
    if (end - start).days >= MAX_COLLECTION_DAYS:
        raise ValueError("Collection range cannot exceed 30 calendar days.")
    if end > datetime.now(PHILIPPINES_TZ) + timedelta(days=1):
        raise ValueError("date_to cannot be in the future.")
    return start, end


def _source_category(record: CanonicalGroupIBRecord) -> str:
    normalized = {value.strip().casefold() for value in record.source_types}
    if "unique" in normalized:
        return "Unique"
    if "combolist" in normalized or "combo list" in normalized:
        return "Combolist"
    return "Unmapped"


def _timestamp(record: CanonicalGroupIBRecord) -> datetime | None:
    value = record.date_last_seen or record.date_first_seen
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
    return parsed.astimezone(PHILIPPINES_TZ)


def _masked_login(value: str | None) -> str:
    if not value:
        return "Not provided"
    if "@" in value:
        name, domain = value.rsplit("@", 1)
        visible = name[:2] if len(name) > 2 else name[:1]
        return f"{visible}{'*' * max(3, len(name) - len(visible))}@{domain}"
    return value[:2] + "*" * max(3, len(value) - 2)


def _record_view(record: CanonicalGroupIBRecord, result: ClassificationResult) -> dict[str, Any]:
    return {
        "first_seen": record.date_first_seen,
        "last_seen": record.date_last_seen,
        "date_first_compromised": record.date_first_compromised,
        "date_last_compromised": record.date_last_compromised,
        "date_detected": record.date_detected,
        "domain": record.domain or record.service_domain or "Not provided",
        "login": _masked_login(record.account),
        "source_types": list(record.source_types),
        "source_category": _source_category(record),
        "malware": list(record.stealer_families),
        "event_count": record.event_count,
        "classification": result.classification,
        "classification_reason": result.reason,
        "credential_present": record.credential_present,
        "provider_record_id": record.provider_record_id,
        "sort_timestamp": (
            _timestamp(record).isoformat() if _timestamp(record) else None
        ),
    }


def _load_snapshot(date_from: str, date_to: str) -> dict[str, Any]:
    config = AppConfig.from_environment()
    if not config.has_credentials():
        raise ValueError("Group-IB credentials are missing. Check local .env configuration.")
    start, end = _validate_range(date_from, date_to)
    provider_start = start.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    provider_end = end.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with GroupIBClient(
        config.username,
        config.api_token,
        base_url=config.api_base_url,
        timeout_seconds=config.request_timeout_seconds,
    ) as client:
        response = client.get_compromised_account_slice(
            date_from=provider_start,
            date_to=provider_end,
            limit=500,
        )

    records = normalize_response(response.items)
    observed_at = datetime.now(timezone.utc)
    with HistoryStore(DEFAULT_HISTORY_PATH) as history:
        classifications = classify_records(
            history,
            records,
            observed_at=observed_at,
            newness_window_days=7,
        )

    pairs = sorted(
        zip(records, classifications),
        key=lambda pair: (
            _timestamp(pair[0]) or datetime.min.replace(tzinfo=PHILIPPINES_TZ),
            pair[0].date_first_seen or "",
            pair[0].provider_record_id or "",
        ),
        reverse=True,
    )
    refreshed_at = datetime.now(PHILIPPINES_TZ).isoformat()
    return {
        "provider_connected": True,
        "refreshed_at": refreshed_at,
        "date_from": date_from,
        "date_to": date_to,
        "records": tuple(pair[0] for pair in pairs),
        "classifications": tuple(pair[1] for pair in pairs),
        "retrieved_count": len(response.items),
        "normalized_count": len(records),
        "collection_complete": True,
    }


def _filtered_payload(query: dict[str, list[str]]) -> dict[str, Any]:
    if not _snapshot:
        raise ValueError("No Group-IB records loaded. Choose dates and click Refresh from Group-IB.")

    date_from = (query.get("date_from") or [_snapshot["date_from"]])[0]
    date_to = (query.get("date_to") or [_snapshot["date_to"]])[0]
    start, end = _validate_range(date_from, date_to)
    if date_from < _snapshot["date_from"] or date_to > _snapshot["date_to"]:
        raise ValueError("Selected dates are outside the loaded collection. Click Refresh from Group-IB to load that range.")

    domain_filter = (query.get("domain") or [""])[0].strip().casefold()
    source_filter = (query.get("source") or ["all"])[0].strip().casefold()
    classification_filter = (query.get("classification") or ["all"])[0].strip().casefold()
    page_raw = (query.get("page") or ["1"])[0]
    size_raw = (query.get("page_size") or [str(DEFAULT_PAGE_SIZE)])[0]
    try:
        page, page_size = int(page_raw), int(size_raw)
    except ValueError as exc:
        raise ValueError("page and page_size must be integers.") from exc
    if page < 1 or not 1 <= page_size <= 200:
        raise ValueError("page must be positive and page_size must be between 1 and 200.")

    pairs = []
    for record, classification in zip(_snapshot["records"], _snapshot["classifications"]):
        stamp = _timestamp(record)
        if stamp is None or not start <= stamp <= end:
            continue
        domain = record.domain or record.service_domain or ""
        if domain_filter and domain.casefold() != domain_filter:
            continue
        category = _source_category(record).casefold()
        if source_filter != "all" and category != source_filter:
            continue
        if classification_filter != "all" and classification.classification.casefold() != classification_filter:
            continue
        pairs.append((record, classification))

    pairs.sort(
        key=lambda pair: (
            _timestamp(pair[0]) or datetime.min.replace(tzinfo=PHILIPPINES_TZ),
            pair[0].date_first_seen or "",
        ),
        reverse=True,
    )
    total_filtered = len(pairs)
    page_pairs = pairs[(page - 1) * page_size:page * page_size]
    records = tuple(pair[0] for pair in pairs)
    classifications = tuple(pair[1] for pair in pairs)
    report_end = end
    metrics = build_quick_view(
        date_to,
        classifications,
        records,
        report_end=report_end,
        previous_run=None,
    )
    assessment = build_assessment(metrics, records)
    all_domains = sorted(
        {
            record.domain or record.service_domain
            for record in _snapshot["records"]
            if record.domain or record.service_domain
        },
        key=str.casefold,
    )
    category_counts = {
        category: sum(_source_category(record).casefold() == category.casefold()
                      for record in _snapshot["records"])
        for category in ("Unique", "Combolist", "Unmapped")
    }
    return {
        "status": "ok",
        "collection": {
            "provider": "Group-IB TI&A",
            "refreshed_at": _snapshot["refreshed_at"],
            "date_from": _snapshot["date_from"],
            "date_to": _snapshot["date_to"],
            "retrieved_count": _snapshot["retrieved_count"],
            "normalized_count": _snapshot["normalized_count"],
            "collection_complete": _snapshot["collection_complete"],
            "sort_basis": "dateLastSeen; fallback dateFirstSeen",
        },
        "filters": {
            "date_from": date_from,
            "date_to": date_to,
            "domain": domain_filter,
            "source": source_filter,
            "classification": classification_filter,
            "page": page,
            "page_size": page_size,
        },
        "total_filtered": total_filtered,
        "total_pages": max(1, (total_filtered + page_size - 1) // page_size),
        "metrics": {
            "new": sum(x.classification == "NEW" for x in classifications),
            "recycled": sum(x.classification == "RESEEN/RECYCLED" for x in classifications),
            "old": sum(x.classification == "OLD/HISTORICAL" for x in classifications),
            "repeat": sum(x.classification == "REPEAT" for x in classifications),
            "unverified": sum(x.classification == "UNVERIFIED" for x in classifications),
            "unique": category_counts["Unique"],
            "combolist": category_counts["Combolist"],
            "unmapped_source": category_counts["Unmapped"],
            "total": len(records),
        },
        "domains": all_domains,
        "records": [_record_view(record, result) for record, result in page_pairs],
        "assessment": {
            "activity_level": assessment.activity_level,
            "confidence": assessment.confidence,
            "facts": list(assessment.facts),
            "observations": list(assessment.observations),
            "assessment": assessment.assessment,
            "analyst_attention": list(assessment.analyst_attention),
        },
    }


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "GroupIBDashboard"
    sys_version = ""

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802
        global _snapshot
        parsed = urlsplit(self.path)
        if parsed.path in ("/", "/index.html"):
            try:
                body = INDEX_FILE.read_bytes()
            except OSError:
                self._send(500, b"Dashboard UI is unavailable.", "text/plain; charset=utf-8")
                return
            self._send(200, body, "text/html; charset=utf-8")
            return
        if parsed.path == "/api/health":
            self._json(200, build_health_payload())
            return
        if parsed.path != "/api/records":
            self._send(404, b"Not found.", "text/plain; charset=utf-8")
            return

        query = parse_qs(parsed.query, keep_blank_values=True)
        if (query.get("refresh") or [""])[0] == "1":
            date_from = (query.get("date_from") or [""])[0]
            date_to = (query.get("date_to") or [""])[0]
            try:
                # Validate before calling the provider; only replace the cache on success.
                _validate_range(date_from, date_to)
                fresh = _load_snapshot(date_from, date_to)
            except (ValueError, GroupIBClientError, OSError) as exc:
                self._json(502 if isinstance(exc, GroupIBClientError) else 400,
                           {"status": "error", "message": str(exc)})
                return
            with _snapshot_lock:
                _snapshot = fresh

        try:
            with _snapshot_lock:
                payload = _filtered_payload(query)
        except ValueError as exc:
            self._json(400, {"status": "error", "message": str(exc)})
            return
        self._json(200, payload)

    def do_POST(self) -> None:  # noqa: N802
        self._send(405, b"Method not allowed.", "text/plain; charset=utf-8")

    def log_message(self, format_string: str, *args: object) -> None:
        # Request paths contain filters only; never log response bodies or credentials.
        super().log_message(format_string, *args)


def main() -> int:
    if not INDEX_FILE.is_file():
        raise SystemExit(f"Dashboard entry point not found: {INDEX_FILE}")
    server = ThreadingHTTPServer((HOST, PORT), DashboardHandler)
    print(f"Group-IB dashboard: http://{HOST}:{PORT}")
    print("Bound to loopback only. Click Refresh from Group-IB to load records.")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
