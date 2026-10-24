"""Loopback-only local web dashboard for Group-IB account intelligence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit
from zoneinfo import ZoneInfo
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

import csv
import io
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
    normalized = {
        value.strip().casefold()
        for value in (*record.source_types, *record.source_names)
        if value and value.strip()
    }
    if "unique" in normalized:
        return "Unique"
    if "combolist" in normalized or "combo list" in normalized:
        return "Combolist"
    return "Unmapped"


def _classification_matches(filter_value: str, classification: str) -> bool:
    """Match dashboard temporal filters, including the combined Recycled / Old card."""
    normalized_filter = filter_value.strip().casefold()
    normalized_classification = classification.strip().casefold()
    if normalized_filter in ("", "all"):
        return True
    if normalized_filter == "recycled-old":
        return normalized_classification in {
            "rese en/recycled".replace(" ", ""),
            "reseen/recycled",
            "old/historical",
            "repeat",
        }
    return normalized_classification == normalized_filter


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



def _record_view(record: CanonicalGroupIBRecord, result: ClassificationResult) -> dict[str, Any]:
    return {
        "first_seen": record.date_first_seen,
        "last_seen": record.date_last_seen,
        "date_first_compromised": record.date_first_compromised or record.date_last_compromised,
        "date_detected": record.date_detected,
        "date_first_compromised": record.date_first_compromised,
        "date_last_compromised": record.date_last_compromised,
        "date_detected": record.date_detected,
        "domain": record.domain or record.service_domain or "Not provided",
        "login": record.account or record.username or "Not provided",
        "password": record.password or "Not provided",
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
        if not _classification_matches(classification_filter, classification.classification):
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
                      for record in records)
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

    def _attachment(self, body: bytes, content_type: str, filename: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _export_payload(query: dict[str, list[str]]) -> dict[str, Any]:
        """Return all records matching filters, not only the visible page."""
        first = dict(query)
        first["page"] = ["1"]
        first["page_size"] = ["200"]
        payload = _filtered_payload(first)
        all_records = list(payload["records"])
        for page in range(2, payload["total_pages"] + 1):
            next_query = dict(first)
            next_query["page"] = [str(page)]
            all_records.extend(_filtered_payload(next_query)["records"])
        payload["records"] = all_records
        return payload

    @staticmethod
    def _pdf_export(payload: dict[str, Any]) -> bytes:
        """Build a confidential PDF of the current filtered Group-IB records."""
        buffer = io.BytesIO()
        document = SimpleDocTemplate(
            buffer, pagesize=landscape(A4), rightMargin=8 * mm,
            leftMargin=8 * mm, topMargin=9 * mm, bottomMargin=9 * mm,
            title="Group-IB Compromised Accounts Export",
            author="Accounts Intelligence",
        )
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "ExportTitle", parent=styles["Title"], fontSize=15, leading=18,
            textColor=colors.HexColor("#12304A"), alignment=0, spaceAfter=5,
        )
        note_style = ParagraphStyle(
            "ExportNote", parent=styles["Normal"], fontSize=7, leading=9,
            textColor=colors.HexColor("#7F1D1D"), spaceAfter=8,
        )
        cell_style = ParagraphStyle(
            "ExportCell", parent=styles["Normal"], fontSize=5.5, leading=6.5,
            splitLongWords=True, wordWrap="CJK",
        )
        header_style = ParagraphStyle(
            "ExportHeader", parent=cell_style, fontName="Helvetica-Bold",
            textColor=colors.white,
        )
        story = [
            Paragraph("Group-IB Compromised Accounts", title_style),
            Paragraph(
                "CONFIDENTIAL — includes sensitive compromised account identifiers and password values. "
                "Store and share only through approved secure channels.", note_style,
            ),
            Paragraph(escape(
                f"Filter: {payload['filters']['date_from']} to {payload['filters']['date_to']} "
                f"| Domain: {payload['filters']['domain'] or 'All'} "
                f"| Records: {len(payload['records'])}"
            ), styles["Normal"]),
            Spacer(1, 5 * mm),
        ]
        headers = [
            "Compromised date", "First seen", "Last seen", "Victim domain",
            "Email / Login", "Password", "Source type", "Malware",
            "Classification", "Initial assessment",
        ]
        rows = [[Paragraph(escape(value), header_style) for value in headers]]
        for record in payload["records"]:
            values = [
                record.get("date_first_compromised") or "Not provided",
                record.get("first_seen") or "Not provided",
                record.get("last_seen") or "Not provided",
                record.get("domain") or "Not provided",
                record.get("login") or "Not provided",
                record.get("password") or "Not provided",
                ", ".join(record.get("source_types") or []) or "Not provided",
                ", ".join(record.get("malware") or []) or "Not provided",
                record.get("classification") or "UNVERIFIED",
                record.get("classification_reason") or "Not provided",
            ]
            rows.append([Paragraph(escape(str(value)), cell_style) for value in values])
        widths = [49, 49, 49, 65, 70, 64, 55, 55, 57, 87]
        available = landscape(A4)[0] - 16 * mm
        scale = available / sum(widths)
        table = Table(rows, colWidths=[width * scale for width in widths], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#234C70")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F1F5F9")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(table)
        document.build(story)
        return buffer.getvalue()

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
        if parsed.path not in ("/api/records", "/api/export.csv", "/api/export.pdf"):
            self._send(404, b"Not found.", "text/plain; charset=utf-8")
            return

        query = parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path in ("/api/export.csv", "/api/export.pdf"):
            try:
                with _snapshot_lock:
                    payload = self._export_payload(query)
                stamp = datetime.now(PHILIPPINES_TZ).strftime("%Y%m%d_%H%M%S")
                if parsed.path.endswith(".csv"):
                    output = io.StringIO(newline="")
                    writer = csv.writer(output)
                    writer.writerow([
                        "Compromised Date", "First Seen", "Last Seen", "Victim Domain",
                        "Email / Login", "Password", "Source Type", "Malware",
                        "Classification", "Initial Assessment",
                    ])
                    for record in payload["records"]:
                        writer.writerow([
                            record.get("date_first_compromised") or "",
                            record.get("first_seen") or "",
                            record.get("last_seen") or "",
                            record.get("domain") or "",
                            record.get("login") or "",
                            record.get("password") or "",
                            "; ".join(record.get("source_types") or []),
                            "; ".join(record.get("malware") or []),
                            record.get("classification") or "UNVERIFIED",
                            record.get("classification_reason") or "",
                        ])
                    self._attachment(
                        output.getvalue().encode("utf-8-sig"),
                        "text/csv; charset=utf-8",
                        f"groupib_accounts_{stamp}.csv",
                    )
                else:
                    self._attachment(
                        self._pdf_export(payload), "application/pdf",
                        f"groupib_accounts_{stamp}.pdf",
                    )
            except (ValueError, GroupIBClientError, OSError) as exc:
                self._json(400, {"status": "error", "message": str(exc)})
            return

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
    print("Bound to loopback only. Records load automatically when the dashboard opens.")
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
