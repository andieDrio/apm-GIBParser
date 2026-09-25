"""Professional ReportLab PDF rendering for the Group-IB daily report."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from groupib.normalizer import CanonicalGroupIBRecord
from reporting.charts import distribution_panel, paired_distribution_panel
from reporting.summary import QuickViewMetrics
from storage.classifier import ClassificationResult, NEW, OLD, REPEAT, RESEEN

PHILIPPINES_TZ = ZoneInfo("Asia/Manila")
CHIP_COLORS = (
    "#DBEAFE",
    "#FEE2E2",
    "#DCFCE7",
    "#FFEDD5",
    "#F3E8FF",
    "#CFFAFE",
    "#FCE7F3",
    "#FEF3C7",
)
CHIP_TEXT_COLORS = (
    "#1D4ED8",
    "#B91C1C",
    "#166534",
    "#C2410C",
    "#7E22CE",
    "#0E7490",
    "#BE185D",
    "#A16207",
)


def mask_account(value: str | None) -> str:
    """Return the original account/email for report correlation."""
    return value if value else "—"


def _text(value: str | None) -> str:
    return value if value else "—"


def _join(values: Sequence[str]) -> str:
    return ", ".join(values) if values else "—"


def format_ph_datetime(value: datetime) -> str:
    """Format a timezone-aware timestamp in Philippines Time."""
    if value.tzinfo is None:
        raise ValueError("Timestamp must be timezone-aware.")
    return value.astimezone(PHILIPPINES_TZ).strftime("%b %d, %Y %I:%M %p")


def format_ph_time(value: str | None) -> str:
    """Convert a provider timestamp to readable Philippines time (UTC+8)."""
    if not value:
        return "—"
    normalized = value.strip()
    if not normalized:
        return "—"
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError:
        return normalized
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(PHILIPPINES_TZ).strftime("%b %d, %Y %I:%M %p")


def _chip(value: str | None, *, index: int = 0) -> Paragraph:
    label = _text(value)
    palette_index = index % len(CHIP_COLORS)
    style = ParagraphStyle(
        f"Chip{palette_index}",
        fontName="Helvetica-Bold",
        fontSize=6.5,
        leading=8,
        textColor=colors.HexColor(CHIP_TEXT_COLORS[palette_index]),
        backColor=colors.HexColor(CHIP_COLORS[palette_index]),
        borderColor=colors.HexColor(CHIP_COLORS[palette_index]),
        borderWidth=0.4,
        borderPadding=2,
        spaceAfter=0,
        spaceBefore=0,
    )
    return Paragraph(escape(label), style)


def _stable_chip_index(value: str | None) -> int:
    if not value:
        return 0
    return sum(ord(character) for character in value.casefold()) % len(CHIP_COLORS)


def _record_row(
    record: CanonicalGroupIBRecord,
    *,
    include_actor: bool,
) -> list[object]:
    stealer = record.stealer_families[0] if record.stealer_families else None
    source = record.source_types[0] if record.source_types else None
    row: list[object] = [
        mask_account(record.account),
        _text(record.domain or record.service_domain),
        _chip(stealer, index=_stable_chip_index(stealer)),
        _chip(source, index=_stable_chip_index(source)),
        format_ph_time(record.date_first_compromised),
        _text(_join(record.threat_actors)) if include_actor else "—",
        format_ph_time(record.date_first_seen),
        format_ph_time(record.date_last_seen),
    ]
    return row


def _record_details(record: CanonicalGroupIBRecord) -> Table:
    """Render one clear operational-detail block for a compromise record."""
    label_style = ParagraphStyle(
        "DetailLabel",
        fontName="Helvetica-Bold",
        fontSize=6.5,
        leading=8,
        textColor=colors.HexColor("#475569"),
    )
    value_style = ParagraphStyle(
        "DetailValue",
        fontName="Helvetica",
        fontSize=6.5,
        leading=8,
        textColor=colors.HexColor("#0F172A"),
    )

    def cell(label: str, value: str) -> list[object]:
        return [
            Paragraph(escape(label), label_style),
            Paragraph(escape(value), value_style),
        ]

    rows = [
        cell("Login", _text(record.username or record.account))
        + cell("Password", _text(record.password)),
        cell("Login URL", _text(record.login_url))
        + cell("Victim's IP", _join(record.victim_ips)),
        cell("Compromised", format_ph_time(record.date_first_compromised))
        + cell("Provider", _join(record.victim_providers)),
        cell("Country", _join(record.victim_countries))
        + cell("City", _join(record.victim_cities)),
        cell("Source link", _join(record.source_links))
        + cell("Source type", _join(record.source_types)),
        cell("Source", _join(record.source_names))
        + cell("Threat Actor", _join(record.threat_actors)),
    ]
    table = Table(rows, colWidths=[58, 300, 58, 300], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 0.45, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return table


def _classified_rows(
    classifications: Sequence[ClassificationResult],
    records: Sequence[CanonicalGroupIBRecord],
    wanted: set[str],
) -> list[CanonicalGroupIBRecord]:
    return [
        record
        for result, record in zip(classifications, records)
        if result.classification in wanted
    ]


class _ReportDocument(BaseDocTemplate):
    def __init__(self, filename: str | Path, **kwargs: object) -> None:
        super().__init__(str(filename), pagesize=landscape(A4), **kwargs)
        frame = Frame(
            15 * mm,
            15 * mm,
            landscape(A4)[0] - 30 * mm,
            landscape(A4)[1] - 30 * mm,
            id="normal",
        )
        self.addPageTemplates(
            PageTemplate(id="daily-report", frames=[frame], onPage=self._footer)
        )

    @staticmethod
    def _footer(canvas: object, doc: object) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#64748B"))
        canvas.drawString(
            15 * mm,
            9 * mm,
            "Group-IB Daily Threat Intelligence • Asia/Manila (PHT)",
        )
        canvas.drawRightString(
            landscape(A4)[0] - 15 * mm,
            9 * mm,
            f"Page {doc.page}",
        )
        canvas.restoreState()


def _header_styles() -> tuple[ParagraphStyle, ParagraphStyle, ParagraphStyle, ParagraphStyle]:
    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=2,
    )
    subtitle = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#475569"),
        spaceAfter=8,
    )
    section = ParagraphStyle(
        "Section",
        parent=styles["Heading2"],
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#172554"),
        spaceBefore=4,
        spaceAfter=6,
    )
    note = ParagraphStyle(
        "Note",
        parent=styles["Normal"],
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#64748B"),
    )
    return title, subtitle, section, note


def _accounts_table(
    records: Sequence[CanonicalGroupIBRecord],
    *,
    include_actor: bool,
) -> list[object]:
    """Render one compact, scan-first row per compromised account."""
    header_style = ParagraphStyle(
        "ScanHeader",
        fontName="Helvetica-Bold",
        fontSize=6.2,
        leading=7,
        textColor=colors.HexColor("#F8FAFC"),
    )
    value_style = ParagraphStyle(
        "ScanValue",
        fontName="Helvetica",
        fontSize=5.9,
        leading=7,
        textColor=colors.HexColor("#0F172A"),
    )
    password_style = ParagraphStyle(
        "ScanPassword",
        fontName="Helvetica",
        fontSize=5.7,
        leading=6.8,
        textColor=colors.HexColor("#7F1D1D"),
    )

    def value(text: str, *, password: bool = False) -> Paragraph:
        style = password_style if password else value_style
        return Paragraph(escape(text), style)

    headers = [
        "Compromised Date",
        "First Seen",
        "Last Seen",
        "Victim's Domain",
        "Victim's Login",
        "Password",
        "Victim IP",
        "Source Type",
        "Source",
        "Malware",
        "Threat Actor",
    ]
    # Keep the full table inside the 15 mm A4-landscape frame (735 pt).
    widths = [62, 60, 60, 72, 82, 72, 58, 68, 68, 65, 68]

    rows: list[list[object]] = [[
        Paragraph(escape(header), header_style) for header in headers
    ]]

    for record in records:
        stealer = _join(record.stealer_families)
        source_type = _join(record.source_types)
        source = _join(record.source_names)
        source_links = _join(record.source_links)
        if source_links and source_links != "—":
            source = f"{source}\\n{source_links}" if source != "—" else source_links

        rows.append(
            [
                value(format_ph_time(record.date_first_compromised)),
                value(format_ph_time(record.date_first_seen)),
                value(format_ph_time(record.date_last_seen)),
                value(_text(record.domain or record.service_domain)),
                value(_text(record.username or record.account)),
                value(_text(record.password), password=True),
                value(_join(record.victim_ips)),
                value(source_type),
                value(source),
                value(stealer),
                value(_join(record.threat_actors) if include_actor else "—"),
            ]
        )

    table = Table(
        rows,
        colWidths=widths,
        repeatRows=1,
        hAlign="LEFT",
        splitByRow=1,
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#F8FAFC")),
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("BACKGROUND", (0, 1), (1, -1), colors.HexColor("#F8FAFC")),
                ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#FFFBEB")),
                ("BACKGROUND", (1, 1), (1, -1), colors.HexColor("#EFF6FF")),
                ("BACKGROUND", (2, 1), (2, -1), colors.HexColor("#F0FDF4")),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return [table, Spacer(1, 10)]


def _section_banner(title: str, *, background: str, border: str) -> Table:
    style = ParagraphStyle(
        f"Banner-{title}",
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#172554"),
    )
    table = Table([[Paragraph(escape(title), style)]], colWidths=[735])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(background)),
                ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor(border)),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def generate_daily_report(
    output_path: str | Path,
    *,
    report_date: str,
    window_start: datetime,
    window_end: datetime,
    metrics: QuickViewMetrics,
    classifications: Sequence[ClassificationResult],
    records: Sequence[CanonicalGroupIBRecord],
) -> Path:
    """Generate one complete daily PDF from already-classified canonical records."""
    if len(classifications) != len(records):
        raise ValueError("classifications and records must have equal lengths.")
    if window_start.tzinfo is None or window_end.tzinfo is None:
        raise ValueError("Report window timestamps must be timezone-aware.")
    if window_end <= window_start:
        raise ValueError("Report window end must be after start.")

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    title, subtitle, section, note = _header_styles()

    new_records = _classified_rows(classifications, records, {NEW})
    historical_records = _classified_rows(
        classifications,
        records,
        {OLD, RESEEN, REPEAT},
    )

    quick_view_story: list[object] = [
        Paragraph("Group-IB Daily Threat Intelligence Report", title),
        Paragraph(
            f"Report Date: {escape(report_date)} &nbsp;•&nbsp; "
            f"Window Start: {escape(format_ph_datetime(window_start))} &nbsp;•&nbsp; "
            f"Window End: {escape(format_ph_datetime(window_end))} &nbsp;•&nbsp; "
            "Time Zone: Asia/Manila (PHT)",
            subtitle,
        ),
        Table(
            [[
                paired_distribution_panel(
                    "Infostealer Families",
                    metrics.stealer_family_counts,
                    "Sources / Collection",
                    metrics.source_counts,
                ),
                distribution_panel("Target Domains", metrics.target_domain_counts),
            ]],
            colWidths=[370, 370],
            rowHeights=[350],
            hAlign="CENTER",
            style=TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ]
            ),
        ),
        Spacer(1, 8),
        Paragraph(
            "Charts use only verified provider data. Account identifiers are shown in "
            "full for operational correlation. First Seen and Last Seen are displayed "
            "in Philippines Time (PHT, Asia/Manila).",
            note,
        ),
        PageBreak(),
        _section_banner(
            f"Compromised Accounts — NEW ({len(new_records)})",
            background="#E0F2FE",
            border="#7DD3FC",
        ),
        Spacer(1, 6),
    ]

    if new_records:
        quick_view_story.extend(_accounts_table(new_records, include_actor=True))
    else:
        quick_view_story.append(
            Paragraph("No NEW compromises were classified for this run.", note)
        )

    quick_view_story.extend(
        [
            Spacer(1, 12),
            _section_banner(
                f"Compromised Accounts — OLD / HISTORICAL ({len(historical_records)})",
                background="#F1F5F9",
                border="#CBD5E1",
            ),
            Spacer(1, 6),
        ]
    )

    if historical_records:
        quick_view_story.extend(_accounts_table(historical_records, include_actor=False))
    else:
        quick_view_story.append(
            Paragraph("No OLD / HISTORICAL records were returned.", note)
        )

    quick_view_story.extend(
        [
            Spacer(1, 8),
            Paragraph(
                "Classification is based on durable local history and the verified "
                "Group-IB provider timeline. RESEEN/RECYCLED and REPEAT records are "
                "included in the historical/known population. Provider-supplied "
                "login/password fields are included by explicit project-owner request; "
                "API tokens and session cookies are excluded.",
                note,
            ),
        ]
    )

    document = _ReportDocument(destination)
    document.build(quick_view_story)
    return destination
