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
        _text(_join(record.threat_actors)) if include_actor else "—",
        format_ph_time(record.date_first_seen),
        format_ph_time(record.date_last_seen),
    ]
    return row


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
) -> Table:
    headers = [
        "#",
        "Account / Email",
        "Domain",
        "Infostealer Family",
        "Source / Collection",
        "Threat Actor",
        "First Seen (PHT)",
        "Last Seen (PHT)",
    ]
    rows = [
        [
            str(index),
            *_record_row(record, include_actor=include_actor),
        ]
        for index, record in enumerate(records, start=1)
    ]
    table = Table(
        [headers, *rows],
        repeatRows=1,
        splitByRow=1,
        colWidths=[22, 135, 88, 108, 112, 78, 100, 100],
        hAlign="LEFT",
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
                ("BACKGROUND", (6, 0), (6, 0), colors.HexColor("#DBEAFE")),
                ("BACKGROUND", (7, 0), (7, 0), colors.HexColor("#DCFCE7")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#172554")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (1, -1), "Helvetica"),
                ("FONTNAME", (2, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 6.6),
                ("LEADING", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ]
        )
    )
    return table


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
    metrics: QuickViewMetrics,
    classifications: Sequence[ClassificationResult],
    records: Sequence[CanonicalGroupIBRecord],
) -> Path:
    """Generate one complete daily PDF from already-classified canonical records."""
    if len(classifications) != len(records):
        raise ValueError("classifications and records must have equal lengths.")

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
        quick_view_story.append(_accounts_table(new_records, include_actor=True))
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
        quick_view_story.append(_accounts_table(historical_records, include_actor=False))
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
                "included in the historical/known population. Sensitive provider "
                "secrets, plaintext passwords and session cookies are excluded.",
                note,
            ),
        ]
    )

    document = _ReportDocument(destination)
    document.build(quick_view_story)
    return destination
