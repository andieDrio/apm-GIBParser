"""ReportLab PDF rendering for the focused Group-IB daily report."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Sequence

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from groupib.normalizer import CanonicalGroupIBRecord
from reporting.charts import distribution, new_vs_historical
from reporting.summary import QuickViewMetrics
from storage.classifier import NEW, ClassificationResult, OLD, REPEAT, RESEEN


def mask_account(value: str | None) -> str:
    """Mask an account/email without exposing the full identifier."""
    if not value:
        return "—"
    if "@" in value:
        local, domain = value.split("@", 1)
        if not local:
            return f"***@{domain}"
        if len(local) == 1:
            masked_local = "*"
        elif len(local) == 2:
            masked_local = f"{local[0]}*"
        else:
            masked_local = f"{local[0]}{'*' * max(1, len(local) - 2)}{local[-1]}"
        return f"{masked_local}@{domain}"
    if len(value) <= 2:
        return "*" * len(value)
    return f"{value[0]}{'*' * max(1, len(value) - 2)}{value[-1]}"


def _text(value: str | None) -> str:
    return value if value else "—"


def _join(values: Sequence[str]) -> str:
    return ", ".join(values) if values else "—"


def _record_row(record: CanonicalGroupIBRecord, *, include_actor: bool) -> list[str]:
    row = [
        mask_account(record.account),
        _text(record.domain or record.service_domain),
        _text(record.date_first_seen),
        _text(record.date_last_seen),
        _join(record.stealer_families),
        _join(record.source_types),
    ]
    if include_actor:
        row.append(_join(record.threat_actors))
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
        super().__init__(str(filename), pagesize=A4, **kwargs)
        frame = Frame(
            15 * mm,
            15 * mm,
            A4[0] - 30 * mm,
            A4[1] - 30 * mm,
            id="normal",
        )
        self.addPageTemplates(
            PageTemplate(id="daily-report", frames=[frame], onPage=self._footer)
        )

    @staticmethod
    def _footer(canvas: object, doc: object) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.drawRightString(
            A4[0] - 15 * mm,
            9 * mm,
            f"Page {doc.page}",
        )
        canvas.restoreState()


def _table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    *,
    font_size: int = 7,
) -> Table:
    data = [list(headers), *[list(row) for row in rows]]
    table = Table(data, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E9ECEF")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), font_size),
                ("LEADING", (0, 0), (-1, -1), font_size + 2),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#B8B8B8")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return table


def _metric_table(metrics: QuickViewMetrics) -> Table:
    data = [
        ["Metric", "Count"],
        ["Total Records", str(metrics.total_records)],
        ["NEW Compromises", str(metrics.new_compromises)],
        ["OLD / HISTORICAL", str(metrics.old_historical)],
        ["Infostealer Records", str(metrics.infostealer_records)],
    ]
    return _table(data[0], data[1:], font_size=9)


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

    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        spaceAfter=4,
    )
    subtitle = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=9,
        textColor=colors.HexColor("#555555"),
        spaceAfter=12,
    )
    section = ParagraphStyle(
        "Section",
        parent=styles["Heading2"],
        fontSize=12,
        leading=15,
        spaceBefore=8,
        spaceAfter=6,
    )
    note = ParagraphStyle(
        "Note",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#555555"),
    )

    new_records = _classified_rows(classifications, records, {NEW})
    historical_records = _classified_rows(
        classifications,
        records,
        {OLD, RESEEN, REPEAT},
    )

    story: list[object] = [
        Paragraph("Group-IB Daily Threat Intelligence Report", title),
        Paragraph(f"Report Date: {report_date}", subtitle),
        _metric_table(metrics),
        Spacer(1, 8),
    ]

    charts = []
    primary = new_vs_historical(
        new_count=metrics.new_compromises,
        historical_count=metrics.old_historical,
    )
    if primary is not None:
        charts.append(primary)

    for chart_title, values in (
        ("Infostealer Families", metrics.stealer_family_counts),
        ("Sources / Collection", metrics.source_counts),
        ("Target Domains", metrics.target_domain_counts),
    ):
        chart = distribution(chart_title, values)
        if chart is not None:
            charts.append(chart)

    if charts:
        story.append(Table([charts[i:i + 2] for i in range(0, len(charts), 2)]))
        story.append(Spacer(1, 6))

    story.extend(
        [
            Paragraph(
                "Classification is based on durable local history and the verified "
                "Group-IB provider timeline. RESEEN/RECYCLED and REPEAT records are "
                "included in the historical/known population.",
                note,
            ),
            PageBreak(),
            Paragraph("NEW Compromises", section),
        ]
    )

    if new_records:
        story.append(
            _table(
                ["Account", "Domain", "First Seen", "Last Seen", "Stealer", "Source", "Threat Actor"],
                [_record_row(record, include_actor=True) for record in new_records],
            )
        )
    else:
        story.append(Paragraph("No NEW compromises were classified for this run.", note))

    story.extend([Spacer(1, 12), Paragraph("OLD / HISTORICAL", section)])

    if historical_records:
        story.append(
            _table(
                ["Account", "Domain", "First Seen", "Last Seen", "Stealer", "Source"],
                [_record_row(record, include_actor=False) for record in historical_records],
            )
        )
    else:
        story.append(Paragraph("No OLD / HISTORICAL records were returned.", note))

    story.append(
        Paragraph(
            "Sensitive provider secrets, plaintext passwords and session cookies are "
            "excluded from this report.",
            note,
        )
    )

    document = _ReportDocument(destination)
    document.build(story)
    return destination
