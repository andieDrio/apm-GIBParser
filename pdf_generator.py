"""ReportLab reporting boundary.

This module accepts already-prepared report data and has no dependency on
PyQt6 or the Group-IB HTTP client.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


@dataclass(frozen=True, slots=True)
class ThreatReport:
    title: str = "Group-IB Threat Intelligence Report"
    metrics: dict[str, int] = field(default_factory=dict)
    accounts: Sequence[Sequence[Any]] = field(default_factory=tuple)
    stealers: Sequence[Sequence[Any]] = field(default_factory=tuple)


class PDFReportGenerator:
    """Generate a deterministic PDF from a report data model."""

    def generate(self, report: ThreatReport, output_path: str | Path) -> Path:
        path = Path(output_path).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)

        styles = getSampleStyleSheet()
        document = SimpleDocTemplate(
            str(path),
            pagesize=A4,
            rightMargin=15 * mm,
            leftMargin=15 * mm,
            topMargin=15 * mm,
            bottomMargin=15 * mm,
            title=report.title,
        )

        story: list[Any] = [
            Paragraph(report.title, styles["Title"]),
            Spacer(1, 6 * mm),
        ]

        if report.metrics:
            metric_rows = [[key, str(value)] for key, value in report.metrics.items()]
            metric_table = Table(metric_rows, colWidths=[80 * mm, 40 * mm])
            metric_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                        ("PADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            story.extend([Paragraph("Executive Metrics", styles["Heading2"]), metric_table])

        self._append_data_table(story, styles, "Compromised Accounts", report.accounts)
        self._append_data_table(story, styles, "Infostealer Telemetry", report.stealers)

        document.build(story)
        return path

    @staticmethod
    def _append_data_table(story: list[Any], styles: Any, heading: str, rows: Sequence[Sequence[Any]]) -> None:
        if not rows:
            return
        story.extend([Spacer(1, 5 * mm), Paragraph(heading, styles["Heading2"])])
        table = Table([[str(cell) for cell in row] for row in rows], repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(table)
