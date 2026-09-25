"""Small data-driven donut chart primitives for ReportLab reports."""

from __future__ import annotations

from collections.abc import Iterable

from reportlab.graphics.charts.doughnut import DoughnutChart
from reportlab.graphics.shapes import Drawing, String


def _chart(title: str, values: Iterable[tuple[str, int]]) -> Drawing | None:
    data = tuple((label, count) for label, count in values if count > 0)
    if not data:
        return None

    drawing = Drawing(260, 190)
    chart = DoughnutChart()
    chart.x = 55
    chart.y = 25
    chart.width = 150
    chart.height = 150
    chart.data = [[count for _, count in data]]
    chart.labels = [label for label, _ in data]
    chart.slices.strokeWidth = 0.5
    chart.slices.fontName = "Helvetica"
    chart.slices.fontSize = 8

    drawing.add(chart)
    drawing.add(
        String(
            130,
            175,
            title,
            textAnchor="middle",
            fontName="Helvetica-Bold",
            fontSize=10,
        )
    )
    return drawing


def new_vs_historical(*, new_count: int, historical_count: int) -> Drawing | None:
    """Return the NEW vs historical donut, or None when both are zero."""
    return _chart(
        "NEW vs OLD / HISTORICAL",
        (("NEW", new_count), ("OLD / HISTORICAL", historical_count)),
    )


def distribution(title: str, values: Iterable[tuple[str, int]]) -> Drawing | None:
    """Return a donut for a verified categorical distribution."""
    return _chart(title, values)
