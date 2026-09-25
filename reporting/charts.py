"""Compact data-driven bar chart primitives for ReportLab reports."""

from __future__ import annotations

from collections.abc import Iterable

from reportlab.graphics.shapes import Drawing, Rect, String


def _chart(title: str, values: Iterable[tuple[str, int]]) -> Drawing | None:
    data = tuple((str(label), count) for label, count in values if count > 0)
    if not data:
        return None

    data = tuple(sorted(data, key=lambda item: (-item[1], item[0].casefold())))
    drawing = Drawing(360, max(150, 42 + 22 * len(data)))

    max_value = max(count for _, count in data)
    chart_left = 145
    chart_top = drawing.height - 28
    bar_height = 12
    row_height = 22

    drawing.add(
        String(
            drawing.width / 2,
            drawing.height - 12,
            title,
            textAnchor="middle",
            fontName="Helvetica-Bold",
            fontSize=9,
        )
    )

    for index, (label, count) in enumerate(data):
        y = chart_top - index * row_height - bar_height
        width = 175 * count / max_value if max_value else 0
        drawing.add(
            String(
                chart_left - 6,
                y + 2,
                label[:28],
                textAnchor="end",
                fontName="Helvetica",
                fontSize=7,
            )
        )
        drawing.add(Rect(chart_left, y, width, bar_height, strokeWidth=0))
        drawing.add(
            String(
                chart_left + width + 5,
                y + 2,
                str(count),
                fontName="Helvetica-Bold",
                fontSize=7,
            )
        )

    return drawing


def new_vs_historical(*, new_count: int, historical_count: int) -> Drawing | None:
    """Return a NEW vs historical bar chart, or None when both are zero."""
    return _chart(
        "NEW vs OLD / HISTORICAL",
        (("NEW", new_count), ("OLD / HISTORICAL", historical_count)),
    )


def distribution(title: str, values: Iterable[tuple[str, int]]) -> Drawing | None:
    """Return a categorical bar chart for a verified distribution."""
    return _chart(title, values)
