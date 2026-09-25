"""Small data-driven donut chart primitives for ReportLab reports."""

from __future__ import annotations

from collections.abc import Iterable
from math import tau

from reportlab.graphics.shapes import Circle, Drawing, String, Wedge


def _chart(title: str, values: Iterable[tuple[str, int]]) -> Drawing | None:
    data = tuple((label, count) for label, count in values if count > 0)
    if not data:
        return None

    total = sum(count for _, count in data)
    drawing = Drawing(320, 210)
    center_x = 92
    center_y = 100
    outer_radius = 62
    inner_radius = 35

    start = 90.0
    for index, (label, count) in enumerate(data):
        sweep = 360.0 * count / total
        end = start - sweep
        wedge = Wedge(
            center_x,
            center_y,
            outer_radius,
            end,
            start,
        )
        wedge.strokeWidth = 0.5
        drawing.add(wedge)

        # Keep the label outside the ring; avoid depending on ReportLab's
        # optional doughnut chart implementation, which varies by version.
        mid_angle = (start + end) / 2.0
        radians = mid_angle * tau / 360.0
        label_x = center_x + 82 * __import__("math").cos(radians)
        label_y = center_y + 82 * __import__("math").sin(radians)
        drawing.add(
            String(
                label_x,
                label_y,
                f"{label}: {count}",
                textAnchor="middle",
                fontName="Helvetica",
                fontSize=8,
            )
        )
        start = end

    drawing.add(
        Circle(
            center_x,
            center_y,
            inner_radius,
            fillColor=None,
            strokeWidth=0,
        )
    )
    drawing.add(
        String(
            center_x,
            center_y - 3,
            str(total),
            textAnchor="middle",
            fontName="Helvetica-Bold",
            fontSize=12,
        )
    )
    drawing.add(
        String(
            160,
            190,
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
