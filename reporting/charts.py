"""Professional, data-driven bar chart panels for ReportLab reports."""

from __future__ import annotations

from collections.abc import Iterable

from reportlab.graphics.shapes import Drawing, Line, RoundRect, String
from reportlab.lib import colors


MAX_CATEGORIES = 18
PANEL_HEIGHT = 350
BAR_PALETTE = (
    colors.HexColor("#2F80ED"),
    colors.HexColor("#EB5757"),
    colors.HexColor("#27AE60"),
    colors.HexColor("#F2994A"),
    colors.HexColor("#9B51E0"),
    colors.HexColor("#2D9CDB"),
    colors.HexColor("#E83E8C"),
    colors.HexColor("#F2C94C"),
)


def _data(values: Iterable[tuple[str, int]]) -> tuple[tuple[str, int], ...]:
    return tuple(
        sorted(
            ((str(label), count) for label, count in values if count > 0),
            key=lambda item: (-item[1], item[0].casefold()),
        )[:MAX_CATEGORIES]
    )


def _bar_section(
    drawing: Drawing,
    *,
    x: float,
    y: float,
    width: float,
    height: float,
    title: str,
    values: Iterable[tuple[str, int]],
) -> None:
    data = _data(values)
    drawing.add(
        String(
            x + width / 2,
            y + height - 20,
            title,
            textAnchor="middle",
            fontName="Helvetica-Bold",
            fontSize=9,
            fillColor=colors.HexColor("#172554"),
        )
    )
    if not data:
        drawing.add(
            String(
                x + width / 2,
                y + height / 2,
                "No verified data",
                textAnchor="middle",
                fontName="Helvetica",
                fontSize=8,
                fillColor=colors.HexColor("#64748B"),
            )
        )
        return

    max_value = max(count for _, count in data)
    row_height = min(17, (height - 48) / max(len(data), 1))
    bar_height = max(7, row_height - 5)
    label_x = x + 104
    bar_x = label_x + 6
    bar_width = max(55, width - (label_x - x) - 46)
    chart_top = y + height - 40

    for index, (label, count) in enumerate(data):
        row_y = chart_top - (index + 1) * row_height
        color = BAR_PALETTE[index % len(BAR_PALETTE)]
        drawing.add(
            String(
                label_x,
                row_y + 3,
                label[:24],
                textAnchor="end",
                fontName="Helvetica",
                fontSize=6.8,
                fillColor=colors.HexColor("#1E293B"),
            )
        )
        width_value = bar_width * count / max_value if max_value else 0
        drawing.add(
            RoundRect(
                bar_x,
                row_y,
                width_value,
                bar_height,
                radius=2,
                fillColor=color,
                strokeWidth=0,
            )
        )
        drawing.add(
            String(
                bar_x + width_value + 5,
                row_y + 3,
                str(count),
                fontName="Helvetica-Bold",
                fontSize=6.8,
                fillColor=colors.HexColor("#0F172A"),
            )
        )


def paired_distribution_panel(
    left_title: str,
    left_values: Iterable[tuple[str, int]],
    right_title: str,
    right_values: Iterable[tuple[str, int]],
) -> Drawing:
    """Return one boxed panel containing two compact categorical bar charts."""
    drawing = Drawing(370, PANEL_HEIGHT)
    drawing.add(
        RoundRect(
            2,
            2,
            366,
            PANEL_HEIGHT - 4,
            radius=8,
            fillColor=colors.white,
            strokeColor=colors.HexColor("#93C5FD"),
            strokeWidth=0.8,
        )
    )
    drawing.add(
        Line(
            185,
            25,
            185,
            PANEL_HEIGHT - 25,
            strokeColor=colors.HexColor("#CBD5E1"),
            strokeWidth=0.6,
        )
    )
    _bar_section(
        drawing,
        x=8,
        y=8,
        width=171,
        height=PANEL_HEIGHT - 16,
        title=left_title,
        values=left_values,
    )
    _bar_section(
        drawing,
        x=191,
        y=8,
        width=171,
        height=PANEL_HEIGHT - 16,
        title=right_title,
        values=right_values,
    )
    return drawing


def distribution_panel(
    title: str,
    values: Iterable[tuple[str, int]],
) -> Drawing:
    """Return one boxed categorical bar-chart panel."""
    drawing = Drawing(370, PANEL_HEIGHT)
    drawing.add(
        RoundRect(
            2,
            2,
            366,
            PANEL_HEIGHT - 4,
            radius=8,
            fillColor=colors.white,
            strokeColor=colors.HexColor("#86EFAC"),
            strokeWidth=0.8,
        )
    )
    _bar_section(
        drawing,
        x=12,
        y=8,
        width=346,
        height=PANEL_HEIGHT - 16,
        title=title,
        values=values,
    )
    return drawing


def new_vs_historical(*, new_count: int, historical_count: int) -> Drawing | None:
    """Return the legacy NEW-vs-historical chart for compatibility."""
    data = _data((("NEW", new_count), ("OLD / HISTORICAL", historical_count)))
    if not data:
        return None
    drawing = Drawing(360, 150)
    drawing.add(
        RoundRect(
            2,
            2,
            356,
            146,
            radius=8,
            fillColor=colors.white,
            strokeColor=colors.HexColor("#CBD5E1"),
            strokeWidth=0.8,
        )
    )
    _bar_section(
        drawing,
        x=8,
        y=8,
        width=344,
        height=134,
        title="NEW vs OLD / HISTORICAL",
        values=data,
    )
    return drawing


def distribution(title: str, values: Iterable[tuple[str, int]]) -> Drawing | None:
    """Return a standalone boxed distribution chart for compatibility."""
    if not _data(values):
        return None
    return distribution_panel(title, values)
