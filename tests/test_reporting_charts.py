"""Tests for Phase 5 donut chart generation."""

from __future__ import annotations

import unittest

from reporting.charts import distribution, new_vs_historical


class ChartTests(unittest.TestCase):
    def test_new_vs_historical_returns_chart_for_nonzero_data(self) -> None:
        chart = new_vs_historical(new_count=3, historical_count=7)
        self.assertIsNotNone(chart)
        self.assertGreater(len(chart.contents), 0)

    def test_distribution_height_is_bounded_for_many_categories(self) -> None:
        chart = distribution(
            "Sources",
            tuple((f"source-{index}", index + 1) for index in range(30)),
        )
        self.assertIsNotNone(chart)
        self.assertLessEqual(chart.height, 450)

    def test_empty_distribution_is_omitted(self) -> None:
        self.assertIsNone(distribution("No Data", ()))
        self.assertIsNone(new_vs_historical(new_count=0, historical_count=0))


if __name__ == "__main__":
    unittest.main()
