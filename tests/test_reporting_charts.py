"""Tests for Phase 5 donut chart generation."""

from __future__ import annotations

import unittest

from reporting.charts import distribution, new_vs_historical, distribution_panel, paired_distribution_panel


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

    def test_professional_panels_are_bounded(self) -> None:
        paired = paired_distribution_panel(
            "Infostealer Families",
            tuple((f"family-{index}", index + 1) for index in range(30)),
            "Sources / Collection",
            (("source", 10),),
        )
        domains = distribution_panel(
            "Target Domains",
            tuple((f"domain-{index}.example", index + 1) for index in range(30)),
        )
        self.assertEqual(paired.width, 370)
        self.assertEqual(domains.width, 370)
        self.assertEqual(paired.height, 350)
        self.assertEqual(domains.height, 350)

    def test_empty_distribution_is_omitted(self) -> None:
        self.assertIsNone(distribution("No Data", ()))
        self.assertIsNone(new_vs_historical(new_count=0, historical_count=0))


if __name__ == "__main__":
    unittest.main()
