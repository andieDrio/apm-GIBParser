"""Deterministic, evidence-based daily threat assessment for the PDF report.

This module intentionally avoids LLM-generated prose and arbitrary numeric scores.
Every statement is derived from normalized report metrics and the durable daily
baseline when one exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from groupib.normalizer import CanonicalGroupIBRecord
from reporting.summary import QuickViewMetrics


@dataclass(frozen=True, slots=True)
class AssessmentResult:
    """Auditable assessment generated from one completed daily run."""

    activity_level: str
    confidence: str
    facts: tuple[str, ...]
    observations: tuple[str, ...]
    assessment: str
    analyst_attention: tuple[str, ...]
    basis: tuple[tuple[str, str], ...]


def _source_link_count(records: Sequence[CanonicalGroupIBRecord]) -> int:
    return sum(bool(record.source_links) for record in records)


def build_assessment(
    metrics: QuickViewMetrics,
    records: Sequence[CanonicalGroupIBRecord],
) -> AssessmentResult:
    """Build a deterministic assessment from actual report evidence only."""
    if metrics.total_records != len(records):
        raise ValueError("metrics.total_records must equal len(records).")

    source_link_count = _source_link_count(records)
    source_link_ratio = (
        source_link_count / metrics.total_records if metrics.total_records else 1.0
    )
    family_count = len(metrics.stealer_family_counts)
    domain_count = len(metrics.target_domain_counts)
    new_domain_count = len(metrics.newly_affected_domain_counts)

    if metrics.new_compromises == 0:
        activity_level = "NO NEW ACTIVITY"
    elif new_domain_count > 0 or metrics.newly_detected_7d > metrics.new_compromises:
        activity_level = "ELEVATED ACTIVITY"
    else:
        activity_level = "OBSERVED ACTIVITY"

    if metrics.previous_run is None:
        confidence = "LIMITED"
    elif source_link_ratio >= 0.80 and metrics.total_records > 0:
        confidence = "HIGH"
    else:
        confidence = "MODERATE"

    facts = (
        f"{metrics.new_compromises} NEW compromise record(s) classified in this run.",
        f"{new_domain_count} newly affected domain(s) versus the previous successful run."
        if metrics.previous_run is not None
        else "No previous successful baseline is available for domain-change comparison.",
        f"{metrics.newly_detected_7d} record(s) have a Group-IB detection date within the seven-day window.",
        f"{metrics.new_compromise_7d_total} NEW compromise record(s) fall within the seven-day compromise timeline.",
    )

    observations: list[str] = []
    if domain_count:
        observations.append(
            f"{domain_count} affected domain(s) are represented in the retrieved dataset."
        )
    if family_count:
        observations.append(
            f"{family_count} distinct infostealer family/families are represented."
        )
    observations.append(
        f"Source links are present for {source_link_count}/{metrics.total_records} "
        "normalized record(s)."
    )
    if metrics.previous_run is not None:
        observations.append(
            f"NEW compromise count changed by {metrics.delta_new_compromises:+d} "
            "versus the previous successful run."
        )
    else:
        observations.append(
            "Daily-change comparison is unavailable because this is the first "
            "successful baseline."
        )

    assessment_parts: list[str] = []
    if metrics.new_compromises:
        assessment_parts.append(
            f"The run identified {metrics.new_compromises} newly observed compromise "
            "record(s) under the configured seven-day NEW policy."
        )
    else:
        assessment_parts.append(
            "No compromise records met the configured NEW classification policy in "
            "this run."
        )

    if new_domain_count:
        assessment_parts.append(
            f"{new_domain_count} domain(s) are newly affected compared with the "
            "previous successful run."
        )
    if metrics.newly_detected_7d:
        assessment_parts.append(
            f"{metrics.newly_detected_7d} record(s) were detected by Group-IB within "
            "the last seven days."
        )
    assessment_parts.append(
        "These findings describe observed Group-IB intelligence and do not establish "
        "that a victim environment is currently compromised."
    )

    attention: list[str] = []
    if new_domain_count:
        attention.append("Validate newly affected domains and their associated accounts.")
    if metrics.new_compromises:
        attention.append("Review newly classified credentials and preserve relevant source evidence.")
    if metrics.newly_detected_7d:
        attention.append("Review recent Group-IB detections for recurrence or clustering.")
    if source_link_count < metrics.total_records:
        attention.append("Review records without source links before evidence collection.")
    attention.append("Monitor the next successful daily run for recurrence and change.")
    if not attention:
        attention.append("Continue daily monitoring and compare against the next successful baseline.")

    basis = (
        ("NEW compromises", str(metrics.new_compromises)),
        ("New affected domains", str(new_domain_count)),
        ("Detected in 7d", str(metrics.newly_detected_7d)),
        ("7d NEW total", str(metrics.new_compromise_7d_total)),
        ("Affected domains", str(domain_count)),
        ("Infostealer families", str(family_count)),
        ("Source links", f"{source_link_count}/{metrics.total_records}"),
        ("Previous baseline", "AVAILABLE" if metrics.previous_run is not None else "NOT AVAILABLE"),
    )

    return AssessmentResult(
        activity_level=activity_level,
        confidence=confidence,
        facts=facts,
        observations=tuple(observations),
        assessment=" ".join(assessment_parts),
        analyst_attention=tuple(attention),
        basis=basis,
    )
