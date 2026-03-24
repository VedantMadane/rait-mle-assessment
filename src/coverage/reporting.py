from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from src.schema.models import CoverageProfile, InteractionRecord


def field_present(record: InteractionRecord, field_name: str) -> bool:
    value: Any = getattr(record, field_name)
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, dict | list):
        return bool(value)
    return True


def build_coverage_profile(
    records: Iterable[InteractionRecord],
    required_fields: list[str],
    eligibility_predicate: Callable[[InteractionRecord], bool] | None = None,
    notes: list[str] | None = None,
) -> CoverageProfile:
    record_list = list(records)
    eligible = record_list
    if eligibility_predicate is not None:
        eligible = [record for record in record_list if eligibility_predicate(record)]

    scored = [record for record in eligible if all(field_present(record, field_name) for field_name in required_fields)]

    missing_requirements = [
        field_name
        for field_name in required_fields
        if any(not field_present(record, field_name) for record in eligible)
    ]

    return CoverageProfile(
        required_fields=required_fields,
        eligible_records=len(eligible),
        scored_records=len(scored),
        missing_requirements=missing_requirements,
        notes=notes or [],
    )


def summarize_supplier_data_availability(records: list[InteractionRecord]) -> dict[str, Any]:
    if not records:
        return {
            "record_count": 0,
            "sample_size": 0,
            "total_interactions": None,
            "sample_ratio": None,
            "coverage_note": "No records were ingested.",
        }

    sample_size = len(records)
    total_interactions = None
    context = records[0].aggregation_context
    if context and context.total_interactions:
        total_interactions = context.total_interactions

    sample_ratio = None
    coverage_note = "Full record export available for this synthetic supplier dataset."
    if total_interactions:
        sample_ratio = round(sample_size / total_interactions, 6)
        coverage_note = (
            "Only a sampled subset of interactions is available, so metric results apply to the "
            "sample rather than the full supplier population."
        )

    return {
        "record_count": sample_size,
        "sample_size": sample_size,
        "total_interactions": total_interactions,
        "sample_ratio": sample_ratio,
        "coverage_note": coverage_note,
    }
