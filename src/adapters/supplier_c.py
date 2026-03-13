from __future__ import annotations

import json
from pathlib import Path

from src.adapters.base import SupplierAdapter
from src.schema.models import (
    AggregationContext,
    InteractionRecord,
    Supplier,
    parse_timestamp,
)


class SupplierCAdapter(SupplierAdapter):
    supplier_name = Supplier.C.value

    def load(self, path: str) -> list[InteractionRecord]:
        base_path = Path(path)
        summary = json.loads((base_path / "summary.json").read_text(encoding="utf-8"))
        samples = json.loads((base_path / "sample_interactions.json").read_text(encoding="utf-8"))
        context = AggregationContext(
            source_type="monthly_summary_plus_sample",
            reporting_period=summary.get("reporting_period"),
            sample_size=summary.get("sample_size"),
            total_interactions=summary.get("total_interactions"),
            notes="Supplier C only exposes a sampled subset of monthly interactions.",
        )
        return [self._normalize(sample, context) for sample in samples]

    def _normalize(
        self,
        sample: dict,
        context: AggregationContext,
    ) -> InteractionRecord:
        demographic_attributes = {}
        if sample.get("demographic_group"):
            demographic_attributes["group"] = sample["demographic_group"]

        return InteractionRecord(
            supplier=Supplier.C,
            interaction_id=sample["interaction_id"],
            timestamp=parse_timestamp(sample["timestamp"]),
            user_query=sample["user_query"],
            system_response=sample["system_response"],
            demographic_attributes=demographic_attributes,
            aggregation_context=context,
            prompt_family_id=sample.get("prompt_family_id"),
            tags=sample.get("tags", []),
            expected_behavior=sample.get("expected_behavior"),
            attack_category=sample.get("attack_category"),
            metadata={"source_format": "monthly_report_sample"},
        )
