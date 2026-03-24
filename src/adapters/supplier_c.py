from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.adapters.base import SupplierAdapter
from src.schema.models import Supplier


class SupplierCAdapter(SupplierAdapter):
    supplier_name = Supplier.C.value

    def load(self, path: str) -> list[dict[str, Any]]:
        base_path = Path(path)
        summary = json.loads((base_path / "summary.json").read_text(encoding="utf-8"))
        samples = json.loads((base_path / "sample_interactions.json").read_text(encoding="utf-8"))
        context = {
            "source_type": "monthly_summary_plus_sample",
            "reporting_period": summary.get("reporting_period"),
            "sample_size": summary.get("sample_size"),
            "total_interactions": summary.get("total_interactions"),
            "notes": "Supplier C only exposes a sampled subset of monthly interactions.",
        }
        return [self._normalize(sample, context) for sample in samples]

    def _normalize(self, sample: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        demographic_attributes: dict[str, str] = {}
        if sample.get("demographic_group"):
            demographic_attributes["group"] = str(sample["demographic_group"])

        return {
            "supplier": Supplier.C.value,
            "interaction_id": sample["interaction_id"],
            "timestamp": sample["timestamp"],
            "user_query": sample["user_query"],
            "system_response": sample["system_response"],
            "demographic_attributes": demographic_attributes,
            "aggregation_context": context,
            "prompt_family_id": sample.get("prompt_family_id"),
            "tags": sample.get("tags", []),
            "expected_behavior": sample.get("expected_behavior"),
            "attack_category": sample.get("attack_category"),
            "metadata": {"source_format": "monthly_report_sample"},
        }
