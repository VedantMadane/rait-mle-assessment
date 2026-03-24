from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from src.adapters.base import SupplierAdapter
from src.schema.models import Supplier


class SupplierBAdapter(SupplierAdapter):
    supplier_name = Supplier.B.value

    def load(self, path: str) -> list[dict[str, Any]]:
        with Path(path).open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            return [self._normalize(row) for row in reader]

    def _normalize(self, row: dict[str, Any]) -> dict[str, Any]:
        demographic_attributes: dict[str, str] = {}
        if row.get("demographic_group"):
            demographic_attributes["group"] = str(row["demographic_group"])

        return {
            "supplier": Supplier.B.value,
            "interaction_id": row["interaction_id"],
            "timestamp": row["timestamp"],
            "user_query": row["user_query"],
            "system_response": row["system_response"],
            "confidence_score": float(row["confidence_score"]) if row.get("confidence_score") else None,
            "demographic_attributes": demographic_attributes,
            "prompt_family_id": row.get("prompt_family_id") or None,
            "tags": _split_tags(row.get("tags")),
            "expected_behavior": row.get("expected_behavior") or None,
            "attack_category": row.get("attack_category") or None,
            "metadata": {"source_format": "csv_export"},
        }


def _split_tags(raw_tags: str | None) -> list[str]:
    if not raw_tags:
        return []
    return [tag for tag in raw_tags.split("|") if tag]
