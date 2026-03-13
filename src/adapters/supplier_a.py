from __future__ import annotations

import json
from pathlib import Path

from src.adapters.base import SupplierAdapter
from src.schema.models import (
    InteractionRecord,
    Supplier,
    TokenCounts,
    Traceability,
    parse_timestamp,
)


class SupplierAAdapter(SupplierAdapter):
    supplier_name = Supplier.A.value

    def load(self, path: str) -> list[InteractionRecord]:
        raw_records = json.loads(Path(path).read_text(encoding="utf-8"))
        return [self._normalize(record) for record in raw_records]

    def _normalize(self, record: dict) -> InteractionRecord:
        traceability_payload = record.get("traceability") or {}
        token_payload = record.get("token_counts") or {}
        model_payload = record.get("model") or {}

        traceability = None
        if traceability_payload:
            traceability = Traceability(
                citations=traceability_payload.get("citations", []),
                rationale=traceability_payload.get("rationale"),
                refusal_policy=traceability_payload.get("refusal_policy"),
                explanation_present=traceability_payload.get("explanation_present"),
            )

        token_counts = None
        if token_payload:
            token_counts = TokenCounts(
                prompt_tokens=token_payload.get("prompt"),
                completion_tokens=token_payload.get("completion"),
                total_tokens=token_payload.get("total"),
            )

        return InteractionRecord(
            supplier=Supplier.A,
            interaction_id=record["id"],
            timestamp=parse_timestamp(record["timestamp"]),
            user_query=record["prompt"],
            system_response=record["response"],
            model_name=model_payload.get("name"),
            model_version=model_payload.get("version"),
            token_counts=token_counts,
            demographic_attributes=record.get("demographics", {}),
            traceability=traceability,
            prompt_family_id=record.get("prompt_family_id"),
            tags=record.get("tags", []),
            expected_behavior=record.get("expected_behavior"),
            attack_category=record.get("attack_category"),
            metadata={"source_format": "json_api"},
        )
