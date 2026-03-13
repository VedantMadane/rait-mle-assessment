from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Supplier(str, Enum):
    A = "supplier_a"
    B = "supplier_b"
    C = "supplier_c"


@dataclass(slots=True)
class TokenCounts:
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None


@dataclass(slots=True)
class Traceability:
    citations: list[str] = field(default_factory=list)
    rationale: str | None = None
    refusal_policy: str | None = None
    explanation_present: bool | None = None


@dataclass(slots=True)
class AggregationContext:
    source_type: str
    reporting_period: str | None = None
    sample_size: int | None = None
    total_interactions: int | None = None
    notes: str | None = None


@dataclass(slots=True)
class InteractionRecord:
    supplier: Supplier
    interaction_id: str
    timestamp: datetime
    user_query: str
    system_response: str
    model_name: str | None = None
    model_version: str | None = None
    token_counts: TokenCounts | None = None
    confidence_score: float | None = None
    demographic_attributes: dict[str, str] = field(default_factory=dict)
    traceability: Traceability | None = None
    aggregation_context: AggregationContext | None = None
    prompt_family_id: str | None = None
    tags: list[str] = field(default_factory=list)
    expected_behavior: str | None = None
    attack_category: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["supplier"] = self.supplier.value
        payload["timestamp"] = self.timestamp.isoformat()
        return payload


@dataclass(slots=True)
class CoverageProfile:
    required_fields: list[str]
    eligible_records: int
    scored_records: int
    missing_requirements: list[str]
    notes: list[str] = field(default_factory=list)

    @property
    def coverage_ratio(self) -> float:
        if self.eligible_records == 0:
            return 0.0
        return round(self.scored_records / self.eligible_records, 4)


@dataclass(slots=True)
class MetricResult:
    metric_name: str
    supplier: str
    score: float | None
    threshold_label: str
    coverage: CoverageProfile
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["coverage"]["coverage_ratio"] = self.coverage.coverage_ratio
        return payload


@dataclass(slots=True)
class AttackPattern:
    attack_id: str
    category: str
    attack_prompt: str
    attack_intent: str
    expected_failure_mode: str
    keywords: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AttackMatch:
    pattern: AttackPattern
    similarity: float


@dataclass(slots=True)
class JudgeRun:
    run_id: int
    score: float
    rationale: str


@dataclass(slots=True)
class JudgeAggregate:
    average_score: float
    runs: list[JudgeRun]
    threshold_label: str


@dataclass(slots=True)
class AdversarialRecordResult:
    query: str
    response: str
    matched_patterns: list[dict[str, Any]]
    judge_result: JudgeAggregate


@dataclass(slots=True)
class BatchRobustnessReport:
    supplier: str
    category_scores: dict[str, float]
    overall_score: float
    record_results: list[AdversarialRecordResult]


def parse_timestamp(raw_timestamp: str) -> datetime:
    normalized = raw_timestamp.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)
