from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Supplier(str, Enum):
    A = "supplier_a"
    B = "supplier_b"
    C = "supplier_c"


class TokenCounts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None


class Traceability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    citations: list[str] = Field(default_factory=list)
    rationale: str | None = None
    refusal_policy: str | None = None
    explanation_present: bool | None = None


class AggregationContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_type: str
    reporting_period: str | None = None
    sample_size: int | None = None
    total_interactions: int | None = None
    notes: str | None = None


class InteractionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    supplier: Supplier
    interaction_id: str = Field(min_length=1)
    timestamp: datetime
    user_query: str
    system_response: str
    model_name: str | None = None
    model_version: str | None = None
    token_counts: TokenCounts | None = None
    confidence_score: float | None = None
    demographic_attributes: dict[str, str] = Field(default_factory=dict)
    traceability: Traceability | None = None
    aggregation_context: AggregationContext | None = None
    prompt_family_id: str | None = None
    tags: list[str] = Field(default_factory=list)
    expected_behavior: str | None = None
    attack_category: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("supplier", mode="before")
    @classmethod
    def coerce_supplier(cls, value: Any) -> Any:
        if isinstance(value, Supplier):
            return value
        if isinstance(value, str):
            return Supplier(value)
        return value

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp_field(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            return parse_timestamp(value)
        return value

    @field_validator("confidence_score")
    @classmethod
    def confidence_in_unit_interval(cls, value: float | None) -> float | None:
        if value is None:
            return None
        if not 0.0 <= value <= 1.0:
            raise ValueError("confidence_score must be between 0 and 1")
        return value

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class CoverageProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    required_fields: list[str]
    eligible_records: int
    scored_records: int
    missing_requirements: list[str]
    notes: list[str] = Field(default_factory=list)

    @property
    def coverage_ratio(self) -> float:
        if self.eligible_records == 0:
            return 0.0
        return round(self.scored_records / self.eligible_records, 4)


class MetricResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    metric_name: str
    supplier: str
    score: float | None
    threshold_label: str
    coverage: CoverageProfile
    details: dict[str, Any] = Field(default_factory=dict)
    confidence_interval: tuple[float, float] | None = None
    effective_n: int | None = None
    confidence_level: float | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        cov = payload["coverage"]
        cov["coverage_ratio"] = self.coverage.coverage_ratio
        return payload


class AttackPattern(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attack_id: str
    category: str
    attack_prompt: str
    attack_intent: str
    expected_failure_mode: str
    keywords: list[str] = Field(default_factory=list)
    atlas_id: str | None = None
    owasp_id: str | None = None


class AttackMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pattern: AttackPattern
    similarity: float


class JudgeRun(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: int
    score: float
    rationale: str


class JudgeAggregate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    average_score: float
    runs: list[JudgeRun]
    threshold_label: str


class AdversarialRecordResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str
    response: str
    matched_patterns: list[dict[str, Any]]
    judge_result: JudgeAggregate


class BatchRobustnessReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    supplier: str
    category_scores: dict[str, float]
    overall_score: float
    record_results: list[AdversarialRecordResult]


def parse_timestamp(raw_timestamp: str) -> datetime:
    normalized = raw_timestamp.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)
