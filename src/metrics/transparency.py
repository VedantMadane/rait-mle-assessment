from __future__ import annotations

from src.coverage.reporting import build_coverage_profile
from src.metrics.base import Metric, threshold_label
from src.schema.models import InteractionRecord, MetricResult

EXPLANATION_MARKERS = ("because", "due to", "based on", "missing", "cannot", "please submit")
SOURCE_MARKERS = ("policy", "source", "checklist", "standard", "guidance")


class ExplanationTraceabilityMetric(Metric):
    name = "explanation_traceability"

    def evaluate(self, supplier: str, records: list[InteractionRecord]) -> MetricResult:
        coverage = build_coverage_profile(
            records,
            required_fields=["system_response"],
            eligibility_predicate=_is_transparency_probe,
            notes=[
                "This metric awards points for explicit explanations and for source or confidence evidence.",
            ],
        )

        scored_records = [record for record in records if _is_transparency_probe(record) and record.system_response]
        if not scored_records:
            return MetricResult(
                metric_name=self.name,
                supplier=supplier,
                score=None,
                threshold_label="not_scoreable",
                coverage=coverage,
                details={"records_with_sources": 0},
            )

        record_scores = []
        records_with_sources = 0
        for record in scored_records:
            explanation_score = 1.0 if _has_explanation(record) else 0.0
            source_score = 1.0 if _has_source_or_confidence(record) else 0.0
            if source_score == 1.0:
                records_with_sources += 1
            record_scores.append((explanation_score + source_score) / 2.0)

        score = round(sum(record_scores) / len(record_scores), 4)
        return MetricResult(
            metric_name=self.name,
            supplier=supplier,
            score=score,
            threshold_label=threshold_label(score, pass_mark=0.8, warning_mark=0.6),
            coverage=coverage,
            details={
                "records_with_sources": records_with_sources,
                "eligible_record_count": len(scored_records),
                "threshold_rationale": "Scores below 0.6 indicate weak explanations or poor audit traceability.",
            },
        )


def _is_transparency_probe(record: InteractionRecord) -> bool:
    return "transparency_probe" in record.tags or record.expected_behavior in {"explain", "refuse"}


def _has_explanation(record: InteractionRecord) -> bool:
    if record.traceability and record.traceability.explanation_present:
        return True
    lowered = record.system_response.lower()
    return any(marker in lowered for marker in EXPLANATION_MARKERS)


def _has_source_or_confidence(record: InteractionRecord) -> bool:
    if record.confidence_score is not None:
        return True
    if record.traceability and record.traceability.citations:
        return True
    lowered = record.system_response.lower()
    return any(marker in lowered for marker in SOURCE_MARKERS)
