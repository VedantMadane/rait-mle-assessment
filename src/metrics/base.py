from __future__ import annotations

from abc import ABC, abstractmethod

from src.schema.models import InteractionRecord, MetricResult


class Metric(ABC):
    name: str

    @abstractmethod
    def evaluate(self, supplier: str, records: list[InteractionRecord]) -> MetricResult:
        raise NotImplementedError


def threshold_label(score: float | None, pass_mark: float, warning_mark: float) -> str:
    if score is None:
        return "not_scoreable"
    if score >= pass_mark:
        return "pass"
    if score >= warning_mark:
        return "warning"
    return "fail"


def threshold_label_with_ci(
    score: float | None,
    ci_lower: float | None,
    pass_mark: float,
    warning_mark: float,
) -> str:
    """
    If the point estimate passes but the lower confidence bound sits below the warning
    threshold, downgrade to 'warning' to reflect sampling uncertainty.
    """
    label = threshold_label(score, pass_mark, warning_mark)
    if ci_lower is not None and score is not None and label == "pass" and ci_lower < warning_mark:
        return "warning"
    return label
