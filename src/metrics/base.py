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
