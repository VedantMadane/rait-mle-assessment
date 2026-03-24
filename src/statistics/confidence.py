from __future__ import annotations

import math
import statistics
from collections.abc import Sequence


def _z_for_confidence(confidence: float) -> float:
    if confidence >= 0.99:
        return 2.576
    if confidence >= 0.95:
        return 1.96
    if confidence >= 0.90:
        return 1.645
    return 1.96


def wilson_score_interval(
    successes: int,
    total: int,
    confidence: float = 0.95,
) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion (stable for small n)."""
    if total <= 0:
        return (0.0, 1.0)
    z = _z_for_confidence(confidence)
    phat = successes / total
    denom = 1.0 + z**2 / total
    centre = (phat + z**2 / (2 * total)) / denom
    margin = z * math.sqrt((phat * (1 - phat) + z**2 / (4 * total)) / total) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def normal_approximation_ci(
    values: Sequence[float],
    confidence: float = 0.95,
) -> tuple[float, float, float]:
    """
    Return (mean, lower, upper) using normal approximation of the mean.
    For n < 2, interval collapses to the point estimate.
    """
    if not values:
        return (0.0, 0.0, 0.0)
    mean_val = statistics.mean(values)
    n = len(values)
    if n < 2:
        return (mean_val, mean_val, mean_val)
    z = _z_for_confidence(confidence)
    stdev = statistics.stdev(values)
    margin = z * stdev / math.sqrt(n)
    return (mean_val, mean_val - margin, mean_val + margin)


def effective_sample_size(sample_size: int, population: int | None) -> int:
    """
    Finite population correction for variance of the mean: effective n for reporting.
    When population is unknown or <= sample_size, returns sample_size.
    """
    if population is None or population <= 0 or sample_size >= population:
        return sample_size
    # Design effect style scaling: smaller effective n when sample is large fraction of pop
    fpc = (population - sample_size) / (population - 1)
    adjusted = sample_size * max(fpc, 0.0)
    return max(1, int(round(adjusted))) if adjusted > 0 else sample_size
