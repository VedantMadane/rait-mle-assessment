from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from src.adapters.supplier_a import SupplierAAdapter
from src.adapters.supplier_b import SupplierBAdapter
from src.adapters.supplier_c import SupplierCAdapter
from src.adversarial.dataset import load_attack_patterns, load_test_queries
from src.adversarial.judge import MultiRunJudge, judge_report_to_dict
from src.adversarial.retrieval import HashedEmbeddingRetriever
from src.coverage.reporting import summarize_supplier_data_availability
from src.metrics.fairness import DemographicParityMetric
from src.metrics.security import PromptInjectionResistanceMetric
from src.metrics.transparency import ExplanationTraceabilityMetric
from src.schema.models import BatchRobustnessReport


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the RAIT MLE assessment pipeline.")
    parser.add_argument(
        "--output-json",
        action="store_true",
        help="Print the full report as JSON instead of a human-readable summary.",
    )
    return parser.parse_args()


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_supplier_records() -> dict[str, list]:
    root = project_root()
    return {
        "supplier_a": SupplierAAdapter().load(str(root / "data" / "supplier_a" / "interactions.json")),
        "supplier_b": SupplierBAdapter().load(str(root / "data" / "supplier_b" / "interactions.csv")),
        "supplier_c": SupplierCAdapter().load(str(root / "data" / "supplier_c")),
    }


def run_metric_suite(records_by_supplier: dict[str, list]) -> dict[str, list[dict[str, Any]]]:
    metrics = [
        PromptInjectionResistanceMetric(),
        DemographicParityMetric(),
        ExplanationTraceabilityMetric(),
    ]
    outputs: dict[str, list[dict[str, Any]]] = {}
    for supplier, records in records_by_supplier.items():
        outputs[supplier] = [metric.evaluate(supplier, records).to_dict() for metric in metrics]
    return outputs


def run_red_team_batch() -> dict[str, Any]:
    root = project_root()
    patterns = load_attack_patterns(str(root / "data" / "red_team" / "attacks.json"))
    test_queries = load_test_queries(str(root / "data" / "red_team" / "test_queries.json"))
    retriever = HashedEmbeddingRetriever(patterns)
    judge = MultiRunJudge()

    category_scores: dict[str, list[float]] = defaultdict(list)
    record_results = []

    for item in test_queries:
        matches = retriever.search(item["query"], top_k=3)
        judge_result = judge.evaluate(item["query"], item["response"], matches, runs=3)
        top_category = matches[0].pattern.category
        category_scores[top_category].append(judge_result.average_score)
        record_results.append(
            {
                "query": item["query"],
                "response": item["response"],
                "label": item["label"],
                "matched_patterns": [
                    {
                        "attack_id": match.pattern.attack_id,
                        "category": match.pattern.category,
                        "attack_intent": match.pattern.attack_intent,
                        "similarity": match.similarity,
                    }
                    for match in matches
                ],
                "judge_result": judge_report_to_dict(judge_result),
            }
        )

    averaged_categories = {
        category: round(sum(scores) / len(scores), 4) for category, scores in category_scores.items()
    }
    overall_score = round(
        sum(item["judge_result"]["average_score"] for item in record_results) / len(record_results),
        4,
    )
    report = BatchRobustnessReport(
        supplier="cross_supplier_synthetic_batch",
        category_scores=averaged_categories,
        overall_score=overall_score,
        record_results=[],
    )
    return {
        "supplier": report.supplier,
        "category_scores": report.category_scores,
        "overall_score": report.overall_score,
        "record_results": record_results,
    }


def build_report() -> dict[str, Any]:
    records_by_supplier = load_supplier_records()
    return {
        "supplier_data_coverage": {
            supplier: summarize_supplier_data_availability(records)
            for supplier, records in records_by_supplier.items()
        },
        "metric_results": run_metric_suite(records_by_supplier),
        "red_team_report": run_red_team_batch(),
    }


def print_summary(report: dict[str, Any]) -> None:
    print("RAIT MLE Assessment Summary")
    print("=" * 28)
    print()
    print("Supplier data coverage:")
    for supplier, summary in report["supplier_data_coverage"].items():
        print(
            f"- {supplier}: {summary['record_count']} records, "
            f"sample_ratio={summary['sample_ratio']}, note={summary['coverage_note']}"
        )

    print()
    print("Metric results:")
    for supplier, results in report["metric_results"].items():
        print(f"- {supplier}")
        for result in results:
            print(
                f"  {result['metric_name']}: score={result['score']}, "
                f"threshold={result['threshold_label']}, "
                f"coverage={result['coverage']['coverage_ratio']}"
            )

    print()
    print("Red-team batch:")
    print(
        f"- overall_score={report['red_team_report']['overall_score']}, "
        f"category_scores={report['red_team_report']['category_scores']}"
    )


def main() -> None:
    args = parse_args()
    report = build_report()
    if args.output_json:
        print(json.dumps(report, indent=2))
        return
    print_summary(report)


if __name__ == "__main__":
    main()
