from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import structlog

from src.adapters.ingestion import ingest_records
from src.adapters.supplier_a import SupplierAAdapter
from src.adapters.supplier_b import SupplierBAdapter
from src.adapters.supplier_c import SupplierCAdapter
from src.adversarial.dataset import load_attack_patterns, load_test_queries
from src.adversarial.judge import MultiRunJudge, judge_report_to_dict
from src.adversarial.retrieval import HashedEmbeddingRetriever
from src.config import (
    AssessmentYamlConfig,
    get_project_root,
    load_assessment_config,
    resolve_path,
)
from src.coverage.reporting import summarize_supplier_data_availability
from src.metrics.fairness import DemographicParityMetric
from src.metrics.security import PromptInjectionResistanceMetric
from src.metrics.transparency import ExplanationTraceabilityMetric
from src.schema.models import BatchRobustnessReport, InteractionRecord

logger = structlog.get_logger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the RAIT MLE assessment pipeline.")
    parser.add_argument(
        "--output-json",
        action="store_true",
        help="Print the full report as JSON instead of a human-readable summary.",
    )
    return parser.parse_args()


def project_root() -> Path:
    return get_project_root()


def _reset_dead_letter(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")


def load_supplier_records(
    config: AssessmentYamlConfig,
    root: Path,
) -> dict[str, list[InteractionRecord]]:
    dead_letter = resolve_path(root, config.paths.dead_letter_file)
    _reset_dead_letter(dead_letter)

    def _ingest(source: str, dicts: list[dict[str, Any]]) -> list[InteractionRecord]:
        valid, err = ingest_records(dicts, source=source, dead_letter_path=dead_letter)
        if err:
            logger.warning("supplier_ingestion_errors", supplier=source, invalid_rows=err)
        return valid

    a_path = resolve_path(root, config.paths.supplier_a_json)
    b_path = resolve_path(root, config.paths.supplier_b_csv)
    c_path = resolve_path(root, config.paths.supplier_c_dir)

    return {
        "supplier_a": _ingest("supplier_a", SupplierAAdapter().load(str(a_path))),
        "supplier_b": _ingest("supplier_b", SupplierBAdapter().load(str(b_path))),
        "supplier_c": _ingest("supplier_c", SupplierCAdapter().load(str(c_path))),
    }


def run_metric_suite(
    records_by_supplier: dict[str, list[InteractionRecord]],
    config: AssessmentYamlConfig,
) -> dict[str, list[dict[str, Any]]]:
    metrics = [
        PromptInjectionResistanceMetric(config),
        DemographicParityMetric(config),
        ExplanationTraceabilityMetric(config),
    ]
    outputs: dict[str, list[dict[str, Any]]] = {}
    for supplier, records in records_by_supplier.items():
        logger.info("running_metrics", supplier=supplier)
        outputs[supplier] = [metric.evaluate(supplier, records).to_dict() for metric in metrics]
    return outputs


def run_red_team_batch(config: AssessmentYamlConfig, root: Path) -> dict[str, Any]:
    attacks_path = resolve_path(root, config.paths.red_team_attacks)
    queries_path = resolve_path(root, config.paths.red_team_queries)
    patterns = load_attack_patterns(str(attacks_path), config=config)
    test_queries = load_test_queries(str(queries_path))
    retriever = HashedEmbeddingRetriever(patterns)
    judge = MultiRunJudge(config=config)
    top_k = config.red_team.top_k

    category_scores: dict[str, list[float]] = defaultdict(list)
    record_results: list[dict[str, Any]] = []

    logger.info("red_team_batch_start", queries=len(test_queries), patterns=len(patterns))
    for item in test_queries:
        matches = retriever.search(item["query"], top_k=top_k)
        judge_result = judge.evaluate(
            item["query"],
            item["response"],
            matches,
            runs=config.red_team.runs,
        )
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


def build_report(config: AssessmentYamlConfig | None = None) -> dict[str, Any]:
    cfg = config or load_assessment_config()
    root = project_root()
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ],
    )

    logger.info("build_report_start", project_root=str(root))
    records_by_supplier = load_supplier_records(cfg, root)
    return {
        "supplier_data_coverage": {
            supplier: summarize_supplier_data_availability(records)
            for supplier, records in records_by_supplier.items()
        },
        "metric_results": run_metric_suite(records_by_supplier, cfg),
        "red_team_report": run_red_team_batch(cfg, root),
    }


def _format_score_line(result: dict[str, Any]) -> str:
    score = result["score"]
    ci = result.get("confidence_interval")
    level = result.get("confidence_level")
    base = (
        f"{result['metric_name']}: score={score}, "
        f"threshold={result['threshold_label']}, "
        f"coverage={result['coverage']['coverage_ratio']}"
    )
    if ci is not None and score is not None and level is not None:
        pct = int(round(float(level) * 100))
        base += f", ci=[{ci[0]}, {ci[1]}] ({pct}% CI)"
    return base


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
            print(f"  {_format_score_line(result)}")

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
