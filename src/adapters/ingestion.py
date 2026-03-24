from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import structlog
from pydantic import ValidationError

from src.schema.models import InteractionRecord

logger = structlog.get_logger(__name__)


def ingest_records(
    record_dicts: Iterable[dict[str, Any]],
    *,
    source: str,
    dead_letter_path: Path,
) -> tuple[list[InteractionRecord], int]:
    """
    Validate interaction dicts; invalid rows are appended to dead_letter_path as JSON lines.
    Returns (valid_records, error_count).
    """
    dead_letter_path.parent.mkdir(parents=True, exist_ok=True)
    valid: list[InteractionRecord] = []
    errors = 0
    for index, raw in enumerate(record_dicts):
        try:
            valid.append(InteractionRecord.model_validate(raw))
        except ValidationError as exc:
            errors += 1
            payload = {
                "source": source,
                "index": index,
                "errors": exc.errors(),
                "raw": raw,
            }
            logger.warning(
                "ingestion_validation_failed",
                source=source,
                index=index,
                error_count=len(exc.errors()),
            )
            with dead_letter_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, default=str) + "\n")
    if errors:
        logger.info(
            "ingestion_complete_with_errors",
            source=source,
            valid=len(valid),
            invalid=errors,
            dead_letter=str(dead_letter_path),
        )
    else:
        logger.info("ingestion_complete", source=source, count=len(valid))
    return valid, errors
