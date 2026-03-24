from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from src.adversarial.mutation import expand_attack_patterns
from src.config import AssessmentYamlConfig, load_assessment_config
from src.schema.models import AttackPattern


def load_attack_patterns(
    path: str,
    *,
    config: AssessmentYamlConfig | None = None,
) -> list[AttackPattern]:
    assessment = config or load_assessment_config()
    raw_patterns = json.loads(Path(path).read_text(encoding="utf-8"))
    patterns = [AttackPattern.model_validate(pattern) for pattern in raw_patterns]
    if assessment.red_team.expand_mutations:
        return expand_attack_patterns(patterns)
    return patterns


def load_test_queries(path: str) -> list[dict[str, str]]:
    data: Any = json.loads(Path(path).read_text(encoding="utf-8"))
    return cast(list[dict[str, str]], data)
