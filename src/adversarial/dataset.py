from __future__ import annotations

import json
from pathlib import Path

from src.schema.models import AttackPattern


def load_attack_patterns(path: str) -> list[AttackPattern]:
    raw_patterns = json.loads(Path(path).read_text(encoding="utf-8"))
    return [AttackPattern(**pattern) for pattern in raw_patterns]


def load_test_queries(path: str) -> list[dict[str, str]]:
    return json.loads(Path(path).read_text(encoding="utf-8"))
