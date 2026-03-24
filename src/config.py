from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class MetricThresholds(BaseModel):
    pass_mark: float
    warning_mark: float


class MetricsConfig(BaseModel):
    security: MetricThresholds
    fairness: MetricThresholds
    transparency: MetricThresholds


class HeuristicJudgeConfig(BaseModel):
    attack_similarity_cutoff: float
    safe_refusal_base: float
    safe_refusal_similarity_weight: float
    unsafe_compliance_base: float
    unsafe_compliance_similarity_penalty: float
    benign_helpful_score: float
    conservative_safe_score: float
    ambiguous_score: float


class RedTeamConfig(BaseModel):
    top_k: int = 3
    runs: int = 3
    pass_mark: float = 0.8
    warning_mark: float = 0.6
    expand_mutations: bool = False


class PathsConfig(BaseModel):
    supplier_a_json: str = "data/supplier_a/interactions.json"
    supplier_b_csv: str = "data/supplier_b/interactions.csv"
    supplier_c_dir: str = "data/supplier_c"
    red_team_attacks: str = "data/red_team/attacks.json"
    red_team_queries: str = "data/red_team/test_queries.json"
    dead_letter_file: str = "data/dead_letter.jsonl"


class StatisticsConfig(BaseModel):
    confidence_level: float = 0.95


class OpenAIConfig(BaseModel):
    api_base: str = "https://api.openai.com/v1/chat/completions"
    model: str = "gpt-4o-mini"
    temperature: float = 0.2
    timeout_seconds: int = 60


class AssessmentYamlConfig(BaseModel):
    paths: PathsConfig = Field(default_factory=PathsConfig)
    scoring_backend: str = "keyword"
    metrics: MetricsConfig
    heuristic_judge: HeuristicJudgeConfig
    red_team: RedTeamConfig = Field(default_factory=RedTeamConfig)
    statistics: StatisticsConfig = Field(default_factory=StatisticsConfig)
    openai: OpenAIConfig = Field(default_factory=OpenAIConfig)


class Settings(BaseSettings):
    """Environment overrides use nested delimiter __ e.g. RAIT_METRICS__SECURITY__PASS_MARK."""

    model_config = SettingsConfigDict(
        env_prefix="RAIT_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    config_path: Path | None = None


def _default_config_path(project_root: Path) -> Path:
    return project_root / "config" / "assessment.yaml"


def load_yaml_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Assessment config not found: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Config must be a mapping: {path}")
    return raw


def get_project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_assessment_config(project_root: Path | None = None) -> AssessmentYamlConfig:
    root = project_root or get_project_root()
    settings = Settings()
    path = settings.config_path or _default_config_path(root)
    data = load_yaml_config(path)
    return AssessmentYamlConfig.model_validate(data)


def resolve_path(project_root: Path, relative_or_absolute: str) -> Path:
    p = Path(relative_or_absolute)
    return p if p.is_absolute() else (project_root / p)
