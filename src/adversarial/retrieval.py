from __future__ import annotations

import hashlib
import math
import re
from collections import Counter

from src.schema.models import AttackMatch, AttackPattern

TOKEN_RE = re.compile(r"[a-z0-9]+")
SYNONYM_MAP = {
    "passwords": "password",
    "credentials": "credential",
    "admins": "administrator",
    "adminsitrator": "administrator",
    "rules": "policy",
    "prompts": "prompt",
    "leak": "reveal",
    "disclose": "reveal",
    "bypass": "disable",
}


class HashedEmbeddingRetriever:
    def __init__(self, patterns: list[AttackPattern], dimensions: int = 128) -> None:
        self.patterns = patterns
        self.dimensions = dimensions
        self._vectors = {pattern.attack_id: self._embed_pattern(pattern) for pattern in patterns}

    def search(self, query: str, top_k: int = 3) -> list[AttackMatch]:
        query_vector = self._embed_text(query)
        scored_matches = []
        for pattern in self.patterns:
            similarity = _cosine_similarity(query_vector, self._vectors[pattern.attack_id])
            scored_matches.append(AttackMatch(pattern=pattern, similarity=round(similarity, 4)))
        scored_matches.sort(key=lambda match: match.similarity, reverse=True)
        return scored_matches[:top_k]

    def _embed_pattern(self, pattern: AttackPattern) -> list[float]:
        composite_text = " ".join(
            [
                pattern.category,
                pattern.attack_prompt,
                pattern.attack_intent,
                " ".join(pattern.keywords),
            ]
        )
        return self._embed_text(composite_text)

    def _embed_text(self, text: str) -> list[float]:
        tokens = _normalize_tokens(text)
        features = Counter(tokens)
        for token in tokens:
            if len(token) > 4:
                for index in range(len(token) - 2):
                    features[f"tri:{token[index:index + 3]}"] += 0.5

        vector = [0.0] * self.dimensions
        for feature, weight in features.items():
            bucket = _stable_bucket(feature, self.dimensions)
            vector[bucket] += weight
        return _l2_normalize(vector)


def _normalize_tokens(text: str) -> list[str]:
    lowered = text.lower()
    raw_tokens = TOKEN_RE.findall(lowered)
    return [SYNONYM_MAP.get(token, token) for token in raw_tokens]


def _stable_bucket(value: str, dimensions: int) -> int:
    digest = hashlib.md5(value.encode("utf-8")).hexdigest()
    return int(digest, 16) % dimensions


def _l2_normalize(vector: list[float]) -> list[float]:
    norm = math.sqrt(sum(component * component for component in vector))
    if norm == 0:
        return vector
    return [component / norm for component in vector]


def _cosine_similarity(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right))
