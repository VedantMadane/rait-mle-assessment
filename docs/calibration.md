# Calibration and magic numbers

## Heuristic judge coefficients

The offline `HeuristicJudgeClient` uses coefficients loaded from `config/assessment.yaml` under `heuristic_judge`. The intent is documented in the class docstring in `src/adversarial/judge.py`:

- **safe_refusal_base / safe_refusal_similarity_weight**: When the query is likely adversarial (keyword risk or high similarity to catalogued attacks) and the response shows refusal language without actionable unsafe content, the score starts from a base and increases with `similarity_mean` to reward robustness against close matches to known attack vectors.
- **unsafe_compliance_base / unsafe_compliance_similarity_penalty**: When actionable unsafe patterns appear under an adversarial context, the score is driven down, penalized more when attack similarity is high.
- **benign_helpful_score / conservative_safe_score / ambiguous_score**: Handle benign Q&A, weak refusal evidence, and ambiguous cases without silent failure.

These values are **not** production-calibrated; they are reasonable defaults for a reproducible take-home assessment.

## Production calibration

1. **Golden dataset**: Curate thousands of `(query, response, label)` tuples with human adjudication (safe refusal, partial leak, full compliance, etc.).
2. **Fit weights**: Train a simple model (e.g. logistic regression) on features derived from retrieval similarity, NLI scores, and policy tags to replace hand-set coefficients.
3. **Prefer learned judges**: Move from heuristics to a calibrated **LLM-as-judge** (with schema-validated JSON outputs) or to **NLI / cross-encoder** stacks evaluated on the golden set with held-out metrics (ECE, recall on unsafe class).
4. **Threshold tuning**: Set `pass_mark` / `warning_mark` per deployment from ROC analysis and business risk appetite; keep them in config, not code.

## Metric thresholds

Security, fairness, and transparency pass/warning marks live under `metrics` in `config/assessment.yaml`. Adjust them per regulatory context and pilot data rather than editing Python modules.
