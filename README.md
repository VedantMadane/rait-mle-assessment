# RAIT MLE Technical Assessment

This repository implements a lightweight, supplier-agnostic evaluation framework for Responsible AI assessment across three simulated chatbot suppliers with uneven access patterns.

The design goal was not to maximize sophistication. It was to make the scoring path auditable, explicit about missing evidence, and easy to extend when a new supplier arrives with a different raw format.

## What This Submission Covers
- A canonical schema that separates required and optional interaction fields
- Three ingestion adapters for simulated Supplier A, B, and C formats
- A coverage reporter that makes scoreability and sampling limits explicit
- Three auditable metrics:
  - security / adversarial robustness
  - fairness / demographic response parity
  - transparency / explainability
- A red-team pipeline with:
  - curated adversarial prompts (base set plus extensions; see `data/red_team/attacks.json`) across four attack categories
  - embedding-style similarity retrieval using deterministic hashed vector embeddings
  - multi-run LLM-as-judge support with an offline heuristic fallback
  - a scored batch report over benign and adversarial examples
- Focused unit tests around normalization, coverage, metrics, retrieval, and end-to-end reporting

## Repository Layout
- `config/assessment.yaml`: thresholds, heuristic judge coefficients, paths, `scoring_backend`, red-team flags
- `src/schema/models.py`: Pydantic canonical records, coverage models, and adversarial result models
- `src/config.py`: typed config loader (optional `RAIT_CONFIG_PATH`)
- `src/adapters/`: one adapter per supplier (raw dict normalization + `ingest_records` validation)
- `src/coverage/reporting.py`: coverage utilities and supplier-level data availability summary
- `src/metrics/`: metric interfaces and the three implemented metrics (with optional CIs)
- `src/scoring/`: pluggable keyword vs NLI/cross-encoder scorers
- `src/statistics/`: Wilson and normal approximation confidence helpers
- `src/adversarial/`: red-team dataset loader, retrieval, judge, and deterministic mutation helpers
- `src/cli.py`: one command entry point to run the full assessment
- `data/`: synthetic supplier data plus the red-team dataset (`data/dead_letter.jsonl` is created for invalid rows)
- `docs/metric_definitions.md`: metric definitions, formulas, and thresholds
- `docs/calibration.md`, `docs/regulatory_landscape.md`, `docs/90_day_plan.md`, `docs/threat_coverage.md`: production and compliance notes
- `tests/test_pipeline.py`: focused regression tests
- `.github/workflows/ci.yml`: ruff, mypy strict, pytest on Python 3.11 and 3.12

## Canonical Schema
The core normalized object is `InteractionRecord`.

Required fields:
- `supplier`
- `interaction_id`
- `timestamp`
- `user_query`
- `system_response`

Optional fields:
- `model_name`, `model_version`, `token_counts`
- `confidence_score`
- `demographic_attributes`
- `traceability`
- `aggregation_context`
- `prompt_family_id`, `tags`, `expected_behavior`, `attack_category`

### Why this structure
I deliberately kept the required contract small. In real supplier integrations, the ingestion layer should not force every supplier to produce metadata they do not actually expose. Instead:
- required fields support basic cross-supplier evaluation
- optional fields unlock richer metrics where evidence exists
- `aggregation_context` makes sampled or summary-derived data explicit rather than pretending record-level completeness

This is the key mechanism for graceful degradation. Supplier C normalizes into the same schema, but carries a clear note that evaluation is based only on a sampled monthly subset.

## Supplier Adapters
### Supplier A
Full JSON prompt/response interactions with model metadata and token counts.

### Supplier B
Daily CSV export with query, response, and supplier-provided confidence score.

### Supplier C
Monthly summary plus sampled JSON interactions. The adapter loads the sample interactions and attaches an `AggregationContext` populated from the monthly summary. This allows the evaluation layer to know that only a small sample is scoreable.

## Coverage Reporting
There are two coverage ideas in the implementation:

1. Metric scoreability coverage
- each metric reports `eligible_records`
- each metric reports `scored_records`
- each metric reports `missing_requirements`
- each metric exposes `coverage_ratio = scored_records / eligible_records`

2. Supplier data availability coverage
- for sampled suppliers like Supplier C, the framework also reports `sample_size`, `total_interactions`, and `sample_ratio`
- this avoids overstating confidence in metrics computed from a small exposed subset

This is the most important design choice in the repository. The framework does not silently skip unsupported cases and does not fabricate completeness for Supplier C.

## Metric Choices
Detailed definitions live in `docs/metric_definitions.md`.

### 1. Security: `prompt_injection_resistance`
Measures whether explicit adversarial or security probe prompts are safely refused without actionable unsafe detail.

Why this metric:
- auditable with simple per-record pass/fail logic
- works across all three suppliers as long as prompt/response pairs are available
- degrades naturally when a supplier exposes fewer attack probes

### 2. Fairness: `demographic_response_parity`
Measures response quality parity across repeated prompt families that differ only in demographic variant.

Why this metric:
- makes fairness comparative rather than anecdotal
- works with synthetic probe families across suppliers
- remains inspectable because the family-level disparity is exposed

### 3. Transparency: `explanation_traceability`
Measures whether the system provides both an explanation signal and an auditable traceability signal such as citations, policy wording, or supplier confidence.

Why this metric:
- balances interpretability with evidence for auditability
- can use richer metadata where available without requiring it from all suppliers
- exposes weaker transparency for sampled or poorly sourced suppliers

## Adversarial Robustness Deep Dive
The red-team pipeline does four things:

1. Loads a curated attack set (expandable via config) across:
- `prompt_injection`
- `jailbreak`
- `information_extraction`
- `policy_contradiction`

2. Encodes attack prompts and new queries into deterministic hashed vector embeddings
- This is intentionally lightweight and offline-friendly
- It is less semantically rich than a pretrained embedding model, but keeps the repo runnable with no external dependency or API requirement

3. Retrieves the closest attack patterns by cosine similarity

4. Evaluates the matched query and response with multi-run judging
- if `OPENAI_API_KEY` is set, the code attempts a live OpenAI-compatible judge via HTTPS
- otherwise it falls back to a deterministic heuristic judge so the pipeline still runs end to end

### Why the fallback exists
The brief allows any LLM API, but a take-home repository should still be runnable by a reviewer without credentials. The fallback preserves reproducibility while still showing a real LLM-judge integration point.

## Trade-offs
### Minimal schema over exhaustive schema
I favored a small canonical contract with optional enrichments instead of a large schema that every supplier would fail to satisfy.

### Deterministic metrics over fully model-based metrics
For Part 2, deterministic or mostly rule-based metrics are easier to audit. They are less expressive than a live judge, but better fit the requirement that an auditor can verify the implementation against the definition.

### Offline hashed embeddings over a pretrained embedding dependency
The retrieval stack is intentionally lightweight. A pretrained embedding model would likely improve semantic recall, but it would also make local execution heavier and less predictable in a short assessment submission.

### Synthetic probes as evaluation scaffolding
The fairness metric relies on synthetic demographic variants and repeated prompt families. That makes the metric demonstrable and cross-supplier, but it also means the result quality depends on how representative the synthetic probes are.

## Onboarding A Fourth Supplier
The architecture is intended to avoid rewriting the evaluation layer.

To onboard a new supplier:
1. Write a new adapter class under `src/adapters/` that reads the supplier's native format.
2. Normalize the raw data into `InteractionRecord`.
3. Populate optional fields only when the supplier genuinely provides them.
4. If the supplier exposes sampled or aggregated data, attach `AggregationContext`.
5. Register the adapter in `src/cli.py` or any orchestration layer.

The metric code should not need supplier-specific branching as long as the adapter maps the new source into the canonical schema correctly.

## How To Run

Install dependencies (from repo root):

```bash
pip install -e ".[dev]"
```

Optional NLI / cross-encoder backends:

```bash
pip install -e ".[dev,nli]"
```

Set `scoring_backend: nli` in `config/assessment.yaml` to use cross-encoder / NLI paths (with keyword fallbacks if models are unavailable).

Run the full pipeline:

```bash
python -m src.cli
```

Emit the full report as JSON:

```bash
python -m src.cli --output-json
```

Run tests:

```bash
python -m pytest tests/ -v
```

Override config path (example on Windows):

```bash
set RAIT_CONFIG_PATH=C:\path\to\custom.yaml
python -m src.cli
```

## Notes On AI Tooling
I used an AI coding assistant to accelerate scaffolding and iteration, but the repository structure, schema choices, metric definitions, thresholds, and degradation behavior were intentionally directed and reviewed rather than accepted blindly.

## If I Had More Time
- replace the hashed embedding retriever with a stronger pretrained embedding backend behind the same interface
- add richer fairness probes and subgroup intersectionality
- make transparency scoring more componentized, with separate citation quality and refusal rationale subscores
- persist CLI outputs into versioned report artifacts for easier audit comparison
