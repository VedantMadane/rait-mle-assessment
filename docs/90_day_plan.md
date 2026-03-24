# First 90 days (production hardening)

## Days 0–30: Foundation

- Audit **real** upstream formats from each supplier; extend adapters and Pydantic models accordingly.
- Enable **CI/CD** (lint, `mypy --strict`, tests) in the deployment org; gate merges on green builds.
- Operationalize **structured logging** and dead-letter review (owner, SLA, tooling).
- Confirm **config management**: environment-specific YAML + secrets for API-backed judges.

## Days 30–60: Evaluation upgrade

- Replace or augment keyword metrics with **NLI / cross-encoder** or **LLM-as-judge**, trained or calibrated on a **golden dataset**.
- Run **human adjudication** on disagreements between heuristic and model judges; feed back into prompts and weights.
- Treat **sampled suppliers** as first-class: always report **confidence intervals** and effective sample sizes in executive summaries.

## Days 60–90: Scale and map

- Grow the red-team library via **automated mutation** (`src/adversarial/mutation.py`) and optional secondary-LLM generation with safety controls.
- Map attack inventory to **MITRE ATLAS** and **OWASP LLM Top 10** coverage gaps; prioritize gaps by likelihood and impact.
- Integrate batch JSON outputs into an **observability dashboard** (trends, regressions, per-supplier drift).
