# Regulatory and standards landscape

This framework is a **technical evaluation scaffold**. It does not replace legal counsel or formal conformity assessment. The following mappings help position the tool relative to common AI governance references.

## NIST AI RMF

| RMF function | How this repo supports it |
|--------------|---------------------------|
| **Map** | Supplier adapters normalize heterogeneous inputs; coverage and `aggregation_context` surface what data exists per supplier. |
| **Measure** | Metrics (security, fairness, transparency), Wilson / normal CIs for sampled data, red-team batch with explicit judge rationales. |
| **Manage** | Config-driven thresholds; dead-letter queue for failed ingestion; extensible scorers (keyword vs NLI). |
| **Govern** | Auditable `details` on each metric result; documentation of limitations in `docs/calibration.md` and this file. |

## EU AI Act (high-level)

Relevant themes for chatbot / GPAI use cases include **transparency** (e.g. Article 13-style clarity to users), **risk tiering** and obligations for high-risk systems, and **fundamental rights** considerations. This codebase:

- Surfaces **non-deceptive** reporting via confidence intervals when only samples are available (Supplier C pattern).
- Separates **evidence-backed** optional fields (citations, confidence) from minimal required fields to avoid false completeness.
- Does **not** implement DPIAs, CE marking, or EU database registration—those remain organizational processes.

## ISO/IEC 42001 (AI management systems)

ISO/IEC 42001 emphasizes **context**, **leadership**, **planning**, **support**, **operation**, **performance evaluation**, and **improvement**. This repository contributes to **performance evaluation** (measurement methods, records, traceability of scores) and supports **operation** (repeatable CLI, CI, validation). Full 42001 alignment requires documented policies, roles, and management review beyond software.

## OWASP Top 10 for LLMs / MITRE ATLAS

See [threat_coverage.md](threat_coverage.md) for how red-team prompts relate to OWASP LLM and MITRE ATLAS-style labels on selected attacks.
