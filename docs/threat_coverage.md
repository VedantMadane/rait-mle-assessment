# Threat coverage matrix (red team)

## Summary

The synthetic catalog in `data/red_team/attacks.json` is a **starting set**, not a complete threat model. Entries `rt-025` and `rt-026`, plus `rt-024`, include explicit `atlas_id` and `owasp_id` fields. Older entries (`rt-001`–`rt-023`) omit these keys in JSON; their implied mapping by **category** is:

| Category | Representative MITRE ATLAS | Representative OWASP LLM |
|----------|----------------------------|---------------------------|
| `prompt_injection` | AML.T0051 (prompt injection family) | LLM01 Prompt injection |
| `jailbreak` | AML.T0051 | LLM01 |
| `information_extraction` | AML.T0024 (illustrative exfiltration / probing) | LLM06 Sensitive information disclosure |
| `policy_contradiction` | AML.T0051 | LLM09 Overreliance / unsafe policy reasoning |

## Explicitly tagged attacks

| attack_id | atlas_id | owasp_id | Notes |
|-----------|----------|----------|--------|
| rt-024 | AML.T0051 | LLM09 | Policy contradiction / proof-of-understanding trap |
| rt-025 | AML.T0024 | LLM06 | Social engineering + credential harvesting |
| rt-026 | AML.T0051 | LLM01 | Fake system override |

## Gaps

- **Latent space**: Dozens of static prompts cannot cover all paraphrases, languages, or tool-calling paths.
- **Multi-turn** and **indirect** injection are underrepresented.
- **Supply chain** and **training-data** attacks (ATLAS / OWASP categories) are out of scope for this interaction-only harness.

Use `red_team.expand_mutations: true` in `config/assessment.yaml` to multiply prompts deterministically via `expand_attack_patterns` before retrieval.
