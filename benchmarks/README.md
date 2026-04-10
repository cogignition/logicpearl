# Benchmark Layout

LogicPearl benchmarks should separate development data from post-freeze external evaluation.

For guardrail work, the important split is:
- `train`: broad development corpus for building observers, pearls, and routes
- `dev`: held-out tuning set for threshold and false-positive work
- `external`: untouched post-freeze checks kept separate from development

The public guardrail benchmark layout lives in [guardrails](./guardrails/README.md).

Benchmark adapter profile schema and examples live in [profiles](./profiles/README.md).

Rules:
- do not tune on post-freeze external checks
- do not reuse external evaluation corpora as development data
- keep benign negatives separate from attack traffic
- track both attack catch rate and false-positive rate

Recommended public benchmark families:
- `opa_rego/` for a small bounded parity example against a fixed Rego policy
- `guardrails/`
- `waf/`
