# Benchmark Layout

LogicPearl benchmarks should separate development data from proof data.

For guardrail work, the important split is:
- `train`: broad development corpus for building observers, pearls, and routes
- `dev`: held-out tuning set for threshold and false-positive work
- `proof`: untouched final evaluation set

The public guardrail benchmark layout lives in [guardrails](./guardrails/README.md).

Benchmark adapter profile schema and examples live in [profiles](./profiles/README.md).

Rules:
- do not tune on `proof`
- do not use `PINT` as a development set
- keep benign negatives separate from attack traffic
- track both attack catch rate and false-positive rate

Recommended public benchmark families:
- `opa_rego/`
- `guardrails/`
- `waf/`
