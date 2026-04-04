# Guardrail Benchmark Layout

This folder defines the public LogicPearl shape for guardrail benchmarking.

The goal is not to train on a benchmark and then brag about the benchmark. The goal is:
- build on broad public corpora
- tune on a held-out development slice
- prove generalization on an untouched proof set

## Dataset Roles

Development corpora:
- `Salad-Data`
- `ChatGPT-Jailbreak-Prompts`
- `Vigil: LLM Jailbreak embeddings`
- `ALERT Adverserial`
- `NOETI ToxicQAFinal`
- `SQuAD 2.0`

Proof-only corpus:
- `PINT`

## Directory Shape

```text
benchmarks/guardrails/
  README.md
  guardrail_benchmark.manifest.json
  datasets/
    train/
      prompt_injection/
      moderation/
      benign_negative/
    dev/
      prompt_injection/
      moderation/
      benign_negative/
    proof/
      pint/
  examples/
    agent_guardrail/
```

## Category Intent

- `prompt_injection/`: jailbreaks, indirect injections, instruction hijacks, tool-misuse prompts
- `moderation/`: harmful-content pressure that should still map to explicit route policy
- `benign_negative/`: false-positive control traffic that should mostly pass

## Why `PINT` Lives In `proof/`

`PINT` is the final proof set, not a tuning set.

Use the six public corpora above to build and calibrate the LogicPearl pipeline. Then run `PINT` once you want a defensible headline result.

Proof design:
- [proof/pint/README.md](./proof/pint/README.md)
- [proof/pint/pint_case_schema.json](./proof/pint/pint_case_schema.json)
- [proof/pint/pint_adapter_spec.json](./proof/pint/pint_adapter_spec.json)

Non-proof preparation:
- [prep/README.md](./prep/README.md)

## Recommended LogicPearl Metrics

- `attack_catch_rate`
- `false_positive_rate`
- `benign_pass_rate`
- `review_rate`
- `observer_extraction_success_rate`
- `deterministic_route_coverage`

## Feature Contract

Public normalized feature contract:
- [feature_contract.json](./feature_contract.json)

Discovery notes:
- [discovery/README.md](./discovery/README.md)

## Recommended Public Example

The first flagship benchmark should be an agent guardrail pipeline:

- observer extracts tool intent, source trust, and side effects
- pearls enforce authorization, injection boundary, and exfiltration policy
- final route is `allow`, `deny`, or `needs_human_review`

That shape is where LogicPearl is strongest.

See:
- [examples/agent_guardrail/README.md](./examples/agent_guardrail/README.md)
- [examples/agent_guardrail/discovery/README.md](./examples/agent_guardrail/discovery/README.md)

To score a dataset slice against a pipeline, use:

```bash
logicpearl benchmark run \
  benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json \
  benchmarks/guardrails/examples/agent_guardrail/dev_cases.jsonl
```
