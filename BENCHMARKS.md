# Benchmarks

This file is the short benchmark summary for the public LogicPearl repo.

For the full workflow details, use:
- [benchmarks/guardrails/README.md](./benchmarks/guardrails/README.md)
- [docs/advanced-guardrail-guide.md](./docs/advanced-guardrail-guide.md)

## Why This Matters

LogicPearl benchmark work is meant to show two things:
- the public artifact model can recover clean deterministic rules from real corpora
- the resulting artifacts still perform well on unseen data

The repo keeps that story honest:
- `train` for discovery
- `dev` for held-out evaluation
- `proof` for untouched final benchmarks such as `PINT`

`PINT` is intentionally held back for final proof-only evaluation.

## Current Highlights

### OPA parity demo

The repo includes a public parity/import benchmark that starts from an existing Rego policy and emits LogicPearl artifacts:
- [benchmarks/opa_rego/README.md](./benchmarks/opa_rego/README.md)

This is the clearest example of LogicPearl replacing a bounded logic slice with a smaller deterministic artifact while preserving behavior.

### Guardrail corpora

The current public guardrail development path uses:
- `Salad-Data`
- `ALERT`
- `ChatGPT-Jailbreak-Prompts`
- `Vigil`
- `NOETI ToxicQAFinal`
- `SQuAD 2.0`

These are used for development only. `PINT` stays untouched until final proof.

### Held-out non-PINT evaluation

Using the public guardrail workflow, LogicPearl was run on a merged non-`PINT` corpus of `209,417` rows and then evaluated on a deterministic held-out dev split of `42,134` rows.

Train/dev split:
- train: `167,283`
- dev: `42,134`

Held-out dev results for the learned artifacts:
- macro exact match: `99.9988%`
- macro positive recall: `100.0%`
- macro negative pass rate: `99.9988%`

Per target:
- `target_instruction_boundary`
  - exact match: `100.0%`
  - positive recall: `100.0%`
  - false positive rate: `0.0%`
- `target_exfiltration`
  - exact match: `99.9976%`
  - positive recall: `100.0%`
  - false positive rate: `0.0024%`

The learned rules are also clean and inspectable:
- `target_instruction_boundary` -> `requests_instruction_override == 1`
- `target_exfiltration` -> `requests_secret_exfiltration == 1`

`target_tool_use` is not included in the headline yet because the current public corpora do not provide clean denied tool-use labels.

## How To Reproduce

Use the public benchmark commands:

```bash
logicpearl benchmark split-cases \
  /tmp/guardrail_dev.jsonl \
  --train-output /tmp/guardrail_train.jsonl \
  --dev-output /tmp/guardrail_dev_holdout.jsonl \
  --train-fraction 0.8

logicpearl benchmark prepare \
  /tmp/guardrail_train.jsonl \
  --config benchmarks/guardrails/prep/trace_projection.guardrails_v1.json \
  --output-dir /tmp/guardrail_train_prep \
  --json

logicpearl benchmark observe \
  /tmp/guardrail_dev_holdout.jsonl \
  --output /tmp/guardrail_dev_holdout_observed.jsonl

logicpearl benchmark emit-traces \
  /tmp/guardrail_dev_holdout_observed.jsonl \
  --config benchmarks/guardrails/prep/trace_projection.guardrails_v1.json \
  --output-dir /tmp/guardrail_dev_holdout_traces

logicpearl benchmark score-artifacts \
  /tmp/guardrail_train_prep/discovered/artifact_set.json \
  /tmp/guardrail_dev_holdout_traces/multi_target.csv \
  --json
```

## What This Proves

These benchmark results show that the current public observer plus artifact-discovery path can:
- learn compact deterministic guardrail artifacts from public corpora
- preserve strong held-out performance on unseen dev traffic
- keep the learned rules inspectable instead of turning them into opaque classifiers

They do not yet prove:
- final `PINT` performance
- clean public `tool_use` supervision
- every possible agent-security scenario
