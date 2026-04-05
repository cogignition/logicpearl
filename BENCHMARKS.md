# Benchmarks

This file is the short benchmark summary for the public LogicPearl repo.

For the full workflow details, use:
- [benchmarks/guardrails/README.md](./benchmarks/guardrails/README.md)
- [docs/advanced-guardrail-guide.md](./docs/advanced-guardrail-guide.md)
- [scripts/guardrails/README.md](./scripts/guardrails/README.md)

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
- `OpenAgentSafety`
- `MCPMark`
- `SafeArena`
- `Vigil`
- `NOETI ToxicQAFinal`
- `SQuAD 2.0`

These are used for development only. `PINT` stays untouched until final proof.

One additional agent-safety corpus is staged locally but not included yet because it is access-gated on Hugging Face:
- `MT-AgentRisk`

### Held-out non-PINT evaluation

Using the public guardrail workflow, LogicPearl was run on a merged non-`PINT` corpus of `210,515` rows and then evaluated on a deterministic held-out dev split of `42,468` rows.

Train/dev split:
- train: `168,047`
- dev: `42,468`

Held-out dev results for the learned artifacts:
- macro exact match: `99.9937%`
- macro positive recall: `100.0%`
- macro negative pass rate: `99.9937%`

Per target:
- `target_instruction_boundary`
  - exact match: `100.0%`
  - positive recall: `100.0%`
  - false positive rate: `0.0%`
- `target_exfiltration`
  - exact match: `99.9812%`
  - positive recall: `100.0%`
  - false positive rate: `0.0189%`
- `target_tool_use`
  - exact match: `100.0%`
  - positive recall: `100.0%`
  - false positive rate: `0.0%`

The learned rules are also clean and inspectable:
- `target_instruction_boundary` -> `requests_instruction_override == 1`
- `target_exfiltration` -> `requests_secret_exfiltration == 1`
- `target_tool_use` -> `requests_tool_misuse == 1`

### Benchmark Boundaries

These are honest development numbers, not final proof numbers.

Important boundary notes:
- `PINT` is still untouched and reserved for final proof-only evaluation.
- The development corpus is merged from public datasets with different native schemas and labels.
- LogicPearl adapts those raw datasets into a common benchmark-case format, then projects observer features into the target labels used for discovery.
- In other words, route-level supervision comes from the source datasets, while some target-level supervision is a LogicPearl projection over the normalized observer contract.
- That means these results are a fair held-out evaluation of the current public LogicPearl workflow, but they are not the same thing as a single gold-standard benchmark with a native shared label ontology.

In practice:
- `instruction_boundary` is the cleanest target because several public prompt-injection corpora align naturally with it.
- `exfiltration` and `tool_use` are still honest, but they depend more on the current observer contract and target projection config.
- That is exactly why `PINT` remains the final untouched benchmark rather than being mixed into development.

## How To Reproduce

The lowest-level public benchmark commands are:

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

For the full frozen pre-`PINT` path, use the checked-in public scripts:

```bash
python3 scripts/guardrails/build_pre_pint_guardrail_bundle.py \
  --output-dir /tmp/guardrails_pre_pint_bundle

python3 scripts/guardrails/evaluate_guardrail_bundle.py \
  --bundle-dir /tmp/guardrails_pre_pint_bundle \
  --raw-benchmark ~/Documents/LogicPearl/datasets/public/pint/PINT.yaml \
  --profile pint \
  --output-dir /tmp/guardrails_pre_pint_bundle/pint_eval
```

That bundle path freezes:
- the staged public development corpora used for training
- the scaffolded observer artifact
- the discovered artifact set
- a derived combined pearl with route labels, messages, and counterfactual hints
- the route policy used to collapse the specialized pearls into final `allow` / `deny`

## What This Proves

These benchmark results show that the current public observer plus artifact-discovery path can:
- learn compact deterministic guardrail artifacts from public corpora
- preserve strong held-out performance on unseen dev traffic
- keep the learned rules inspectable instead of turning them into opaque classifiers

They do not yet prove:
- final `PINT` performance
- every possible agent-security scenario
- performance on the access-gated `MT-AgentRisk` corpus
- that every current target label is a native gold annotation from the source datasets themselves
