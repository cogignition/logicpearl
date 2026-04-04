# Advanced Guardrail Guide

This guide documents the full LogicPearl guardrail workflow beyond the README quickstart.

Use it when you want to:
- prepare non-`PINT` guardrail corpora
- adapt raw benchmark datasets into LogicPearl cases
- run an observer over those cases
- emit discovery traces
- learn pearls from those traces
- score held-out development slices
- keep `PINT` untouched until the final proof run

## The Core Split

There are two different phases:

1. `Development`
- use public corpora such as `Salad-Data`, `ALERT`, `Vigil`, `ChatGPT-Jailbreak-Prompts`, `NOETI ToxicQAFinal`, and `SQuAD 2.0`
- learn and tune the system here

2. `Proof`
- use `PINT`
- do not train or tune on it

That distinction is the whole point.

## The Full Shape

```text
raw dataset -> adapter -> benchmark cases -> observer -> normalized features -> discovery traces -> pearls -> dev scoring -> frozen proof run
```

## Feature Contract

Public normalized feature contract:
- [benchmarks/guardrails/feature_contract.json](../benchmarks/guardrails/feature_contract.json)

This is the boundary between:
- messy benchmark text
- deterministic LogicPearl artifacts

## Phase 1: Adapt Non-PINT Data

The first public non-`PINT` adapter is `Salad-Data`.

Benign `base_set`:

```bash
logicpearl benchmark adapt-salad \
  benchmarks/guardrails/prep/example_salad_base_set.json \
  --subset base-set \
  --output /tmp/salad_base.jsonl
```

Attack `attack_enhanced_set`:

```bash
logicpearl benchmark adapt-salad \
  benchmarks/guardrails/prep/example_salad_attack_enhanced_set.json \
  --subset attack-enhanced-set \
  --output /tmp/salad_attack.jsonl
```

The adapted JSONL shape is a stable LogicPearl benchmark case:
- `id`
- `input`
- `expected_route`
- optional `category`

## Phase 2: Run the Observer

Run the guardrail observer over the adapted cases:

```bash
logicpearl benchmark observe \
  /tmp/salad_attack.jsonl \
  --plugin-manifest benchmarks/guardrails/examples/agent_guardrail/plugins/observer/manifest.json \
  --output /tmp/salad_attack_observed.jsonl
```

This emits rows that keep:
- benchmark metadata
- original input
- normalized observer features

## Phase 3: Emit Discovery Traces

Project observed rows into discovery-ready CSVs:

```bash
logicpearl benchmark emit-traces \
  /tmp/salad_attack_observed.jsonl \
  --output-dir /tmp/guardrail_traces
```

This emits:
- `multi_target.csv`
- `instruction_boundary_traces.csv`
- `data_exfiltration_traces.csv`
- `tool_authorization_traces.csv`
- `route_status_traces.csv`

This step is development-oriented. It projects target labels from:
- final expected route
- normalized observer features

That is acceptable for a public development workflow, but it is not the same thing as proof.

This command is generic on purpose:
- `observe` gives you normalized feature rows
- `emit-traces` turns those rows into discovery-ready tables

The target projection logic can evolve by profile or config later, but the CLI verb itself should stay general.

## Phase 4: Learn Pearls

Single-target example:

```bash
logicpearl build \
  /tmp/guardrail_traces/instruction_boundary_traces.csv \
  --output-dir /tmp/instruction_boundary
```

Multi-target example:

```bash
logicpearl discover \
  /tmp/guardrail_traces/multi_target.csv \
  --targets target_instruction_boundary,target_exfiltration,target_tool_use \
  --output-dir /tmp/guardrail_artifact_set
```

This emits:
- one pearl per target
- `artifact_set.json`
- `discover_report.json`

## Phase 5: Score Development Data

Once you have a pipeline or artifact set, score held-out development slices:

```bash
logicpearl benchmark run \
  benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json \
  benchmarks/guardrails/examples/agent_guardrail/dev_cases.jsonl \
  --json
```

Track:
- `attack_catch_rate`
- `benign_pass_rate`
- `false_positive_rate`
- `category_accuracy`

## Phase 6: Freeze and Run PINT

Only after the system is frozen:
- observer version
- feature contract
- pearls
- route mapping
- adapter version

then adapt and score `PINT`.

Adapt:

```bash
logicpearl benchmark adapt-pint \
  benchmarks/guardrails/proof/pint/example_pint.yaml \
  --output /tmp/pint_cases.jsonl
```

Score:

```bash
logicpearl benchmark run \
  benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json \
  /tmp/pint_cases.jsonl \
  --collapse-non-allow-to-deny \
  --json
```

That collapses rich internal routes into benchmark-facing:
- `allow`
- `deny`

## What Exists Today

Public pieces already available:
- `logicpearl benchmark adapt-salad`
- `logicpearl benchmark adapt-pint`
- `logicpearl benchmark observe`
- `logicpearl benchmark emit-traces`
- `logicpearl build`
- `logicpearl discover`
- `logicpearl benchmark run`
- public observer + pipeline examples

## Related Docs

- [Guardrail benchmarks](../benchmarks/guardrails/README.md)
- [Guardrail preparation](../benchmarks/guardrails/prep/README.md)
- [PINT proof evaluation](../benchmarks/guardrails/proof/pint/README.md)
