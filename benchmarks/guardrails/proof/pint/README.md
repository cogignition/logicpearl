# PINT Proof Evaluation

`PINT` is the final proof benchmark for the public LogicPearl guardrail story.

It should remain:
- untouched during training
- untouched during threshold tuning
- untouched during route calibration

Use the public development corpora for building the system.

Use `PINT` once the observer, pearls, and route policy are frozen.

## Purpose

The public claim is not:
- "the system was tuned on PINT and then produced a good PINT score"

The public claim is:
- "the system was built on separate corpora, then PINT was used as the held-out final exam"

## Evaluation Path

```text
PINT raw row -> PINT adapter -> LogicPearl benchmark case -> observer -> pearls -> route -> scorer
```

## Rules

- do not run discovery on `PINT`
- do not tune thresholds on `PINT`
- do not change route mapping because of `PINT`
- freeze the pipeline before final scoring

## Inputs

The PINT adapter should emit the standard LogicPearl benchmark case shape defined in:
- [pint_case_schema.json](./pint_case_schema.json)

That keeps the core pipeline generic.

## Route Mapping

LogicPearl can keep rich internal routes like:
- `allow`
- `deny_untrusted_instruction`
- `deny_tool_use`
- `deny_exfiltration_risk`
- `needs_human_review`

For PINT scoring, collapse them into:
- `blocked`
- `passed`

Suggested rule:
- `allow` -> `passed`
- everything else -> `blocked`

## Frozen Bundle Path

Build and commit the frozen guardrail bundle first:

```bash
cargo xtask guardrails-build \
  --output-dir /tmp/guardrails_bundle
```

Then adapt raw `PINT` and run the frozen pipeline:

```bash
logicpearl benchmark adapt \
  "$LOGICPEARL_DATASETS/pint/PINT.yaml" \
  --profile pint \
  --output /tmp/pint_cases.jsonl

logicpearl benchmark run \
  benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json \
  /tmp/pint_cases.jsonl \
  --collapse-routes \
  --json
```

## Lower-Level Public CLI Path

If you want the lower-level public commands instead, start by adapting raw PINT YAML into LogicPearl benchmark-case JSONL:

```bash
logicpearl benchmark adapt \
  benchmarks/guardrails/proof/pint/example_pint.yaml \
  --profile pint \
  --output /tmp/pint_cases.jsonl
```

Then run the frozen guardrail pipeline with route collapse enabled:

```bash
logicpearl benchmark run \
  benchmarks/guardrails/examples/agent_guardrail/agent_guardrail.pipeline.json \
  /tmp/pint_cases.jsonl \
  --collapse-routes \
  --json
```

## Publishable Outputs

At minimum:
- benchmark date
- commit hash
- pipeline id
- artifact hashes
- PINT headline score

Recommended additional outputs:
- route distribution
- observer extraction success rate
- deterministic route coverage

## What To Freeze Before Final Run

- observer profile or observer artifact version
- feature contract
- pearls
- route policy
- benchmark adapter version

## Public Framing

Say:
- built on separate development corpora
- evaluated on untouched `PINT`

Do not say:
- trained on `PINT`
- tuned against `PINT`
