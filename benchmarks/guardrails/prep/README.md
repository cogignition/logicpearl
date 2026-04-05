# Guardrail Preparation

This is the non-`PINT` preparation path for LogicPearl guardrail work.

Use public development corpora here:
- `Salad-Data`
- `ALERT`
- `Vigil`
- `ChatGPT-Jailbreak-Prompts`
- `NOETI ToxicQAFinal`
- `SQuAD 2.0`

Do not use `PINT` here.

Recommended local staging path for full ALERT runs:

```text
~/Documents/LogicPearl/datasets/public/alert/
```

Recommended local filenames:
- `ALERT.jsonl`
- `ALERT_Adv.jsonl`

Recommended source:
- Official ALERT repository: `https://github.com/Babelscape/ALERT`

Recommended local staging path for full SQuAD 2.0 runs:

```text
~/Documents/LogicPearl/datasets/public/squad/
```

Recommended local filenames:
- `train-v2.0.json`
- `dev-v2.0.json`

## Workflow

The intended automated flow is:

```text
raw dataset -> adapter -> benchmark cases -> observer -> normalized features -> discovery traces -> pearls -> dev scoring
```

## Explicit Inputs

Automation still needs explicit contracts:
- adapter
- observer
- feature contract
- target configuration

That is the right LogicPearl shape:
- explicit boundaries
- automated artifact generation

## Long-Term Command Shape

```bash
logicpearl prepare guardrails \
  --dataset raw_salad.jsonl \
  --adapter salad \
  --observer observers/guardrail_observer.json \
  --targets instruction_boundary,tool_authorization,data_exfiltration \
  --dev-dataset squad.jsonl \
  --output-dir /tmp/logicpearl-guardrails
```

This command is not implemented yet.

Today, the public pieces already in place are:
- `logicpearl discover`
- `logicpearl benchmark run`
- `logicpearl benchmark adapt`
- `logicpearl benchmark adapt-salad`
- `logicpearl benchmark adapt-alert`
- `logicpearl benchmark adapt-squad`
- `logicpearl benchmark observe`
- `logicpearl benchmark emit-traces`
- `logicpearl benchmark adapt-pint`
- the public guardrail observer/pipeline examples

Useful native observer commands:
- `logicpearl observer list`
- `logicpearl observer scaffold`
- `logicpearl observer repair`

## Current Public Adapter Path

Benign `Salad-Data base_set`:

```bash
logicpearl benchmark adapt \
  benchmarks/guardrails/prep/example_salad_base_set.json \
  --profile salad-base-set \
  --output /tmp/salad_base.jsonl
```

Attack `Salad-Data attack_enhanced_set`:

```bash
logicpearl benchmark adapt \
  benchmarks/guardrails/prep/example_salad_attack_enhanced_set.json \
  --profile salad-attack-enhanced-set \
  --output /tmp/salad_attack.jsonl
```

Attack `ALERT`:

```bash
logicpearl benchmark adapt \
  ~/Documents/LogicPearl/datasets/public/alert/ALERT_Adv.jsonl \
  --profile alert \
  --output /tmp/alert_attack.jsonl
```

Benign `SQuAD 2.0`:

```bash
logicpearl benchmark adapt \
  ~/Documents/LogicPearl/datasets/public/squad/train-v2.0.json \
  --profile squad \
  --output /tmp/squad_benign.jsonl
```

Small checked-in benign sample:

```bash
logicpearl benchmark adapt \
  benchmarks/guardrails/prep/example_squad_v2.json \
  --profile squad \
  --output /tmp/squad_benign_sample.jsonl
```

Small checked-in sample:

```bash
logicpearl benchmark adapt \
  benchmarks/guardrails/prep/example_alert_attack.json \
  --profile alert \
  --output /tmp/alert_attack_sample.jsonl
```

Merge benign and attack slices into one development set:

```bash
logicpearl benchmark merge-cases \
  /tmp/squad_benign.jsonl \
  /tmp/alert_attack.jsonl \
  --output /tmp/salad_dev.jsonl
```

Observe those adapted rows:

```bash
logicpearl benchmark observe \
  /tmp/salad_dev.jsonl \
  --output /tmp/salad_dev_observed.jsonl
```

If the input shape matches a built-in native observer profile, LogicPearl detects and uses it automatically. Use `--observer-artifact` to pin a scaffolded observer artifact, or `--plugin-manifest` only when you truly need an external observer.

Then project them into discovery-ready traces:

```bash
logicpearl benchmark emit-traces \
  /tmp/salad_dev_observed.jsonl \
  --config benchmarks/guardrails/prep/trace_projection.guardrails_v1.json \
  --output-dir /tmp/guardrail_traces
```

Or run the generic middle stage in one shot:

```bash
logicpearl benchmark prepare \
  /tmp/salad_dev.jsonl \
  --config benchmarks/guardrails/prep/trace_projection.guardrails_v1.json \
  --output-dir /tmp/guardrail_prep \
  --json
```

The internal workflow design is documented in:
- [/Users/missingno/Documents/LogicPearl/internal_docs/logicpearl/guardrail-prep-workflow.md](/Users/missingno/Documents/LogicPearl/internal_docs/logicpearl/guardrail-prep-workflow.md)
