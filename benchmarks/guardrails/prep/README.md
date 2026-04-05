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
- `logicpearl benchmark adapt-salad`
- `logicpearl benchmark adapt-alert`
- `logicpearl benchmark observe`
- `logicpearl benchmark emit-traces`
- `logicpearl benchmark adapt-pint`
- the public guardrail observer/pipeline examples

## Current Public Adapter Path

Benign `Salad-Data base_set`:

```bash
logicpearl benchmark adapt-salad \
  benchmarks/guardrails/prep/example_salad_base_set.json \
  --subset base-set \
  --output /tmp/salad_base.jsonl
```

Attack `Salad-Data attack_enhanced_set`:

```bash
logicpearl benchmark adapt-salad \
  benchmarks/guardrails/prep/example_salad_attack_enhanced_set.json \
  --subset attack-enhanced-set \
  --output /tmp/salad_attack.jsonl
```

Attack `ALERT`:

```bash
logicpearl benchmark adapt-alert \
  benchmarks/guardrails/prep/example_alert_attack.json \
  --output /tmp/alert_attack.jsonl
```

Merge benign and attack slices into one development set:

```bash
logicpearl benchmark merge-cases \
  /tmp/salad_base.jsonl \
  /tmp/salad_attack.jsonl \
  --output /tmp/salad_dev.jsonl
```

Observe those adapted rows:

```bash
logicpearl benchmark observe \
  /tmp/salad_dev.jsonl \
  --plugin-manifest benchmarks/guardrails/examples/agent_guardrail/plugins/observer/manifest.json \
  --output /tmp/salad_dev_observed.jsonl
```

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
  --plugin-manifest benchmarks/guardrails/examples/agent_guardrail/plugins/observer/manifest.json \
  --config benchmarks/guardrails/prep/trace_projection.guardrails_v1.json \
  --output-dir /tmp/guardrail_prep \
  --json
```

The internal workflow design is documented in:
- [/Users/missingno/Documents/LogicPearl/internal_docs/logicpearl/guardrail-prep-workflow.md](/Users/missingno/Documents/LogicPearl/internal_docs/logicpearl/guardrail-prep-workflow.md)
