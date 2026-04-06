# Guardrail Preparation

This is the non-`PINT` preparation path for LogicPearl guardrail work.

Use public development corpora here:
- `Salad-Data`
- `ALERT`
- `OpenAgentSafety`
- `MCPMark`
- `SafeArena`
- `Vigil`
- `ChatGPT-Jailbreak-Prompts`
- `NOETI ToxicQAFinal`
- `SQuAD 2.0`

Do not use `PINT` here.

Recommended staged dataset root:

```text
$LOGICPEARL_DATASETS
```

Recommended:

```bash
export LOGICPEARL_DATASETS="$HOME/logicpearl-datasets/public"
```

If unset, the checked-in guardrail scripts fall back to `../datasets/public` relative to the cloned `logicpearl/` repo.

Recommended local staging path for full ALERT runs:

```text
$LOGICPEARL_DATASETS/alert/
```

Recommended local filenames:
- `ALERT.jsonl`
- `ALERT_Adv.jsonl`

Recommended source:
- Official ALERT repository: `https://github.com/Babelscape/ALERT`

Recommended local staging path for full SQuAD 2.0 runs:

```text
$LOGICPEARL_DATASETS/squad/
```

Recommended local filenames:
- `train-v2.0.json`
- `dev-v2.0.json`

Recommended local staging paths for the remaining public development corpora:

```text
$LOGICPEARL_DATASETS/chatgpt_jailbreak/
$LOGICPEARL_DATASETS/vigil/
$LOGICPEARL_DATASETS/noeti_toxicqa/
$LOGICPEARL_DATASETS/openagentsafety/
$LOGICPEARL_DATASETS/mcpmark/
```

Additional staged corpora for agent tool-use evaluation:

```text
$LOGICPEARL_DATASETS/mt_agentrisk/
$LOGICPEARL_DATASETS/safearena/
```

Current access note:
- `MT-AgentRisk` is still gated on Hugging Face
- `SafeArena` is available locally and wired into the public non-`PINT` workflow

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
- `logicpearl benchmark list-profiles`
- `logicpearl benchmark detect-profile`
- `logicpearl benchmark observe`
- `logicpearl benchmark emit-traces`
- `logicpearl benchmark adapt-pint`
- the public guardrail observer/pipeline examples

Useful native observer commands:
- `logicpearl observer list`
- `logicpearl observer scaffold`
- `logicpearl observer synthesize`
- `logicpearl observer repair`

`observer synthesize` is seed-based and Z3-first:
- start from a built-in or scaffolded signal family
- mine deterministic candidates from matched denied cases
- let Z3 select a compact subset
- by default, hold out a deterministic development slice and let LogicPearl choose the smallest near-best candidate cap automatically
- if you already have an explicit dev split, pass `--dev-benchmark-cases` and LogicPearl will use that instead of auto-splitting

## Current Public Adapter Path

Attack `Salad-Data base_set`:

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
  "$LOGICPEARL_DATASETS/alert/ALERT_Adv.jsonl" \
  --profile alert \
  --output /tmp/alert_attack.jsonl
```

Attack `ChatGPT-Jailbreak-Prompts`:

```bash
logicpearl benchmark adapt \
  "$LOGICPEARL_DATASETS/chatgpt_jailbreak/chatgpt_jailbreak_prompts.json" \
  --profile chatgpt-jailbreak-prompts \
  --output /tmp/chatgpt_jailbreak_attack.jsonl
```

Attack `Vigil`:

```bash
logicpearl benchmark adapt \
  "$LOGICPEARL_DATASETS/vigil/vigil.json" \
  --profile vigil \
  --output /tmp/vigil_attack.jsonl
```

Attack `NOETI ToxicQAFinal`:

```bash
logicpearl benchmark adapt \
  "$LOGICPEARL_DATASETS/noeti_toxicqa/noeti_toxicqa.json" \
  --profile noeti-toxicqa \
  --output /tmp/noeti_attack.jsonl
```

Attack `OpenAgentSafety`:

```bash
logicpearl benchmark adapt \
  "$LOGICPEARL_DATASETS/openagentsafety/openagentsafety_s26.json" \
  --profile openagentsafety-s26 \
  --output /tmp/openagentsafety_attack.jsonl
```

Benign `MCPMark`:

```bash
logicpearl benchmark adapt \
  "$LOGICPEARL_DATASETS/mcpmark/mcpmark_tasks.json" \
  --profile mcpmark \
  --output /tmp/mcpmark_benign.jsonl
```

Benign `SafeArena`:

```bash
logicpearl benchmark adapt \
  "$LOGICPEARL_DATASETS/safearena/safe.json" \
  --profile safearena-safe \
  --output /tmp/safearena_safe.jsonl
```

Attack `SafeArena`:

```bash
logicpearl benchmark adapt \
  "$LOGICPEARL_DATASETS/safearena/harm.json" \
  --profile safearena-harm \
  --output /tmp/safearena_harm.jsonl
```

Benign `SQuAD 2.0`:

```bash
logicpearl benchmark adapt \
  "$LOGICPEARL_DATASETS/squad/train-v2.0.json" \
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

Small checked-in attack samples for the other corpora:

```bash
logicpearl benchmark adapt \
  benchmarks/guardrails/prep/example_chatgpt_jailbreak_prompts.json \
  --profile chatgpt-jailbreak-prompts \
  --output /tmp/chatgpt_jailbreak_sample.jsonl

logicpearl benchmark adapt \
  benchmarks/guardrails/prep/example_vigil.json \
  --profile vigil \
  --output /tmp/vigil_sample.jsonl

logicpearl benchmark adapt \
  benchmarks/guardrails/prep/example_noeti_toxicqa.json \
  --profile noeti-toxicqa \
  --output /tmp/noeti_sample.jsonl

logicpearl benchmark adapt \
  benchmarks/guardrails/prep/example_openagentsafety_s26.json \
  --profile openagentsafety-s26 \
  --output /tmp/openagentsafety_sample.jsonl

logicpearl benchmark adapt \
  benchmarks/guardrails/prep/example_mcpmark_tasks.json \
  --profile mcpmark \
  --output /tmp/mcpmark_sample.jsonl

logicpearl benchmark adapt \
  benchmarks/guardrails/prep/example_safearena_safe.json \
  --profile safearena-safe \
  --output /tmp/safearena_safe_sample.jsonl

logicpearl benchmark adapt \
  benchmarks/guardrails/prep/example_safearena_harm.json \
  --profile safearena-harm \
  --output /tmp/safearena_harm_sample.jsonl
```

Merge benign and attack slices into one development set:

```bash
logicpearl benchmark merge-cases \
  /tmp/squad_benign.jsonl \
  /tmp/salad_base.jsonl \
  /tmp/alert_attack.jsonl \
  --output /tmp/guardrail_dev.jsonl
```

Observe those adapted rows:

```bash
logicpearl benchmark observe \
  /tmp/guardrail_dev.jsonl \
  --output /tmp/guardrail_dev_observed.jsonl
```

If the input shape matches a built-in native observer profile, LogicPearl detects and uses it automatically. Use `--observer-artifact` to pin a scaffolded observer artifact, or `--plugin-manifest` only when you truly need an external observer.

Then project them into discovery-ready traces:

```bash
logicpearl benchmark emit-traces \
  /tmp/guardrail_dev_observed.jsonl \
  --config benchmarks/guardrails/prep/trace_projection.guardrails_v1.json \
  --output-dir /tmp/guardrail_traces
```

Or run the generic middle stage in one shot:

```bash
logicpearl benchmark prepare \
  /tmp/guardrail_dev.jsonl \
  --config benchmarks/guardrails/prep/trace_projection.guardrails_v1.json \
  --output-dir /tmp/guardrail_prep \
  --json
```

## Honest Held-Out Evaluation

Do not use the `training_parity` inside `benchmark prepare` as the headline number.

For a real non-`PINT` evaluation:

1. split the merged benchmark cases into deterministic `train` and `dev`
2. run `benchmark prepare` only on `train`
3. observe and emit traces for untouched `dev`
4. score the discovered artifact set against the held-out `dev` traces

Example:

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

## Frozen Pre-PINT Bundle

For the public proof flow, the preferred source-of-truth is still a string of pearls:
- one frozen observer artifact
- one frozen discovered artifact set
- an explicit route policy over the specialized target pearls

To make that easy to rerun and audit, the repo also ships a higher-level builder:

```bash
python3 scripts/guardrails/build_pre_pint_guardrail_bundle.py \
  --output-dir /tmp/guardrails_pre_pint_bundle
```

That script:
- adapts every staged non-`PINT` public corpus
- merges them into one train/dev benchmark set
- freezes the observer artifact used for training
- discovers the target pearls on train only
- scores them on held-out dev
- copies the frozen artifact set into one bundle
- derives one combined pearl with route labels, messages, and counterfactual hints

The frozen bundle is what should be committed before any final `PINT` run.
