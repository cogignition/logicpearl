# Benchmarks

This file is the short benchmark summary for LogicPearl.

For workflow details, use:
- [DATASETS.md](./DATASETS.md)
- [benchmarks/guardrails/README.md](./benchmarks/guardrails/README.md)
- [docs/advanced-guardrail-guide.md](./docs/advanced-guardrail-guide.md)

## Current Public Story

Current headline benchmark lane:
- a guardrail development lane with held-out evaluation and post-freeze external stress tests

Separately, the repo also includes a small bounded OPA / Rego parity example:
- [benchmarks/opa_rego/README.md](./benchmarks/opa_rego/README.md)

That OPA example is useful as an additional parity walkthrough, but it is not the flagship public proof path and should not be blurred together with the guardrail benchmark story.

## Guardrail Development Lane

The current public guardrail development corpora are:
- `Salad-Data`
- `ALERT`
- `ChatGPT-Jailbreak-Prompts`
- `OpenAgentSafety`
- `MCPMark`
- `SafeArena`
- `Vigil`
- `NOETI ToxicQAFinal`
- `SQuAD 2.0`

Two important boundary notes:
- `PINT` is intentionally held back for final proof-only evaluation
- `MT-AgentRisk` is staged locally but still excluded from the public lane because access is gated on Hugging Face

## Held-Out Non-PINT Development Results

The public non-`PINT` guardrail workflow was run on a merged corpus of `210,515` rows and evaluated on a deterministic held-out development split of `42,468` rows.

Split:
- train: `168,047`
- dev: `42,468`

Held-out dev metrics for the learned artifact set:
- macro exact match: `99.9937%`
- macro positive recall: `100.0%`
- macro negative pass rate: `99.9937%`

Per target:
- `target_instruction_boundary`: exact match `100.0%`, positive recall `100.0%`, false positive rate `0.0%`
- `target_exfiltration`: exact match `99.9812%`, positive recall `100.0%`, false positive rate `0.0189%`
- `target_tool_use`: exact match `100.0%`, positive recall `100.0%`, false positive rate `0.0%`

The learned rules are also compact and inspectable:
- `target_instruction_boundary` -> `requests_instruction_override == 1`
- `target_exfiltration` -> `requests_secret_exfiltration == 1`
- `target_tool_use` -> `requests_tool_misuse == 1`

## Post-Freeze External Checks

After freezing the pre-`PINT` bundle, the same compiled guardrail artifact was evaluated on three open external benchmarks that were not part of the training bundle:
- `JailbreakBench`
- `PromptShield`
- `rogue-security/prompt-injections-benchmark`

Results:
- `JailbreakBench`: exact match `50.0%`, attack catch rate `2.0%`, benign pass rate `98.0%`
- `PromptShield`: exact match `67.878%`, attack catch rate `15.528%`, benign pass rate `99.774%`
- `rogue-security/prompt-injections-benchmark`: exact match `62.98%`, attack catch rate `8.138%`, benign pass rate `99.633%`

How to read those checks:
- `JailbreakBench` is not a clean apples-to-apples prompt-injection benchmark for the current guardrail bundle; many deny-labeled rows are broad harmful-task prompts rather than instruction-override or agent-boundary attacks
- `PromptShield` and `rogue-security/prompt-injections-benchmark` are closer to the intended task and show the current frozen bundle is conservative: very low false positives, much weaker recall on broader prompt-injection variants than on the public pre-`PINT` development corpora
- these are useful external stress tests, not headline replacement metrics for the current pre-`PINT` workflow

## What These Numbers Mean

These are honest development numbers, not final proof numbers.

Important caveats:
- the development corpus is merged from public datasets with different native schemas and label semantics
- LogicPearl first adapts those raw datasets into a common benchmark-case format
- LogicPearl then projects normalized observer features into the target labels used for discovery
- some route-level supervision comes directly from the source datasets, while some target-level supervision depends on the current observer contract and projection config

In practice:
- `instruction_boundary` is the cleanest target because several public prompt-injection corpora align naturally with it
- `exfiltration` and `tool_use` are still honest held-out results, but they depend more on the current observer contract and target projection config
- that is exactly why `PINT` remains the untouched final proof benchmark instead of being mixed into development

## Reproduce

For the low-level public held-out workflow:

```bash
logicpearl benchmark split-cases \
  /tmp/guardrail_dev.jsonl \
  --train-output /tmp/guardrail_train.jsonl \
  --dev-output /tmp/guardrail_dev_holdout.jsonl \
  --train-fraction 0.8

logicpearl benchmark learn \
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

For the full frozen-bundle refresh flow, use:

```bash
cargo xtask refresh-benchmarks
```

For the proof-only `PINT` scoring path after the bundle is frozen:

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

## What This Proves

These benchmark results show that the current public observer-plus-discovery path can:
- learn compact deterministic guardrail artifacts from public corpora
- preserve strong held-out performance on unseen non-`PINT` development traffic
- keep the learned rules inspectable instead of collapsing them into opaque classifiers

They do not yet prove:
- final proof-only benchmark performance
- coverage across every agent-security scenario
- performance on the access-gated `MT-AgentRisk` corpus
- that every current target label is a native gold annotation from the source datasets themselves
