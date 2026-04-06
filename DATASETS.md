# Datasets

This file is the public guide for the datasets used in the LogicPearl benchmark and guardrail workflows.

It answers four things:
- where the datasets come from
- where LogicPearl expects them locally
- how to freeze deterministic `dev` and `final_holdout` splits
- how to evaluate the frozen bundle reproducibly with the checked-in scripts

## Local Staging Root

The public guardrail scripts resolve staged datasets from:

```text
$LOGICPEARL_DATASETS
```

Recommended:

```bash
export LOGICPEARL_DATASETS="$HOME/logicpearl-datasets/public"
```

If `LOGICPEARL_DATASETS` is unset, the scripts fall back to `../datasets/public` relative to the cloned `logicpearl/` repo directory.

That is the root used by:
- [scripts/guardrails/freeze_guardrail_holdouts.py](./scripts/guardrails/freeze_guardrail_holdouts.py)
- [scripts/guardrails/build_pre_pint_guardrail_bundle.py](./scripts/guardrails/build_pre_pint_guardrail_bundle.py)
- [scripts/guardrails/run_open_guardrail_benchmarks.py](./scripts/guardrails/run_open_guardrail_benchmarks.py)
- [scripts/guardrails/evaluate_guardrail_bundle.py](./scripts/guardrails/evaluate_guardrail_bundle.py)

## Development Corpora

These are the public corpora used for development and frozen holdouts before any final proof-only run.

| Dataset | Source | Expected local file |
|---|---|---|
| `SQuAD 2.0` | https://rajpurkar.github.io/SQuAD-explorer/ | `$LOGICPEARL_DATASETS/squad/train-v2.0.json` |
| `ALERT` | https://github.com/Babelscape/ALERT | `$LOGICPEARL_DATASETS/alert/ALERT.jsonl` |
| `ALERT_Adv` | https://github.com/Babelscape/ALERT | `$LOGICPEARL_DATASETS/alert/ALERT_Adv.jsonl` |
| `Salad-Data base_set` | https://huggingface.co/datasets/OpenSafetyLab/Salad-Data | `$LOGICPEARL_DATASETS/salad/base_set.json` |
| `Salad-Data attack_enhanced_set` | https://huggingface.co/datasets/OpenSafetyLab/Salad-Data | `$LOGICPEARL_DATASETS/salad/attack_enhanced_set.json` |
| `ChatGPT-Jailbreak-Prompts` | https://huggingface.co/datasets/rubend18/ChatGPT-Jailbreak-Prompts | `$LOGICPEARL_DATASETS/chatgpt_jailbreak/chatgpt_jailbreak_prompts.json` |
| `Vigil` | https://huggingface.co/datasets/deadbits/vigil-jailbreak-ada-002 | `$LOGICPEARL_DATASETS/vigil/vigil.json` |
| `NOETI ToxicQAFinal` | https://huggingface.co/datasets/NobodyExistsOnTheInternet/ToxicQAFinal | `$LOGICPEARL_DATASETS/noeti_toxicqa/noeti_toxicqa.json` |
| `OpenAgentSafety S26` | https://huggingface.co/datasets/mgulavani/openagentsafety_S26 | `$LOGICPEARL_DATASETS/openagentsafety/openagentsafety_s26.json` |
| `MCPMark` | https://github.com/eval-sys/mcpmark | `$LOGICPEARL_DATASETS/mcpmark/mcpmark_tasks.json` |
| `SafeArena safe` | https://huggingface.co/datasets/McGill-NLP/safearena | `$LOGICPEARL_DATASETS/safearena/safe.json` |
| `SafeArena harm` | https://huggingface.co/datasets/McGill-NLP/safearena | `$LOGICPEARL_DATASETS/safearena/harm.json` |

## Open External Evaluation Corpora

These are useful as external benchmark checks for the frozen guardrail bundle.

| Dataset | Source | Expected local file |
|---|---|---|
| `JailbreakBench` | https://github.com/JailbreakBench/jailbreakbench | `$LOGICPEARL_DATASETS/jailbreakbench/jbb_behaviors.json` |
| `PromptShield` | https://huggingface.co/datasets/hendzh/PromptShield | `$LOGICPEARL_DATASETS/promptshield/promptshield.json` |
| `rogue-security/prompt-injections-benchmark` | https://huggingface.co/datasets/rogue-security/prompt-injections-benchmark | `$LOGICPEARL_DATASETS/rogue_security/prompt_injections_benchmark.json` |

## Access-Gated Corpora

These are relevant to the same workflow but may require explicit access approval:

| Dataset | Source | Expected local file |
|---|---|---|
| `PINT` | https://github.com/lakeraai/pint-benchmark | `$LOGICPEARL_DATASETS/pint/PINT.yaml` |
| `MT-AgentRisk` single-turn | https://huggingface.co/datasets/CHATS-Lab/MT-AgentRisk | `$LOGICPEARL_DATASETS/mt_agentrisk/single_dataset.csv` |
| `MT-AgentRisk` multi-turn | https://huggingface.co/datasets/CHATS-Lab/MT-AgentRisk | `$LOGICPEARL_DATASETS/mt_agentrisk/multi_dataset.csv` |

`PINT` is not publicly downloadable in full from the benchmark repo. The public notebook says access must be requested from Lakera.

## Freeze `dev` And `final_holdout`

Once the raw datasets are staged under the expected local paths, freeze deterministic per-dataset splits with:

```bash
python3 scripts/guardrails/freeze_guardrail_holdouts.py
```

That writes:

```text
<dataset_parent>/logicpearl_splits/<dataset_id>/
  dev.jsonl
  final_holdout.jsonl
```

and a split manifest that records the boundary.

This is the cleanest public protocol:
- develop on merged `dev`
- keep `final_holdout` for frozen evaluation

## Build The Frozen Bundle

After the per-dataset splits exist:

```bash
python3 scripts/guardrails/build_pre_pint_guardrail_bundle.py \
  --output-dir /tmp/guardrails_pre_pint_bundle
```

That script:
- merges all per-dataset `dev` splits
- scaffolds and synthesizes the observer through the public CLI
- discovers the guardrail artifact set
- scores the artifact set once on merged `final_holdout`
- emits a frozen bundle containing:
  - observer artifact
  - discovered artifact set
  - derived combined pearl
  - route policy
  - manifests and hashes

## Evaluate The Frozen Bundle

### Run the open external evaluation corpora

```bash
python3 scripts/guardrails/run_open_guardrail_benchmarks.py \
  --bundle-dir /tmp/guardrails_pre_pint_bundle \
  --input-split final_holdout \
  --output-dir /tmp/guardrails_pre_pint_bundle/open_benchmarks_final_holdout
```

For a faster sampled regression check:

```bash
python3 scripts/guardrails/run_open_guardrail_benchmarks.py \
  --bundle-dir /tmp/guardrails_pre_pint_bundle \
  --input-split final_holdout \
  --sample-size 200 \
  --output-dir /tmp/guardrails_pre_pint_bundle/open_benchmarks_sample200
```

### Run a raw benchmark file such as `PINT`

```bash
python3 scripts/guardrails/evaluate_guardrail_bundle.py \
  --bundle-dir /tmp/guardrails_pre_pint_bundle \
  --raw-benchmark "$LOGICPEARL_DATASETS/pint/PINT.yaml" \
  --profile pint \
  --output-dir /tmp/guardrails_pre_pint_bundle/pint_eval
```

That:
- adapts the raw benchmark file
- runs the frozen observer
- runs the frozen compiled combined pearl
- emits case-level decisions, route labels, messages, and counterfactual hints

## Public Contract

The public repo does not vendor these external datasets into git.

Instead it provides:
- adapter profiles
- deterministic split and evaluation scripts
- expected local paths
- reproducible commands

That keeps the benchmark story honest and makes it easy for a fresh clone to reproduce the workflow once the datasets are staged locally.
