# Guardrail Scripts

These scripts make the public non-`PINT` and final-`PINT` guardrail workflow reproducible.

## Scripts

- `build_pre_pint_guardrail_bundle.py`
  - freezes deterministic per-dataset `dev` and `final_holdout` splits across all staged guardrail datasets
  - merges the per-dataset `dev` splits into one development pool
  - scaffolds a native observer artifact
  - synthesizes the guardrail signal families against the merged development pool through the `logicpearl observer synthesize` CLI
  - freezes the synthesized observer artifact used for development discovery
  - runs development-only discovery
  - scores the frozen artifact set once on the merged `final_holdout`
  - emits a frozen bundle with:
    - the observer artifact
    - the discovered artifact set
    - a derived combined pearl
    - a route policy
    - build and score manifests

- `evaluate_guardrail_bundle.py`
  - takes a frozen bundle plus a raw benchmark file such as `PINT`
  - adapts the raw benchmark cases
  - runs the frozen observer
  - evaluates the frozen combined pearl
  - emits case-by-case decisions, route labels, and counterfactual hints

- `run_open_guardrail_benchmarks.py`
  - runs the frozen bundle against staged open benchmarks
  - currently supports:
    - `JailbreakBench`
    - `PromptShield`
    - `rogue-security/prompt-injections-benchmark`
  - uses the frozen `dev` split by default
  - can also run the frozen `final_holdout` split once you are ready
  - writes per-benchmark reports plus one aggregate summary

- `freeze_guardrail_holdouts.py`
  - adapts all staged guardrail datasets through the public CLI
  - writes deterministic benchmark-case splits under each dataset directory:
    - `logicpearl_splits/<dataset_id>/dev.jsonl`
    - `logicpearl_splits/<dataset_id>/final_holdout.jsonl`
  - writes a split manifest so the holdout boundary is explicit

## Usage

Build the frozen pre-`PINT` bundle:

```bash
python3 scripts/guardrails/build_pre_pint_guardrail_bundle.py \
  --output-dir /tmp/guardrails_pre_pint_bundle
```

Evaluate untouched `PINT` against that bundle:

```bash
python3 scripts/guardrails/evaluate_guardrail_bundle.py \
  --bundle-dir /tmp/guardrails_pre_pint_bundle \
  --raw-benchmark ~/Documents/LogicPearl/datasets/public/pint/PINT.yaml \
  --profile pint \
  --output-dir /tmp/guardrails_pre_pint_bundle/pint_eval
```

Run the same frozen bundle against the staged open post-freeze benchmarks:

```bash
python3 scripts/guardrails/run_open_guardrail_benchmarks.py \
  --bundle-dir /tmp/guardrails_pre_pint_bundle \
  --output-dir /tmp/guardrails_pre_pint_bundle/open_benchmarks
```

Freeze development and final-holdout splits for all staged guardrail datasets:

```bash
python3 scripts/guardrails/freeze_guardrail_holdouts.py
```

Later, when you are ready for a final untouched external check, run the frozen holdout split explicitly:

```bash
python3 scripts/guardrails/run_open_guardrail_benchmarks.py \
  --bundle-dir /tmp/guardrails_pre_pint_bundle \
  --input-split final_holdout \
  --output-dir /tmp/guardrails_pre_pint_bundle/open_benchmarks_final_holdout
```

## Important Boundary

The frozen bundle keeps two related but different things:

- source-of-truth artifact discovery outputs:
  - observer artifact
  - specialized target pearls
  - held-out artifact-set score

- a derived single combined pearl:
  - easier to ship as one deployable artifact
  - carries route labels, messages, and counterfactual hints

The current combined pearl is a deployment artifact, not the main development metric. The most honest held-out development score still comes from the frozen artifact set evaluated against the held-out target traces.
