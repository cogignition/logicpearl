# Guardrail Scripts

These scripts make the public non-`PINT` and final-`PINT` guardrail workflow reproducible.

Dataset sources, expected local staging paths, and the full split/build/eval flow are documented in:
- [DATASETS.md](../../DATASETS.md)

These scripts honor `LOGICPEARL_DATASETS` as the staged dataset root. If it is unset, they fall back to `../datasets/public` relative to the cloned `logicpearl/` repo.

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
  - can deterministically subsample large benchmark splits for fast regression checks
  - can compare sampled results against a checked-in baseline and fail on regressions
  - automatically selects a goal-specific sampled baseline from the bundle manifest when available
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

Build the same bundle with a guardrail-specific synthesis goal:

```bash
python3 scripts/guardrails/build_pre_pint_guardrail_bundle.py \
  --output-dir /tmp/guardrails_pre_pint_bundle \
  --target-goal protective-gate
```

Evaluate untouched `PINT` against that bundle:

```bash
python3 scripts/guardrails/evaluate_guardrail_bundle.py \
  --bundle-dir /tmp/guardrails_pre_pint_bundle \
  --raw-benchmark "$LOGICPEARL_DATASETS/pint/PINT.yaml" \
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

For a faster regression check that avoids a full rebuild and avoids scoring every case on large benchmarks:

```bash
python3 scripts/guardrails/run_open_guardrail_benchmarks.py \
  --bundle-dir /tmp/guardrails_pre_pint_bundle \
  --input-split final_holdout \
  --sample-size 200 \
  --output-dir /tmp/guardrails_pre_pint_bundle/open_benchmarks_sample200
```

If a checked-in sampled baseline is present, the runner uses it automatically for sampled runs. It prefers a goal-specific file such as:
- `scripts/guardrails/open_guardrail_regression_baseline.sample200.protective-gate.json`
- `scripts/guardrails/open_guardrail_regression_baseline.sample200.parity-first.json`

If no goal-specific file exists, it falls back to:
- `scripts/guardrails/open_guardrail_regression_baseline.sample200.json`

The runner exits non-zero if:
- `exact_match_rate` drops
- `attack_catch_rate` drops
- `benign_pass_rate` drops
- `false_positive_rate` rises

Use `--tolerance` if you want a small amount of slack around the recorded baseline.

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
