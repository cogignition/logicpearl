# Guardrail Scripts

These scripts make the public guardrail workflow reproducible.

Fast path:
- `cargo xtask refresh-benchmarks`

Additional `xtask` commands:
- `cargo xtask guardrails-freeze`
- `cargo xtask guardrails-build`
- `cargo xtask guardrails-eval`

The Python files in this folder remain as supplementary reference tooling.

Dataset sources, expected local staging paths, and the full split/build/eval flow are documented in:
- [DATASETS.md](../../DATASETS.md)

These scripts honor `LOGICPEARL_DATASETS` as the staged dataset root. If it is unset, they fall back to `../datasets/public` relative to the project root.

If the gated `MT-AgentRisk` dataset is staged at `$LOGICPEARL_DATASETS/mt_agentrisk/full_repo`, the freeze/build flow includes it automatically in the grouped guardrail bundle. If it is absent, the remaining workflow still runs.

## Scripts

- `build_guardrail_bundle.py`
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
  - supports:
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

For the full public refresh path, including guardrails, WAF, and scoreboard updates:

```bash
cargo xtask refresh-benchmarks
```

or from the project root:

```bash
scripts/refresh_all_benchmarks.sh
```

For guardrail-only maintenance flows, use these commands:

Build the frozen guardrail bundle:

```bash
cargo xtask guardrails-build \
  --output-dir /tmp/guardrails_bundle
```

Build the same bundle with a guardrail-specific synthesis goal:

```bash
cargo xtask guardrails-build \
  --output-dir /tmp/guardrails_bundle \
  --target-goal protective-gate
```

Build a faster deterministic subset bundle for quick iteration:

```bash
cargo xtask guardrails-build \
  --output-dir /tmp/guardrails_bundle_sample \
  --target-goal protective-gate \
  --dev-case-limit 20000 \
  --final-holdout-case-limit 4000
```

Those subset limits are route-stratified, so the smaller bundle keeps a stable mix of:
- `allow`
- `deny_untrusted_instruction`
- `deny_exfiltration_risk`
- `deny_tool_use`

Use `--resume` with the same output directory if the long synthesis step has already finished once.

Evaluate untouched `PINT` against that bundle:

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

Run the same frozen bundle against the staged open post-freeze benchmarks:

```bash
cargo xtask guardrails-eval \
  --bundle-dir /tmp/guardrails_bundle \
  --output-dir /tmp/guardrails_bundle/open_benchmarks
```

Freeze development and final-holdout splits for all staged guardrail datasets:

```bash
cargo xtask guardrails-freeze
```

Later, when you are ready for a final untouched external check, run the frozen holdout split explicitly:

```bash
cargo xtask guardrails-eval \
  --bundle-dir /tmp/guardrails_bundle \
  --input-split final_holdout \
  --output-dir /tmp/guardrails_bundle/open_benchmarks_final_holdout
```

For a faster regression check that avoids a full rebuild and avoids scoring every case on large benchmarks:

```bash
cargo xtask guardrails-eval \
  --bundle-dir /tmp/guardrails_bundle \
  --input-split final_holdout \
  --sample-size 200 \
  --output-dir /tmp/guardrails_bundle/open_benchmarks_sample200
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
