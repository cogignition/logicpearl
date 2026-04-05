# Guardrail Scripts

These scripts make the public non-`PINT` and final-`PINT` guardrail workflow reproducible.

## Scripts

- `build_pre_pint_guardrail_bundle.py`
  - adapts the staged public non-`PINT` corpora
  - merges and splits them into deterministic train/dev sets
  - scaffolds a native observer artifact
  - synthesizes the guardrail signal families against the non-`PINT` train/dev split through the `logicpearl observer synthesize` CLI
  - freezes the synthesized observer artifact used for training
  - runs train-only discovery
  - scores the frozen artifact set on held-out dev
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
  - runs the frozen bundle against staged open post-freeze benchmarks
  - currently supports:
    - `JailbreakBench`
    - `PromptShield`
    - `rogue-security/prompt-injections-benchmark`
  - writes per-benchmark reports plus one aggregate summary

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
