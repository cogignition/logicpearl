# Discovery Workspace

This directory contains the Python-side authoring and analysis tools for LogicPearl.

Use this workspace to:
- load and validate Pearl IR
- load and validate observer specs
- evaluate pearls against feature inputs
- execute observers over raw inputs
- render bitmask and heatmap outputs
- inspect OPA / Rego demo policies through the public domain adapter

The intended boundary is simple:
- `discovery/` prepares, validates, and emits pearls
- `runtime/` loads and evaluates pearls

## Main Areas

- `src/logicpearl/ir/`
  Pearl IR models, loaders, validation, and evaluation helpers.
- `src/logicpearl/observer/`
  Observer specs, feature contracts, loaders, and validation.
- `src/logicpearl/render/`
  SVG and HTML renderers for bitmask and heatmap output.
- `src/logicpearl/engine/`
  Shared engine helpers used across the public proof layer.
- `src/logicpearl/domains/opa/`
  Public OPA / Rego parsing and evaluation wrappers.
- `tests/`
  Public tests for IR, observers, renderers, engine helpers, and OPA parsing.

## Recommended Commands

Run these from `discovery/`:

### Run tests

```bash
uv run python -m pytest
```

### Evaluate a pearl directly

```bash
uv run logicpearl-discovery ../fixtures/ir/valid/auth-demo-v1.json ../fixtures/ir/eval/auth-demo-v1-deny-multiple-rules-input.json
```

### Execute an observer over raw input

```bash
uv run logicpearl-observe ../fixtures/observer/valid/auth-observer-v1.json ../fixtures/observer/eval/auth-observer-v1-sample-input.json
```

### Validate observer fixtures

```bash
uv run logicpearl-validate-observer ../fixtures/observer/eval/auth-observer-v1-cases.json
```

### Render the auth-demo bitmask

```bash
uv run logicpearl-render-bitmask --gate ../fixtures/ir/valid/auth-demo-v1.json --input ../fixtures/ir/eval/auth-demo-v1-deny-multiple-rules-input.json --output /tmp/auth-bitmask.svg
```

### Render the auth-demo heatmap

```bash
uv run logicpearl-render-bitmask --eval-fixture ../fixtures/ir/eval/auth-demo-v1-cases.json --output /tmp/auth-heatmap.svg
```

### Inspect the OPA demo policy

```bash
uv run logicpearl-opa-inspect ../benchmarks/opa_rego/policy.rego
```

### Run the OPA parity demo

```bash
uv run python ../benchmarks/opa_rego/run_benchmark.py
```

## What The Public Discovery Workspace Proves

This public slice is intended to prove:
- Pearl IR is real and inspectable
- observer specs and feature contracts are real
- pearls can be evaluated and rendered locally
- OPA / Rego parity can be demonstrated through a public adapter path
- the public workspace is useful on its own, not just a teaser

It is not intended to prove every private migration workflow or every high-consequence production deployment pattern.

## Notes On Scope

The public repository intentionally excludes:
- healthcare reconstruction workflows
- private datasets
- private migration heuristics
- enterprise approval/publish workflow

See:
- [Repository Architecture](../../AGENTS.md)
