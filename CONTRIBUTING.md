# Contributing

LogicPearl is intentionally small and architecture-sensitive.

The goal of contributions should be:
- make pearls easier to run, inspect, and validate
- improve the public IR/runtime/observer story
- keep the generic engine generic
- avoid blending benchmark-specific behavior into shared engine code

## Good Contribution Areas

- runtime improvements
- IR validation and tooling
- observer-spec improvements
- renderer improvements
- docs and examples
- public parity/import benchmarks
- test coverage

## Areas To Treat Carefully

- anything that introduces domain-specific logic into the generic engine
- benchmark-specific shortcuts presented as generic features
- broad changes to the artifact format without schema/runtime coordination
- public claims that overstate what a demo proves

## Development

### Python side

```bash
cd discovery
uv run python -m pytest
```

### Runtime side

```bash
cd runtime
cargo test
```

### OPA demo

Requires an `opa` binary on your path.

```bash
cd discovery
uv run logicpearl-opa-inspect ../benchmarks/opa_rego/policy.rego
uv run python ../benchmarks/opa_rego/run_benchmark.py
```

## Design Expectations

Please preserve these boundaries:

- `runtime/` is the deterministic evaluator
- `schema/` defines the public artifact contracts
- `discovery/` owns authoring, IR tooling, observer tooling, and public adapters
- benchmark/demo-specific logic should stay outside the generic engine when possible

## Before Opening A PR

Please make sure:
- tests pass
- new public docs are accurate and conservative
- performance claims are scoped clearly
- demo framing matches what the code actually does

## Commercial Boundary

This repository is the public proof layer for LogicPearl. It is meant to be real, useful, and exciting on its own.

The bigger commercial story is not “the real thing is hidden elsewhere.” The point is that this repo proves the artifact model in public, while the hardest migrations, domain reconstructions, and high-consequence decision systems are where the model becomes even more valuable.

If you want help applying LogicPearl to a real rules or policy system, use the public contact path rather than expecting every private migration workflow to live in this repository.
