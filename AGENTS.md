# AGENTS.md

This file is for coding agents and automation tools working inside the public `logicpearl` repository.

## What This Repo Is

LogicPearl turns labeled behavior into deterministic deployable artifacts called `pearls`.

The public repo is meant to stand on its own. Treat it like a real product repository:
- keep generic engine code generic
- keep examples honest
- keep benchmark claims conservative
- prefer inspectable artifacts over hidden magic

## Fastest Valid Path

If you need to prove the repo works, start here:

```bash
cargo run --manifest-path Cargo.toml -p logicpearl -- \
  build examples/getting_started/decision_traces.csv \
  --output-dir /tmp/logicpearl-build
```

Then:

```bash
cargo run --manifest-path Cargo.toml -p logicpearl -- inspect /tmp/logicpearl-build
cargo run --manifest-path Cargo.toml -p logicpearl -- run /tmp/logicpearl-build examples/getting_started/new_input.json
```

The normal public artifact is a directory bundle, not just a raw `pearl.ir.json`.

## Preferred Public UX

Bias toward the simple CLI path:
- `logicpearl build ...`
- `logicpearl inspect ...`
- `logicpearl run ...`
- `logicpearl pipeline ...`
- `logicpearl benchmark ...`

If you add sophistication internally, keep the public command surface simple.

## Repository Boundaries

Keep these boundaries intact:
- `crates/logicpearl-cli`: user-facing Rust CLI crate, published as `logicpearl`
- `crates/logicpearl-ir`: public artifact structures
- `crates/logicpearl-runtime`: deterministic evaluation
- `crates/logicpearl-discovery`: discovery and refinement
- `crates/logicpearl-benchmark`: benchmark adaptation and scoring
- `examples/`: first-run examples and small demos
- `benchmarks/`: public benchmark assets and docs

Do not mix benchmark-specific hacks into generic engine code.

## What Good Changes Look Like

Good changes:
- improve first-run experience
- improve artifact inspectability
- improve parity, conformance, or runtime validation
- add generic discovery or observer capabilities
- add honest tests, examples, or benchmark docs

Changes to treat carefully:
- benchmark-shaped shortcuts
- domain-specific logic in shared crates
- public claims that overstate what a demo proves
- new CLI flags that make the common path harder to learn

## Build, Test, Verify

Useful commands:

```bash
cargo test --workspace
```

```bash
cargo run --manifest-path Cargo.toml -p logicpearl -- --help
```

```bash
cargo run --manifest-path Cargo.toml -p logicpearl -- benchmark --help
```

The repo also includes end-to-end CLI coverage for:
- getting started
- held-out benchmark flow
- demo artifact builds

## Examples And Benchmarks

Treat these honestly:
- `examples/getting_started`: canonical first-run proof
- `examples/demos`: small showcase datasets, not headline benchmark evidence
- `BENCHMARKS.md`: benchmark summary and caveats

If you change benchmark logic, make sure the docs still match what the code actually does.

## When In Doubt

Prefer:
- smaller public interfaces
- stronger tests
- more inspectable artifacts
- generic capabilities over one-off benchmark tuning

If a feature only makes sense for one dataset or one customer-shaped workflow, it probably does not belong in the public core without cleanup first.
