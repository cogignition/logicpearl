# Contributing

LogicPearl is a small product repository.

The goal is not just to land code. The goal is to make the public engine better:
- easier to run
- easier to inspect
- more honest on parity and benchmarks
- more generic, not more benchmark-shaped

## Quality Tracking

The repository keeps a visible checked-in quality report for the public example and benchmark suites.

The report is generated from:
- checked-in examples
- demo datasets
- the fast open guardrail regression sample

Files:
- [QUALITY.json](./QUALITY.json)
- [scripts/quality/README.md](./scripts/quality/README.md)

## How To Improve The Quality Suites

High-value contribution patterns:
- improve the generic engine so more datasets build cleanly without special handling
- improve runtime, IR, validation, or inspection tooling
- improve observer synthesis or benchmark infrastructure in ways that stay generic
- add honest examples, tests, and docs that strengthen the public first-run path
- reduce regressions and keep benchmarks reproducible

Low-value or rejected patterns:
- benchmark-specific hacks disguised as generic features
- demo-only shortcuts in shared engine code
- claims in docs that overstate what a benchmark proves
- changes that feel magical only because hidden assumptions were baked in

The fastest way to lose the plot here is optimizing for metric movement while making the engine less honest.

## Design Rules

Keep the engine generic.

Good:
- feature support that works across multiple datasets
- discovery improvements that do not mention one benchmark by name
- better simplification, validation, or runtime behavior

Bad:
- hardcoded benchmark heuristics in shared discovery/runtime code
- public UX shaped around one private workflow
- synthetic demos that only work because the engine secretly special-cases them

## Before You Open A PR

Please make sure:
- tests pass
- new public docs are accurate and conservative
- benchmark framing matches what the code actually proves
- metric movement, if any, comes from a generic improvement

If your change is metric-neutral but makes the repo cleaner, easier to use, or more honest, it is still a good contribution.

## Local Development

Enable the repository hooks:

```bash
git config core.hooksPath .githooks
```

Run the same shared verification suites manually:

```bash
cargo xtask verify pre-commit
```

```bash
cargo xtask verify pre-push
```

```bash
cargo xtask verify ci
```

Ignored local output can get large because compile, package, benchmark, and smoke-test flows create build products and JSON reports that are intentionally not tracked. Successful Cargo-backed compile runs clean up their transient generated crate by default; set `LOGICPEARL_KEEP_GENERATED_BUILDS=1` only when you need to debug the generated Rust project. Before sharing a worktree snapshot, inspect generated output with:

```bash
cargo xtask clean-generated
```

That command is a dry run. To remove those ignored generated paths:

```bash
cargo xtask clean-generated --apply
```

Use `cargo clean` or `cargo xtask clean-generated --include-cargo-target --apply` when you also want to remove the full root `target/` Cargo build cache. Public source archives should come from git, not a zipped local checkout:

```bash
git archive --format=zip --output logicpearl-source.zip HEAD
```

Run the targeted solver parity suite when you are touching solver-backed discovery, verification, or observer selection code:

```bash
cargo xtask verify solver-backends
```

Run the full public test suite directly when you want the raw command:

```bash
cargo test --workspace
```

Internal solver bring-up is configurable through environment variables:

```bash
export LOGICPEARL_SOLVER_BACKEND=auto
export LOGICPEARL_SOLVER_TIMEOUT_MS=5000
export LOGICPEARL_SOLVER_DIR="$HOME/.logicpearl/current/bin"
```

Accepted backend values are `auto`, `z3`, `cvc5`, `prefer-z3`, and `prefer-cvc5`.

`auto` prefers `z3` first and falls back to `cvc5` when `z3` is not available. `prefer-cvc5` flips that order. `z3` remains the default path, and `cvc5` is still an internal backend for bring-up and parity testing rather than a public CLI knob.

`LOGICPEARL_SOLVER_DIR` is optional. Use it when you want LogicPearl to prefer a bundled solver directory over whatever happens to be on the global `PATH`.

Observer phrase selection also has an internal backend toggle for subset-selection experiments:

```bash
export LOGICPEARL_OBSERVER_SELECTION_BACKEND=mip
```

Accepted values are `smt` and `mip`.

`mip` is now the default path for observer synthesis because it matched the SMT results on the checked-in observer comparison workloads while removing the external solver dependency from subset selection. `smt` remains available as an internal comparison path. Both backends are still internal toggles rather than public CLI knobs.

Discovery exact rule selection also has an internal backend toggle for solver-selection experiments:

```bash
export LOGICPEARL_DISCOVERY_SELECTION_BACKEND=smt
```

Accepted values are `smt` and `mip`.

`smt` remains the default path. `mip` enables an internal mixed-integer exact-selection prototype built on `good_lp` with the pure-Rust `microlp` backend. It is intended for parity comparison on larger candidate frontiers rather than as a public CLI knob.

These internal backend overrides are included in build/discover cache fingerprints, and `build --json` now records the exact-selection backend and outcome in `exact_selection` so backend experiments do not silently reuse stale reports.

Maintainers can package a distributable CLI bundle with a bundled solver by running:

```bash
cargo xtask package-release-bundle \
  --logicpearl-binary target/release/logicpearl \
  --z3-binary "$(command -v z3)" \
  --target-triple x86_64-unknown-linux-gnu \
  --output-dir dist
```

Quality report maintenance is explicit and stays out of the git hooks. Refresh the report when you actually intend to update it:

```bash
cargo xtask quality-report
```
