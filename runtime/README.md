# Runtime Legacy Surface

This directory contains the older runtime package that preceded the new Rust workspace.

The active public direction now lives at the workspace root:

- `Cargo.toml`
- `crates/logicpearl` published as the `logicpearl` crate
- `crates/logicpearl-ir`
- `crates/logicpearl-runtime`
- `crates/logicpearl-discovery`
- `crates/logicpearl-observer`
- `crates/logicpearl-verify`
- `crates/logicpearl-render`
- `crates/logicpearl-conformance`

Use the workspace CLI for the current public path:

```bash
cargo test --manifest-path ../Cargo.toml --workspace
cargo run --manifest-path ../Cargo.toml -p logicpearl -- build ../examples/getting_started/decision_traces.csv --output-dir ../examples/getting_started/output
cargo run --manifest-path ../Cargo.toml -p logicpearl -- inspect ../examples/getting_started/output/pearl.ir.json
cargo run --manifest-path ../Cargo.toml -p logicpearl -- run ../examples/getting_started/output/pearl.ir.json ../examples/getting_started/new_input.json
```
