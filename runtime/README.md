# Runtime Workspace

This directory is reserved for the runtime and deployment side of LogicPearl.

Intended responsibilities:
- loading the shared Gate IR,
- runtime gate evaluation,
- WASM and native compilation targets,
- artifact validation,
- high-performance CLI or embedding surfaces,
- cross-implementation conformance tests against discovery-generated fixtures.

Current runtime code now lives here. Older historical experiments remain outside the public repo surface.

The intended long-term boundary is:
- discovery authors and discovers,
- runtime executes and ships.

Initial implementation now exists in:
- `runtime/src/ir.rs` for serde-based Gate IR types and semantic validation
- `runtime/src/lib.rs` for the public crate surface
- `runtime/Cargo.toml` for the runtime crate definition

Current test coverage includes:
- loading shared valid fixtures,
- rejecting shared invalid fixtures,
- evaluating shared parity cases with expected bitmasks.

Cross-implementation conformance is orchestrated from:
- `conformance/run_parity.py`

Recommended commands from `runtime/`:
- `cargo test`
- `cargo run -- ../fixtures/ir/valid/auth-demo-v1.json ../fixtures/ir/eval/auth-demo-v1-deny-multiple-rules-input.json`
- `cargo run --bin logicpearl -- build ../examples/getting_started/decision_traces.csv --output-dir ../examples/getting_started/output`
- `cargo run --bin logicpearl -- inspect ../examples/getting_started/output/pearl.ir.json`
- `cargo run --bin logicpearl -- run ../examples/getting_started/output/pearl.ir.json ../examples/getting_started/new_input.json`

## Current Code Map

The public runtime surface should own:

- shared Gate IR loading and validation,
- deterministic pearl evaluation,
- CLI inspection and execution,
- compilation targets like WASM and native backends,
- conformance tests against public discovery outputs.

## Target Layout

As runtime grows, it should roughly become:

```text
runtime/
  ir/
  evaluator/
  compiler/
  wasm/
  native/
  cli/
  conformance/
```

Recommended responsibilities:

- `ir/`
  Load and validate the shared Gate IR.
- `evaluator/`
  Execute bitmask gates deterministically.
- `compiler/`
  Lower the IR into WASM/native targets.
- `wasm/`
  WASM-facing runtime crates or templates.
- `native/`
  Native Rust binaries or libraries.
- `cli/`
  Runtime-facing inspection and evaluation tools.
- `conformance/`
  Golden tests proving parity with discovery outputs.

Today, `logicpearl` is the start of that user-facing surface:
- `logicpearl build` emits a pearl from labeled decision traces
- `logicpearl inspect` summarizes the emitted artifact
- `logicpearl run` evaluates the artifact on new inputs

## Migration Priorities

Suggested migration order:

1. Stabilize the Gate IR contract first.
2. Move runtime-facing schema loaders and evaluators second.
3. Move Rust codegen and transpiler backends third.
4. Move generated artifacts and benchmark runtimes last.

## What Should Stay Out

These concerns do not belong in runtime long-term:
- dataset preparation,
- trace synthesis,
- model fitting,
- discovery-time heuristics,
- benchmark narration and result interpretation.
