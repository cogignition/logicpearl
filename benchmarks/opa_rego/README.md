# OPA / Rego Parity Example

This is a small bounded parity example, not the flagship proof path for the repository.

The current goal is narrower than "general Rego import":
- start from a compact Rego policy
- evaluate that policy with the real `opa` CLI on generated requests
- observe those requests into a fixed LogicPearl feature contract
- build a pearl from the resulting labeled decision traces
- verify runtime parity on that generated slice with the current `logicpearl` CLI

If you want the main first-run path, start with [`examples/getting_started`](../../examples/getting_started).
If you want the main public benchmark story, start with [`BENCHMARKS.md`](../../BENCHMARKS.md).

## Prerequisites

- Rust
- Python 3
- `opa` on `PATH`

## Run

From the project root:

```bash
python3 benchmarks/opa_rego/run_benchmark.py
```

That script:
- generates deterministic authz-style raw requests
- labels them with `opa eval` against [`policy.rego`](./policy.rego)
- writes observed decision traces to `benchmarks/opa_rego/output/decision_traces.csv`
- builds a real LogicPearl artifact bundle with `logicpearl build`
- runs `logicpearl inspect`
- runs `logicpearl conformance runtime-parity`
- runs one sample payload through `logicpearl run`

## Outputs

Generated files are written under `benchmarks/opa_rego/output/`:
- `decision_traces.csv`
- `sample_raw_input.json`
- `sample_feature_input.json`
- `artifact_bundle/`
- `inspect.json`
- `runtime_parity.json`
- `sample_run.json`
- `summary.json`

`output/` is local generated material and is intentionally not checked into git.

## What This Example Proves

- a bounded Rego policy can act as a labeling oracle for a deterministic LogicPearl build
- the current public CLI can build, inspect, and validate the resulting artifact bundle end to end
- the artifact/runtime path is inspectable rather than hidden behind a custom importer

## What It Does Not Prove

- general Rego transpilation or import coverage
- parity on arbitrary policies beyond this compact example
- end-to-end request-path latency parity
- that raw requests can skip the observer boundary
