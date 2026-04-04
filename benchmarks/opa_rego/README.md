# OPA / Rego Benchmark

This benchmark keeps OPA-specific parsing and evaluation behind a LogicPearl domain adapter while the shared engine stays generic.

The demo uses a compact RBAC policy in Rego and compares:
- OPA's `allow` decision
- an equivalent LogicPearl pearl built from imported bounded policy behavior
- the emitted `pearl.ir.json` evaluated through `pearl-runtime`

Important benchmark framing:
- This is a parity/import benchmark, not an automatic discovery demo.
- The interesting part is the artifact chain: start from an existing policy, import the bounded behavior through a domain adapter, emit a pearl, and run it through the shared runtime.
- The latency comparison is policy-core-to-policy-core. OPA evaluates raw requests directly, while the LogicPearl timing uses precomputed feature payloads and does not include observation/adaptation cost.
- The stronger claim here is parity plus artifact/runtime portability: same policy behavior, emitted as `pearl.ir.json`, validated through `pearl-runtime`, and compiled to WASM.

Run from the repo root:

```bash
cd discovery
uv run python ../benchmarks/opa_rego/run_benchmark.py
```

Outputs are written under:
- `benchmarks/opa_rego/output/pearl.json`
- `benchmarks/opa_rego/output/pearl.ir.json`
- `benchmarks/opa_rego/output/pearl_audit.json`

The benchmark is intentionally demo-sized. The reusable pieces live in:
- `logicpearl.domains.opa` for Rego parsing/eval wrappers
- `logicpearl.engine` for gate compilation, IR emission, and WASM generation

What this benchmark is good for:
- showing that existing policy behavior can be imported into a compact deterministic pearl
- demonstrating runtime parity between OPA, Python evaluation, `pearl-runtime`, and emitted IR/WASM artifacts
- proving the OPA adapter can stay outside the generic engine

What this benchmark does not prove by itself:
- automatic policy discovery from OPA traces
- full end-to-end request-path latency parity
- general Rego transpilation coverage beyond the demonstrated parity path
