<p align="center">
  <img src="./docs/assets/hero-shell.svg" alt="LogicPearl hero shell" height="260" />
</p>

# LogicPearl

**LogicPearl** turns hard software behavior into deterministic deployable artifacts called `pearls`.

If your system makes consequential decisions about policy, eligibility, trust, compliance, claims, approvals, or risk, LogicPearl is a different execution model: messy input stays at the edge, observers normalize it, pearls run deterministic logic, and the result becomes something you can inspect, diff, validate, compile, and deploy.

Imagine a giant codebase full of decision logic accumulated over ten years: thousands of conditionals, spread across handlers, services, scripts, and edge cases nobody wants to touch. The LogicPearl claim is that a bounded pearl can replace that logic slice with something smaller, faster, easier to understand, and parity-checkable against the old behavior. When that slice hits 100% measured parity on the real fixtures and decision surface you care about, it starts to feel like magic because it is effectively acting as a compact deterministic replacement for the old maze.

LogicPearl does not require AI. The artifact model stands on its own. But it becomes much more powerful with AI: AI can help extract messy inputs, build observers, synthesize artifacts, and call pearls as deterministic tools inside larger workflows.

And there is a practical reason this matters: if you are spending a fortune on tokens to repeatedly reconstruct the same logic, something has gone wrong. LogicPearl gives you another path. Use AI to find, learn, extract, or synthesize the behavior once, then distill that behavior into deterministic pearls you can run cheaply, validate exactly, and stop paying to rediscover on every call.

Software should run as artifact, not fog.

<p align="center">
  <a href="./LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-0f172a.svg?style=flat-square"></a>
  <a href="./Cargo.toml"><img alt="Workspace" src="https://img.shields.io/badge/workspace-Rust-173053.svg?style=flat-square"></a>
  <a href="./crates/logicpearl-cli/Cargo.toml"><img alt="CLI" src="https://img.shields.io/badge/cli-logicpearl-173053.svg?style=flat-square"></a>
  <a href="./benchmarks/opa_rego/README.md"><img alt="Demo" src="https://img.shields.io/badge/demo-OPA%20parity-173053.svg?style=flat-square"></a>
  <a href="./schema"><img alt="Schema" src="https://img.shields.io/badge/artifact-Pearl%20IR-173053.svg?style=flat-square"></a>
</p>

New here? Read [Terminology](./TERMINOLOGY.md) first.

[Website](https://logicpearl.com) · [Terminology](./TERMINOLOGY.md) · [Start Here](#start-here) · [Why This Is Interesting](#why-this-is-interesting) · [Generate Your Own Pearl](#generate-your-own-pearl) · [Next Demos](#next-demos) · [Repository Layout](#repository-layout)

Quick proof path:

```bash
cargo install --path crates/logicpearl-cli
logicpearl build examples/getting_started/decision_traces.csv --output-dir examples/getting_started/output
```

If that output makes you think “wait, that became a pearl from examples alone,” you are looking at the point of the project.

This repo gives you the public proof layer. If you want the bigger story, the harder migrations, or help attacking a real legacy decision system, go to [logicpearl.com](https://logicpearl.com) or [reach out directly](mailto:ken@devopslibrary.com?subject=LogicPearl%20Consulting).

We are looking for the world's hardest decision-logic problems: the systems with ten years of conditionals, brittle policy layers, hidden behavior, and real consequences. That is the kind of work this model is for, and it is the kind of work we are used to solving.

## What LogicPearl Is

LogicPearl is not just a rules engine. It is a way to compile important behavior into bounded artifacts instead of hiding that behavior inside application code.

A pearl is logic as software artifact:
- inspectable
- diffable
- testable
- portable
- explainable
- compilable to WASM

The execution shape is simple:
1. messy real-world input stays at the edge
2. an observer maps it into normalized features
3. a pearl executes deterministic logic
4. the result can be inspected, validated, diffed, and deployed

This repo is the public proof layer for that model:
- Pearl IR and schemas
- observer and feature-contract tooling
- Rust runtime evaluation
- reproducible public demos
- parity/import examples for bounded logic slices

## Start Here

If you only do one thing, run the public proof.

Prerequisites:
- Rust
- a willingness to treat logic as a build artifact instead of application glue

Install the public CLI once:

```bash
cargo install --path crates/logicpearl-cli
```

For local development inside the repo, the equivalent form is:

```bash
cargo run --manifest-path Cargo.toml -p logicpearl-cli -- <command>
```

### 1. Build a pearl from decision traces

Start with a tiny labeled behavior slice:

- [decision_traces.csv](./examples/getting_started/decision_traces.csv)

Each row is an observed decision:
- input features
- final outcome in the `allowed` column

Now emit a pearl with no hand-written rules:

```bash
logicpearl build examples/getting_started/decision_traces.csv --output-dir examples/getting_started/output
```

What you should see:
- a discovered pearl emitted to `examples/getting_started/output/pearl.ir.json`
- a `build_report.json` with the number of rows, discovered rules, and training parity

Inspect the artifact:

```bash
logicpearl inspect examples/getting_started/output/pearl.ir.json
```

Run it on a new input:

```bash
logicpearl run examples/getting_started/output/pearl.ir.json examples/getting_started/new_input.json
```

Compile it into a standalone native executable:

```bash
logicpearl compile examples/getting_started/output/pearl.ir.json --name authz-demo
./examples/getting_started/output/authz-demo.pearl examples/getting_started/new_input.json
```

You can also target specific platforms by Rust target triple:

```bash
logicpearl compile examples/getting_started/output/pearl.ir.json --name authz-demo --target x86_64-unknown-linux-gnu
logicpearl compile examples/getting_started/output/pearl.ir.json --name authz-demo --target x86_64-pc-windows-msvc
logicpearl compile examples/getting_started/output/pearl.ir.json --name authz-demo --target aarch64-apple-darwin
```

That is the simplest LogicPearl loop:
- observed behavior goes in
- a pearl comes out
- the artifact is inspectable
- the runtime is deterministic

If you want to drive LogicPearl from Python or another language, prefer the stable artifact and CLI boundary rather than reaching into Rust internals directly:

```bash
logicpearl build examples/getting_started/decision_traces.csv --output-dir /tmp/logicpearl-build --json
```

The same stage model is available to plugins:
- `observer` plugins map messy input into normalized features
- `trace_source` plugins emit decision traces for discovery
- `enricher` plugins transform records before artifact emission
- `verify` plugins annotate proof or audit status

### 2. Run a pearl in under a minute

```bash
logicpearl inspect fixtures/ir/valid/auth-demo-v1.json
logicpearl run fixtures/ir/valid/auth-demo-v1.json fixtures/ir/eval/auth-demo-v1-deny-multiple-rules-input.json
```

What you should see:
- a deterministic evaluation result
- a compact artifact summary
- behavior that is explicit instead of buried in service code

That small output shows the core shape:
- small artifact
- deterministic runtime
- explicit reasons
- behavior that does not disappear into service code

### 3. Use a Python observer plugin at the edge

```bash
logicpearl observer validate examples/plugins/python_observer/manifest.json --plugin-manifest
logicpearl observer run --plugin-manifest examples/plugins/python_observer/manifest.json --input examples/plugins/python_observer/raw_input.json
```

What you should see:
- raw input mapped into normalized features
- a clean process boundary for Python or any other language
- a plugin contract that does not require embedding Python into the Rust core

That is the other half of the model:
- raw input comes in
- the observer emits normalized features
- the pearl consumes deterministic features

In the full LogicPearl workflow, observers are an artifact boundary too:
- models or adapters can live at the edge
- the normalized contract stays explicit
- the pearl stays deterministic in the middle

### 4. Build through Python plugin stages

Use a Python trace-source plugin:

```bash
logicpearl build \
  --trace-plugin-manifest examples/plugins/python_trace_source/manifest.json \
  --trace-plugin-input examples/getting_started/decision_traces.csv \
  --output-dir examples/getting_started/output-plugin
```

Add a Python enricher plugin in the same build:

```bash
logicpearl build \
  --trace-plugin-manifest examples/plugins/python_trace_source/manifest.json \
  --trace-plugin-input examples/getting_started/decision_traces.csv \
  --enricher-plugin-manifest examples/plugins/python_enricher/manifest.json \
  --output-dir examples/getting_started/output-plugin-enriched
```

Verify an emitted pearl through a Python verify plugin:

```bash
logicpearl verify examples/getting_started/output/pearl.ir.json \
  --plugin-manifest examples/plugins/python_verify/manifest.json \
  --json
```

That is the intended plugin shape:
- Rust owns the core CLI and artifact model
- Python can plug into explicit stages
- the contracts stay JSON-based and inspectable

### 5. See the bitmask visually

See example outputs:
- [Auth Bitmask SVG](./docs/examples/auth-bitmask.svg)
- [Auth Heatmap SVG](./docs/examples/auth-heatmap.svg)

<p align="center">
  <img src="./docs/examples/auth-bitmask.svg" alt="Auth demo bitmask" width="46%" />
  <img src="./docs/examples/auth-heatmap.svg" alt="Auth demo heatmap" width="46%" />
</p>

## Why This Is Interesting

Most real decision logic ends up as one of these:
- a giant rules blob
- conditionals spread across services
- brittle policy code no one wants to touch
- AI extraction with no deterministic boundary after it

LogicPearl is a different shape:
- raw input stays outside the pearl
- normalized features cross a clear boundary
- the pearl itself is deterministic
- the output is compact, portable, and explainable

The point is not “yet another rules engine.”
The point is a new execution shape for decision logic.

The old shape is:
- logic hidden in applications
- changes made by editing fragile mazes
- review done indirectly
- production behavior inferred after the fact

The LogicPearl shape is:
- behavior compiled into artifacts
- semantic boundaries between observation and evaluation
- deterministic runtime outputs
- artifacts that can be inspected, diffed, versioned, and transported

That is why this matters.

If software controls approvals, money, access, policy, risk, or compliance, then “the code runs somewhere” is not a satisfying model anymore.

And the full promise is broader than “write rules in JSON”:
- start from behavior, examples, or an existing policy/runtime
- generate the artifact in the middle
- keep the final pearl deterministic and portable
- keep the observer boundary explicit instead of burying it in application code

## Quick Start

### Run tests

```bash
cargo test --manifest-path Cargo.toml --workspace
```

### Run the OPA parity demo

```bash
cd discovery
uv run logicpearl-opa-inspect ../benchmarks/opa_rego/policy.rego
uv run python ../benchmarks/opa_rego/run_benchmark.py
```

### Run the Rust runtime directly

```bash
logicpearl run benchmarks/opa_rego/output/pearl.ir.json benchmarks/opa_rego/output/runtime_inputs.json
```

Expected OPA outputs:
- `benchmarks/opa_rego/output/pearl.json`
- `benchmarks/opa_rego/output/pearl.ir.json`
- `benchmarks/opa_rego/output/pearl_audit.json`
- `benchmarks/opa_rego/output/*.wasm`

## Generate Your Own Pearl

The real LogicPearl story is not “open a JSON file and hand-author a rules blob.”

The intended workflow is:
1. start from behavior, examples, or an existing policy/runtime
2. generate a pearl artifact
3. generate or validate the observer boundary
4. inspect, diff, and run the emitted pearl

### Fastest public path: start from an existing policy/runtime

The best public example in this repo is the OPA parity/import demo:

```bash
cd discovery
uv run python ../benchmarks/opa_rego/run_benchmark.py
```

That flow:
- starts from an existing Rego policy
- imports the bounded decision behavior through a domain adapter
- emits `pearl.json`, `pearl.ir.json`, audit output, and WASM
- lets you inspect and run the resulting pearl yourself

This is the quickest way for a new person to see the full artifact loop without hand-editing the pearl itself.

See:
- [OPA / Rego Benchmark](./benchmarks/opa_rego/README.md)

### Fastest public path for the observer boundary

The observer fixtures are there to make the boundary inspectable and testable, not to suggest that production observers should be maintained by hand forever.

Run:

```bash
logicpearl observer validate examples/plugins/python_observer/manifest.json --plugin-manifest
```

That shows the intended observer loop:
- raw-input fixtures go in
- observer behavior is validated exactly
- the emitted feature contract can be trusted by the pearl runtime

### What “make your own pearl” really means

In practice, making a new pearl usually means one of these:
- importing an existing policy/runtime into a bounded LogicPearl artifact
- learning a deterministic pearl from labeled examples or known behavior
- generating an observer/adapter boundary for raw input, then validating it against fixtures

The hand-authored auth fixture is still useful for learning the shape of the artifact, but it is not the main product promise.

If you want to inspect the artifact shape directly, start here:
- [auth-demo-v1.json](./fixtures/ir/valid/auth-demo-v1.json)
- [auth-observer-v1.json](./fixtures/observer/valid/auth-observer-v1.json)

But the interesting claim is that LogicPearl can come up with the middle artifact chain for you, then let you inspect and run the result.

## What You Can Do Here

- inspect and validate `pearl.ir.json` artifacts
- run pearls through the Rust runtime
- compile small pearls to WASM
- reproduce the auth demo
- reproduce the OPA / Rego parity demo
- see how observer specs and feature contracts connect raw inputs to pearls
- inspect the generated artifact chain instead of treating the pearl as a black box

## Next Demos

### Auth Demo

Best first technical demo for understanding the artifact model.

### OPA / Rego Demo

Best public demo for parity/import framing.

Important framing:
- this is a parity/import demo
- not an automatic discovery demo

See:
- [benchmarks/opa_rego/README.md](./benchmarks/opa_rego/README.md)

### Private Healthcare / Corpus Demo

The strongest private product demo currently is the healthcare corpus-aware pearl flow, where:
- a request goes in
- a selector runs internally
- applicable policies are chosen deterministically
- logic/documentation bitmasks come back in one response

That flow is not the public open-source entry path, but it is where the broader product story becomes very obvious.

## Reproducible Artifacts

The public demos write real artifacts you can inspect:
- `pearl.json`
- `pearl.ir.json`
- `pearl_audit.json`
- compiled `.wasm`

The promise is simple:
- you should be able to run, inspect, and validate pearls yourself

## Why Use LogicPearl

- replace brittle logic blobs with explicit artifacts
- inspect and diff deployable decision logic
- prove parity on a bounded policy slice
- keep runtime evaluation compact and portable
- pair human-readable specs with deployable runtime artifacts
- keep a clean boundary between messy input handling and deterministic logic
