<p align="center">
  <img src="./docs/assets/hero-shell.svg" alt="LogicPearl hero shell" height="260" />
</p>

# LogicPearl

**Build deterministic decision artifacts from examples. Inspect them. Run them. Verify what changed.**

LogicPearl is for bounded decision logic that should be explicit instead of buried in services, scripts, prompts, spreadsheets, or conditional code.

Give it examples of normalized inputs and the decisions that came out. It builds a `pearl`: a small artifact bundle with deterministic rules, readable reasons, stable JSON output, and integrity metadata.

The launch path is intentionally small:

1. build a pearl from decision traces
2. inspect the learned logic
3. run the artifact on new input
4. verify the artifact bundle and compare later versions

At runtime, a pearl does not call a model, spend tokens, or improvise. The same normalized input produces the same output every time.

<p align="center">
  <a href="./LICENSE"><img alt="MIT License" src="./docs/assets/badges/license-mit.svg"></a>
  <a href="./Cargo.toml"><img alt="Workspace" src="./docs/assets/badges/workspace-rust.svg"></a>
  <a href="./crates/logicpearl/Cargo.toml"><img alt="CLI" src="./docs/assets/badges/cli-logicpearl.svg"></a>
  <a href="./schema"><img alt="Schema" src="./docs/assets/badges/artifact-pearl-ir.svg"></a>
</p>

[Install](./docs/install.md) · [Docs](./docs/README.md) · [Terminology](./TERMINOLOGY.md) · [Core Loop](#core-loop) · [What You Can Trust](#what-you-can-trust) · [Open Core](#open-core-policy) · [Roadmap](./ROADMAP.md) · [Benchmarks](./BENCHMARKS.md) · [Datasets](./DATASETS.md)

## Install

Use Homebrew when the tap has a release formula:

```bash
brew install LogicPearlHQ/tap/logicpearl
logicpearl quickstart
```

For verified direct downloads, persistent install setup, and the convenience installer, see [docs/install.md](./docs/install.md). The recommended manual path downloads the release archive and its SHA-256 sidecar before extraction.

To install from a cloned source checkout instead:

```bash
cargo install --path crates/logicpearl
```

That source path builds the CLI only. For discovery workflows, keep `z3` on your `PATH` or use the prebuilt bundle, which includes `z3`.

## Core Loop

Clone the repository if you want to run the checked-in example data:

```bash
git clone https://github.com/LogicPearlHQ/logicpearl.git
cd logicpearl
```

Build a pearl from observed decision traces:

```bash
logicpearl build examples/getting_started/decision_traces.csv \
  --output-dir /tmp/logicpearl-output
```

Inspect the learned logic:

```bash
logicpearl inspect /tmp/logicpearl-output
```

Run the artifact on a new input:

```bash
logicpearl run /tmp/logicpearl-output examples/getting_started/new_input.json
logicpearl run /tmp/logicpearl-output examples/getting_started/new_input.json --json
```

Verify the artifact bundle:

```bash
logicpearl artifact inspect /tmp/logicpearl-output --json
logicpearl artifact digest /tmp/logicpearl-output
logicpearl artifact verify /tmp/logicpearl-output
```

That is the core product. A labeled behavior slice goes in; an inspectable deterministic artifact comes out.

## What Gets Built

A build writes an artifact bundle:

- `artifact.json`
  Stable bundle manifest with schema version, artifact kind, engine version, IR version, file paths, and hashes.
- `pearl.ir.json`
  The deterministic decision artifact.
- `build_report.json`
  Build details, discovery summary, and generated file hashes.

The bundle directory is the normal CLI entrypoint:

```bash
logicpearl inspect /tmp/logicpearl-output
logicpearl run /tmp/logicpearl-output input.json
```

The runtime JSON has versioned schemas under [schema](./schema/), including gate, action, explanation, and artifact-error result shapes. See [docs/artifacts.md](./docs/artifacts.md) for the full bundle contract.

## Decision Traces

The simplest input is a CSV file where each row is an observed decision:

- feature columns describe the case
- one label column records the outcome

Example:

```csv
role,resource,after_hours,allowed
viewer,doc,false,true
viewer,admin_panel,false,false
editor,doc,true,true
```

By default, `logicpearl build` accepts `.csv`, `.jsonl` / `.ndjson`, and `.json` traces. JSON inputs can contain nested objects and arrays; LogicPearl flattens them into feature paths such as `account.age_days` or `claims.0.code`.

If your label column is not obvious, pass it explicitly:

```bash
logicpearl build traces.csv \
  --label-column allowed \
  --output-dir /tmp/pearl
```

For multi-action traces, use an action column:

```bash
logicpearl build traces.csv \
  --action-column next_action \
  --default-action do_nothing \
  --output-dir /tmp/actions
```

## Inspect, Improve, Diff

The point of the artifact is not just that it runs. The point is that the decision logic is visible enough to review.

Useful follow-up commands:

```bash
logicpearl inspect /tmp/logicpearl-output --json
logicpearl diff /tmp/old-pearl /tmp/new-pearl
logicpearl diff /tmp/old-pearl /tmp/new-pearl --json
```

If a rule looks wrong, improve the trace data or add maintained constraints, rebuild, and diff the artifact. The diff distinguishes raw logic changes from explanation-only changes when metadata is present.

For readable rule labels, pass a feature dictionary:

```bash
logicpearl build traces.csv \
  --feature-dictionary feature_dictionary.json \
  --output-dir /tmp/pearl
```

The dictionary affects generated labels, messages, counterfactual hints, `inspect`, and `diff`. It does not change runtime evaluation.

## What You Can Trust

A pearl is not a claim that the training data was perfect. It is a deterministic boundary around a reviewed behavior slice.

LogicPearl gives you:

- repeatable runtime evaluation for the same normalized input
- inspectable decision logic before deployment
- stable runtime JSON schemas
- artifact manifests and file hashes
- semantic diffs between artifact versions
- no telemetry, no analytics, and no runtime network requests from the CLI/runtime during normal use

AI can help create traces or normalize messy input before the pearl. The pearl itself is deterministic software.

## Further Docs

Most new users can stop after `build`, `inspect`, `run`, `artifact verify`, and `diff`. The deeper docs are organized by boundary:

- [Docs index](./docs/README.md)
  Start here when you need a specific integration or reference page.
- [Artifacts](./docs/artifacts.md)
  Bundle layout, manifests, schemas, digest, verify, and compile.
- [Provenance](./docs/provenance.md)
  Build provenance, source manifests, generated file hashes, and privacy posture.
- [Plugins](./docs/plugins.md)
  Observer, trace-source, enricher, and verifier plugins, including local-process trust boundaries.
- [Pipelines](./docs/pipelines.md)
  Multi-stage "string of pearls" execution.
- [Browser runtime](./docs/browser-runtime.md)
  Browser-safe Wasm evaluation through `@logicpearl/browser`.
- [Conformance](./docs/conformance.md)
  Runtime parity, formal spec checks, schema fixtures, and reproducibility receipts.
- [Development](./docs/development.md)
  Local checks, release readiness, packaging, and maintainer workflow.
- [Benchmarks](./BENCHMARKS.md) and [Datasets](./DATASETS.md)
  Public evidence, corpus hygiene, and reproducible scoring notes.

## Project Status

LogicPearl is a single-maintainer project at version 0.1.x. The core engine, CLI, runtime, artifact format, and schemas are MIT licensed.

The core is domain-agnostic. The examples exist to exercise the engine and show integration patterns; they are not special cases built into the core.

## Open Core Policy

The open-source core is the local artifact workflow:

- `logicpearl` CLI: build, inspect, run, diff, compile, and verify
- Rust crates for IR, runtime, engine loading, discovery, schemas, verification, plugins, pipelines, conformance, rendering, and benchmark adapters
- published artifact and runtime JSON schemas under [schema](./schema/)
- `@logicpearl/browser` for browser-safe evaluation of open artifact bundles
- checked-in examples, fixtures, benchmark protocols, and docs needed to reproduce public claims

Those pieces are MIT licensed and are intended to stay open. New functionality required to build, inspect, run, verify, diff, and reproduce local LogicPearl artifacts belongs in the open core.

Commercial tooling may exist around the core, but not replace it. Examples include hosted trace ingestion, team dashboards, hosted artifact registries, monitoring, review workflows, managed benchmark runs, and enterprise administration.

Telemetry and data posture:

- the local CLI and runtime do not call home during normal use
- no telemetry or analytics are collected by the local CLI/runtime
- hosted services, if offered, must document what data they receive, retain, and process
- customer traces, source manifests, plugin outputs, and artifact contents must not be used for training or benchmarking without explicit permission
- self-hosted and local artifact workflows must remain usable without a hosted account

Contributions are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Repository Layout

- `crates/logicpearl`
  User-facing CLI.
- `crates/logicpearl-*`
  Core Rust libraries for IR, runtime, discovery, pipelines, verification, rendering, conformance, and benchmark adaptation.
- `packages/logicpearl-browser`
  Browser runtime package for Wasm artifact bundles.
- `examples`
  Small runnable examples and demos.
- `benchmarks`
  Public benchmark corpora and parity examples.
- `fixtures`
  Tiny inspection and runtime inputs used by tests and examples.
- `schema`
  Published JSON schemas for public artifact formats.
- `docs`
  Topic docs for artifact contracts, provenance, plugins, pipelines, browser runtime, conformance, development, and advanced guides.

## Why Use LogicPearl

- replace brittle conditional logic with explicit artifacts
- inspect and diff deployable decision logic
- verify artifact integrity before use
- capture parity on bounded trace slices
- keep runtime evaluation compact and deterministic
- keep messy input handling outside the decision artifact
