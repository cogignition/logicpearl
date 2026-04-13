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

[Install](./docs/install.md) · [Terminology](./TERMINOLOGY.md) · [Core Loop](#core-loop) · [What You Can Trust](#what-you-can-trust) · [Optional Advanced Workflows](#optional-advanced-workflows) · [Benchmarks](./BENCHMARKS.md) · [Datasets](./DATASETS.md)

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

The runtime JSON has versioned schemas under [schema](./schema/), including gate, action, explanation, and artifact-error result shapes.

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

## Optional Advanced Workflows

Most new users can stop after `build`, `inspect`, `run`, `artifact verify`, and `diff`.

The repository also contains advanced surfaces for integrations, benchmarks, and demos. They are optional; they are not required to use the core artifact workflow.

### Garden Actions

The garden demo shows a multi-action policy learned from reviewed plant-care notes:

```bash
cd examples/demos/garden_actions
logicpearl build
logicpearl inspect
logicpearl run today.json --explain
```

See [examples/demos/garden_actions](./examples/demos/garden_actions/README.md).

### Synthetic Traces

If you do not have real traces yet, you can generate candidate traces from a reviewed trace-generation spec:

```bash
logicpearl traces generate examples/getting_started/synthetic_access_policy.tracegen.json \
  --output /tmp/synthetic_traces.csv
logicpearl build /tmp/synthetic_traces.csv --output-dir /tmp/synthetic-pearl
logicpearl inspect /tmp/synthetic-pearl
```

Synthetic traces are setup data, not hidden runtime logic. Review them before relying on the artifact.

### Source Provenance

Use a source manifest when traces or dictionaries came from policy documents, customer exports, public URLs, PDFs, manual notes, or synthetic fixtures:

```bash
logicpearl build traces.csv \
  --feature-dictionary feature_dictionary.json \
  --source-manifest sources.json \
  --output-dir /tmp/pearl
```

The engine validates and hashes the manifest, then attaches it to build provenance. It does not fetch URLs, parse PDFs, or interpret domain-specific source names.

### Feature Governance

Feature governance constrains how discovery may use specific features, especially one-sided detection signals:

```bash
logicpearl traces audit traces.jsonl \
  --write-feature-governance /tmp/feature_governance.json

logicpearl build traces.jsonl \
  --feature-governance /tmp/feature_governance.json \
  --output-dir /tmp/pearl
```

Use this when a signal is meaningful only when present, or when context fields should not become policy rules on their own.

### Compile And Browser Runtime

The CLI can run artifact bundles directly. Compilation is optional:

```bash
logicpearl compile /tmp/logicpearl-output
logicpearl compile /tmp/logicpearl-output --target wasm32-unknown-unknown
```

For browser integrations, use the public loader package instead of calling raw Wasm exports:

```js
import { loadArtifact } from '@logicpearl/browser';

const artifact = await loadArtifact('/artifacts/authz');
const result = artifact.evaluate(input);
```

### Plugins And Pipelines

Plugins and pipelines are for custom boundaries: observer plugins, trace-source plugins, enricher plugins, verifier plugins, and multi-stage artifact execution.

They execute local processes declared by manifests. Treat manifests from other repos, issues, or generated examples as untrusted unless you explicitly trust them.

Useful entrypoints:

```bash
logicpearl plugin validate examples/plugins/python_observer/manifest.json
logicpearl plugin run examples/plugins/python_observer/manifest.json --input examples/plugins/python_observer/raw_input.json
logicpearl pipeline validate examples/pipelines/authz/pipeline.json
logicpearl pipeline run examples/pipelines/authz/pipeline.json examples/pipelines/authz/input.json
```

Plugin-backed builds and pipeline stages record versioned provenance metadata with manifest hashes, entrypoint hashes, request/input/output hashes, timeout policy, capability posture, and redacted stdio hashes.

### Benchmarks And Parity Examples

Benchmark and parity material is intentionally separate from the launch path:

- [BENCHMARKS.md](./BENCHMARKS.md)
- [DATASETS.md](./DATASETS.md)
- [OPA / Rego parity example](./benchmarks/opa_rego/README.md)
- [Advanced guardrail guide](./docs/advanced-guardrail-guide.md)
- [WAF edge demo](./examples/waf_edge/README.md)

These are useful when you want evidence, corpus hygiene, guardrail workflows, or comparison examples. They are not required for the basic build/run loop.

## Which Surface To Use

Use the smallest surface that matches where the artifact runs:

- `logicpearl`
  Human-driven CLI workflows: build, inspect, run, diff, verify.
- `logicpearl-engine`
  Rust application embedding, repeated in-process evaluation, server-side adapters.
- `@logicpearl/browser`
  Browser-safe evaluation of Wasm artifact bundles.
- `logicpearl` Python package
  Reserved bridge for Python integrations over the Rust engine.

If it needs plugins, files, secrets, or server-only adapters, keep it server-side. If it is truly browser-safe, use the browser package.

## Project Status

LogicPearl is a single-maintainer project at version 0.1.x. The core engine, CLI, runtime, artifact format, and schemas are MIT licensed.

The core is domain-agnostic. The examples exist to exercise the engine and show integration patterns; they are not special cases built into the core.

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
  Install notes, advanced guides, and background material.

## Why Use LogicPearl

- replace brittle conditional logic with explicit artifacts
- inspect and diff deployable decision logic
- verify artifact integrity before use
- capture parity on bounded trace slices
- keep runtime evaluation compact and deterministic
- keep messy input handling outside the decision artifact
