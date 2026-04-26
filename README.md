<p align="center">
  <img src="./docs/assets/garden-actions-hero.svg" alt="LogicPearl example flow showing notes, traces, local build commands, and a selected action" width="880" />
</p>

# LogicPearl

**Compile repeatable judgment into deterministic artifacts.**

LogicPearl is for workflows where a system keeps making the same bounded
decision: answer this policy question, block this tool call, route this case,
approve or deny this request, choose the next action, diagnose this operational
state.

Instead of leaving that judgment inside prompts, RAG calls, spreadsheets,
legacy conditionals, or tribal reviewer habits, LogicPearl turns reviewed
examples into a small local artifact you can inspect, run, verify, diff, and
ship.

```text
messy input -> observer / extractor -> normalized facts -> pearl -> deterministic result
```

The observer can be a parser, adapter, classifier, RAG step, LLM, script, or
domain integration. Its job is to normalize the world. The pearl's job is to
make the final bounded decision exactly the same way every time.

At runtime, a pearl does not call a model, spend tokens, search documents, or
improvise.

<p align="center">
  <a href="./LICENSE"><img alt="MIT License" src="./docs/assets/badges/license-mit.svg"></a>
  <a href="./Cargo.toml"><img alt="Workspace" src="./docs/assets/badges/workspace-rust.svg"></a>
  <a href="./crates/logicpearl/Cargo.toml"><img alt="CLI" src="./docs/assets/badges/cli-logicpearl.svg"></a>
  <a href="./schema"><img alt="Schema" src="./docs/assets/badges/artifact-pearl-ir.svg"></a>
</p>

[Install](./docs/install.md) | [Docs](./docs/README.md) | [Quickstart](#quickstart) | [Use Cases](#use-cases) | [Core Loop](#core-loop) | [Artifacts](#artifacts) | [Roadmap](./ROADMAP.md) | [Benchmarks](./BENCHMARKS.md)

## Use Cases

Use LogicPearl when the decision is bounded, repeatable, and important enough
to review before it changes.

### Replace Runtime RAG For Bounded Decisions

RAG is useful when the system needs to find or summarize information. It is a
poor final decision engine when the answer should be stable, auditable, and
cheap to run.

Use RAG, extraction, or a model upstream to find facts. Then use a pearl to
decide:

- "Does this request satisfy the policy?"
- "Which required documents are missing?"
- "Should this case be approved, denied, escalated, or routed?"
- "Which troubleshooting step should run next?"

For bounded questions, LogicPearl replaces runtime retrieval-and-reasoning with
compiled deterministic judgment.

### Guard AI Systems

Use pearls as a deterministic control layer around agents and LLM products:

- allow, block, redact, escalate, or ask for clarification
- decide whether a tool call is permitted
- route prompts or outputs to review lanes
- enforce policy after a model extracts normalized signals
- explain which guardrail fired and what input change would matter

The model can observe and propose. The pearl decides the bounded policy.

### Replace Logic-Heavy Legacy Code

If behavior is buried in nested `if` statements, old services, spreadsheet
rules, prompt branches, or reviewer habits, capture examples of the current
behavior and build a pearl from them.

You get a versioned artifact with readable rules, parity reports, stable JSON,
file hashes, and semantic diffs. That makes modernization less like a rewrite
and more like replacing one verified behavior boundary at a time.

### Build Operational Troubleshooting Tools

Observers can normalize logs, Kubernetes objects, cloud events, CI failures,
alerts, or support tickets into features. Pearls can then choose the likely
cause, severity, escalation path, or next action.

This is useful when the workflow currently lives in runbooks, dashboards, and
experienced operators' heads.

### Train And Evaluate Models

Pearls can provide deterministic labels, counterfactuals, hard negatives,
action routes, and verifier signals around model training or evaluation. They
are useful when you want a stable teacher, judge, or regression oracle instead
of another probabilistic call in the loop.

## Why It Matters

LogicPearl gives you deterministic infrastructure for decisions that are too
important to leave as hidden branching logic or prompt behavior.

- **Repeatable runtime behavior**
  The same normalized input produces the same result every time.
- **Inspectable rules**
  Review the learned logic before deploying it.
- **Semantic diffs**
  See whether a change affected raw policy logic, explanations, source schema,
  or action priority.
- **Stable JSON contracts**
  Gate, action, pipeline, explanation, and artifact-error results have
  versioned schemas under [schema](./schema/).
- **Local artifacts**
  Run from the CLI, Rust, Python, browser Wasm, or compiled native binaries.
- **No runtime network dependency**
  Normal CLI/runtime evaluation does not call home, search, or call a model.

A pearl is not proof that your examples were complete or correct. It is a
deterministic boundary around the behavior slice you reviewed.

## Quickstart

Install from a cloned checkout:

```bash
cargo install --path crates/logicpearl
```

Source installs need a solver such as `z3` on `PATH` for discovery workflows.
Prebuilt release bundles include `logicpearl` and `z3`; see
[docs/install.md](./docs/install.md).

Build a multi-action artifact from the checked-in garden example:

```bash
logicpearl build examples/demos/garden_actions/traces.csv \
  --action-column next_action \
  --default-action do_nothing \
  --gate-id garden_actions \
  --output-dir /tmp/garden-actions
```

Inspect the learned rules:

```bash
logicpearl inspect /tmp/garden-actions
```

Run a new input:

```bash
logicpearl run /tmp/garden-actions examples/demos/garden_actions/today.json --explain
logicpearl run /tmp/garden-actions examples/demos/garden_actions/today.json --json
```

Expected shape:

```text
Built action artifact garden_actions
  Rows 16
  Actions water, do_nothing, fertilize, repot
  Default action do_nothing
  Training parity 100.0%

Action rules:
  1. water
     Soil Moisture at or below 18% and Water used in the last 7 days at or below 0.2
  2. fertilize
     Days since fertilized at or above 32.0
  3. repot
     Days since fertilized at or above 15.0 and Days since watered at or above Growth Cm Last 14 Days

action: water
reason:
  - Soil Moisture at or below 18% and Water used in the last 7 days at or below 0.2
```

Verify the artifact bundle:

```bash
logicpearl artifact inspect /tmp/garden-actions --json
logicpearl artifact digest /tmp/garden-actions
logicpearl artifact verify /tmp/garden-actions
```

## Core Loop

```text
build -> inspect -> run -> verify -> diff
```

That loop is the product:

- **build**
  Learn a deterministic gate or action policy from reviewed traces.
- **inspect**
  Read the rule behavior before deployment.
- **run**
  Evaluate normalized JSON input locally.
- **verify**
  Check the bundle manifest, member paths, file hashes, and artifact hash.
- **diff**
  Compare two artifact versions by policy meaning, not just raw JSON changes.

## Decision Traces

The simplest input is a CSV file where each row is an observed decision:

- feature columns describe the case
- one label or action column records the outcome

Binary gate example:

```csv
role,resource,after_hours,allowed
viewer,doc,false,true
viewer,admin_panel,false,false
editor,doc,true,true
```

Build it:

```bash
logicpearl build traces.csv \
  --target allowed \
  --output-dir /tmp/pearl
```

`--target` is the reviewed outcome column. LogicPearl inspects that column and
builds the right artifact shape: a binary gate, a multi-action policy, or a
fan-out pipeline for multi-label action lists. It prints the inferred mode while
keeping `--json` stdout machine-readable.

Not sure which column is the target? Ask the trace doctor first:

```bash
logicpearl doctor traces.csv
```

It reports likely target columns, feature columns, warnings, and a recommended
`logicpearl build` command for gate, action, or fan-out datasets.

Multi-action example:

```bash
logicpearl build traces.csv \
  --target next_action \
  --output-dir /tmp/actions
```

Fan-out example for traces where multiple actions can apply to the same row:

```bash
logicpearl build traces.csv \
  --target applicable_actions \
  --output-dir /tmp/fanout \
  --compile
```

Fan-out builds learn one binary gate per action and assemble them into a typed
pipeline artifact. Runtime JSON uses `logicpearl.fanout_result.v1` with
`applicable_actions`, per-action `verdicts`, and gate-shaped matched-rule
explanations for each action.

When no learned rule should return a different operational action than the
business default:

```bash
logicpearl build traces.csv \
  --action-column decision \
  --default-action releasable \
  --no-match-action insufficient_context \
  --output-dir /tmp/actions
```

`logicpearl build` accepts `.csv`, `.jsonl` / `.ndjson`, and `.json` traces.
JSON inputs can contain nested objects and arrays; LogicPearl flattens them
into feature paths such as `account.age_days` or `claims.0.code`.

If the trace file has review-only columns, choose the feature set explicitly:

```bash
logicpearl build traces.csv \
  --feature-columns role,resource,after_hours \
  --output-dir /tmp/pearl

logicpearl build traces.csv \
  --exclude-columns source,note \
  --output-dir /tmp/pearl
```

`logicpearl build` also reads `logicpearl.yaml`:

```yaml
build:
  traces: traces.csv
  label_column: allowed
  exclude_columns:
    - source
    - note
  show_conflicts: true
  output_dir: output
```

When training parity is below 100%, ask LogicPearl to write a row-level
diagnostic report:

```bash
logicpearl build traces.csv \
  --show-conflicts \
  --output-dir /tmp/pearl
```

The report records the trace row hash, expected result, predicted result,
matched rules, rule-referenced feature values, and near-miss predicates. It is
an opt-in diagnostic sidecar, not part of the artifact's deterministic logic.

## Artifacts

A build writes a local artifact bundle:

- `artifact.json`
  Public manifest with schema version, artifact kind, engine version, IR
  version, file paths, hashes, and build inputs.
- `pearl.ir.json`
  Deterministic gate or action-policy IR.
- `build_report.json`
  Build details, discovery summary, provenance, and generated file hashes.
- `feature_dictionary.generated.json`
  Generated readable feature metadata when no dictionary was supplied.
- `pearl.wasm` / `pearl.wasm.meta.json`
  Optional browser/runtime deployables after compilation.
- native runner
  Optional same-host or target-specific executable after compilation.

The bundle directory is the normal CLI entrypoint:

```bash
logicpearl inspect /tmp/logicpearl-output
logicpearl run /tmp/logicpearl-output input.json
```

Python services can load the same artifact once and evaluate in-process:

```python
from logicpearl import LogicPearlEngine

engine = LogicPearlEngine.from_path("/tmp/logicpearl-output")
result = engine.evaluate({"age": 34, "is_member": True})
print(result["decision_kind"])
```

Browser apps can use [`@logicpearl/browser`](./packages/logicpearl-browser/README.md)
to load compiled Wasm artifact bundles.

See [docs/artifacts.md](./docs/artifacts.md) for the full bundle contract.

## Explanations And Feature Dictionaries

Feature dictionaries attach reviewer-facing meaning to raw feature IDs:

```bash
logicpearl build traces.csv \
  --feature-dictionary feature_dictionary.json \
  --output-dir /tmp/pearl
```

The dictionary can supply labels, messages, source anchors, and
counterfactual hints. It affects generated rule text, `inspect`, and `diff`.
It does not change runtime evaluation.

Do not fix unreadable output by patching labels after discovery. Generate a
dictionary from the same source that generated the traces, then pass it to
`build` or `discover`.

## Pipelines And Plugins

Most first-time workflows only need one artifact bundle. Use pipelines when
the staging is part of the contract:

- normalize raw input through an observer, then run a pearl
- run several pearls and combine explicit outputs
- attach a verifier plugin after a decision
- preserve stage-level traces for review

```bash
logicpearl pipeline validate examples/waf_edge/waf_edge.pipeline.json
logicpearl pipeline run examples/waf_edge/waf_edge.pipeline.json examples/waf_edge/input_block_sqli.json --json
logicpearl pipeline trace examples/waf_edge/waf_edge.pipeline.json examples/waf_edge/input_block_sqli.json --json
```

Plugins are local process boundaries for observers, trace sources, enrichers,
and verifiers. Treat plugin manifests from other repos, issues, or generated
examples as untrusted unless you explicitly trust them. Current plugin
execution records access posture and provenance, but it is not a hard OS
sandbox.

See [docs/pipelines.md](./docs/pipelines.md) and
[docs/plugins.md](./docs/plugins.md).

## Examples

- [Garden actions demo](./examples/demos/garden_actions/README.md)
  Learn a multi-action policy that chooses `water`, `fertilize`, `repot`, or
  `do_nothing`.
- [WAF edge demo](./examples/waf_edge/README.md)
  Observe HTTP requests, evaluate grouped pearls, and route to allow, deny, or
  review.
- [Content moderation demo](./examples/demos/content_moderation/README.md)
  Demonstrate guardrail-style routing.
- [Loan approval demo](./examples/demos/loan_approval/README.md)
  Show a familiar bounded eligibility workflow.
- [PII Shield](https://github.com/LogicPearlHQ/pii-shield)
  A separate repo that wires LogicPearl into a Claude Code hook.

## How It Compares

| Tool | Usually best for | LogicPearl is for |
| --- | --- | --- |
| RAG | Finding and summarizing open-ended context | Compiling bounded policy decisions once facts are known |
| Prompts | Flexible language reasoning | Repeatable decisions that should not improvise |
| ML classifiers | Statistical prediction | Reviewable deterministic behavior on normalized inputs |
| Decision tables | Manually maintained rules | Learned, hashed, diffable, deployable artifacts |
| OPA / Rego | Hand-written policy | Policy learned from reviewed traces plus maintained constraints |
| Legacy conditionals | Embedded application behavior | Extracted behavior boundaries with parity and semantic diffs |

## Project Status

LogicPearl is a single-maintainer project at version 0.1.x. The core engine,
CLI, runtime, artifact format, and schemas are MIT licensed.

The core is domain-agnostic. Examples exercise the engine and show integration
patterns; they are not special cases built into the core.

## Open Core Policy

The open-source core is the local artifact workflow:

- `logicpearl` CLI: build, inspect, run, diff, compile, and verify
- Rust crates for IR, runtime, engine loading, discovery, schemas,
  verification, plugins, pipelines, conformance, rendering, and benchmarks
- published artifact and runtime JSON schemas under [schema](./schema/)
- [`@logicpearl/browser`](./packages/logicpearl-browser/README.md) for
  browser-safe evaluation of open artifact bundles
- checked-in examples, fixtures, benchmark protocols, and docs needed to
  reproduce public claims

Those pieces are MIT licensed and are intended to stay open. New functionality
required to build, inspect, run, verify, diff, and reproduce local LogicPearl
artifacts belongs in the open core.

Commercial tooling may exist around the core, but not replace it. Examples
include hosted trace ingestion, team dashboards, hosted artifact registries,
monitoring, review workflows, managed benchmark runs, and enterprise
administration.

Telemetry and data posture:

- the local CLI and runtime do not call home during normal use
- no telemetry or analytics are collected by the local CLI/runtime
- hosted services, if offered, must document what data they receive, retain,
  and process
- customer traces, source manifests, plugin outputs, and artifact contents
  must not be used for training or benchmarking without explicit permission
- self-hosted and local artifact workflows must remain usable without a hosted
  account

Contributions are welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Repository Layout

- `crates/logicpearl`
  User-facing CLI.
- `crates/logicpearl-*`
  Core Rust libraries for IR, runtime, discovery, pipelines, verification,
  rendering, conformance, and benchmark adaptation.
- `packages/logicpearl-browser`
  Browser runtime package for Wasm artifact bundles.
- `packages/logicpearl-python`
  Python bindings over the Rust execution surface.
- `examples`
  Small runnable examples and demos.
- `benchmarks`
  Public benchmark corpora and parity examples.
- `fixtures`
  Tiny inspection and runtime inputs used by tests and examples.
- `schema`
  Published JSON schemas for public artifact formats.
- `docs`
  Topic docs for artifact contracts, provenance, plugins, pipelines, browser
  runtime, conformance, development, and advanced guides.

## Further Docs

- [Docs index](./docs/README.md)
- [Artifacts](./docs/artifacts.md)
- [Feature dictionaries](./docs/feature-dictionary.md)
- [Provenance](./docs/provenance.md)
- [Plugins](./docs/plugins.md)
- [Pipelines](./docs/pipelines.md)
- [Browser runtime](./docs/browser-runtime.md)
- [Python runtime](./docs/python-runtime.md)
- [Conformance](./docs/conformance.md)
- [Development](./docs/development.md)
- [Benchmarks](./BENCHMARKS.md)
- [Datasets](./DATASETS.md)
