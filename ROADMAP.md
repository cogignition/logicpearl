# Roadmap

This is a living document. It describes current direction, not a binding delivery commitment.

LogicPearl is currently a single-maintainer 0.1.x project. The launch focus is the local artifact workflow:

```text
build -> inspect -> run -> verify -> diff
```

## Current Status

Already in the public repo:

- local CLI for building, inspecting, running, diffing, compiling, digesting, and verifying artifacts
- versioned artifact manifest and runtime JSON schemas
- gate, action, and pipeline artifact support
- feature dictionaries, source manifests, build provenance, plugin provenance, and artifact hashes
- browser runtime package source under `packages/logicpearl-browser`
- checked-in getting-started, garden actions, WAF edge, guardrail, and OPA/Rego examples
- reproducible benchmark documentation that distinguishes checked-in scorecards from larger non-vendored corpus protocols
- GitHub Release bundle automation and Homebrew formula generation

Some surfaces are intentionally still early:

- plugin and pipeline execution APIs
- Python packaging and bindings
- large public guardrail corpus score reporting
- hosted or team workflows

## Near-Term Priorities

1. Launch documentation and onboarding

   Keep README, install docs, quickstart output, and examples focused on the core artifact loop. Avoid making optional plugin, pipeline, browser, and benchmark surfaces look required for first use.

2. Reproducible benchmark evidence

   Promote only benchmark rows with committed or published provenance: commit SHA, LogicPearl version, solver/backend, dataset hashes, bundle hashes, host info, and rerun count. Keep native-gold metrics separate from observer-projected metrics.

3. Runtime and artifact contract hardening

   Continue treating versioned schemas, golden fixtures, browser types, artifact manifests, digest/verify commands, and path confinement as release gates.

4. Build provenance and privacy hardening

   Keep provenance useful for audit without storing free-form secrets. Redact or hash plugin options, source references, build options, stdout/stderr summaries, and other untrusted text by default, then allowlist safe operational fields.

5. Installation and packaging polish

   Keep release assets, checksums, install docs, Homebrew formula generation, and installer smoke tests aligned before public announcements.

## Medium-Term Priorities

- Publish `@logicpearl/browser` when the package API and release process are stable enough for outside users.
- Decide whether Python support should be a thin binding over `logicpearl-engine`, a subprocess wrapper, or a deferred integration.
- Add API documentation coverage for published Rust crates.
- Expand conformance tests around runtime JSON schemas, artifact manifests, plugin provenance, and source manifests.
- Add measured runtime latency benchmarks separately from classification/parity benchmark docs.
- Improve benchmark automation so large-corpus reports emit a single reviewable provenance artifact.

## Stability Policy

LogicPearl is pre-1.0, so CLI flags and advanced APIs may still change. The intent is still to avoid accidental drift in public contracts.

Stable or stabilizing contracts:

- `logicpearl.artifact_manifest.v1`
- `logicpearl.runtime_result.v1`
- `logicpearl.gate_result.v1`
- `logicpearl.action_result.v1`
- `logicpearl.pipeline_result.v1`
- `logicpearl.rule_explanation.v1`
- `logicpearl.feature_explanation.v1`
- `logicpearl.artifact_error.v1`
- `logicpearl.build_provenance.v1`
- `logicpearl.plugin_run_provenance.v1`
- `logicpearl.source_manifest.v1`

Policy:

- additive fields are allowed within a v1 schema
- breaking wire-format changes require a v2 schema
- generated artifacts should declare schema and engine versions
- runtime evaluation must not depend on explanation metadata
- feature dictionary and source manifest metadata may improve readability and auditability, but must not change deterministic evaluation

Less stable surfaces:

- plugin manifest ergonomics and sandbox metadata
- pipeline composition syntax
- benchmark adapter profiles
- Python package shape
- hosted service APIs, if any are introduced

## Open Core Boundary

The MIT open core includes:

- local CLI workflows for build, inspect, run, verify, digest, diff, and compile
- Rust crates needed for IR, discovery, runtime evaluation, engine loading, schemas, provenance, plugins, pipelines, conformance, verification, rendering, and benchmark adaptation
- JSON schemas and reproducibility fixtures
- browser-safe artifact evaluation package source
- examples and benchmark protocols needed to reproduce public claims

Commercial tooling may be built around the core, for example:

- hosted trace ingestion
- team review queues
- hosted artifact registry and dashboards
- monitoring and drift reporting
- managed benchmark runs
- enterprise access control and administration

Commercial tooling should not be required to build, inspect, run, verify, diff, or reproduce local LogicPearl artifacts.

Telemetry and data posture:

- local CLI/runtime should not call home during normal use
- local CLI/runtime should not collect telemetry or analytics
- hosted services must document received data, retention, and processing
- customer traces, source manifests, plugin outputs, and artifacts must not be used for training or public benchmarking without explicit permission

## Maintainer And Support Expectations

- This is currently a single-maintainer project.
- GitHub issues and discussions are handled on a best-effort basis.
- Security and privacy issues should be clearly labeled and will be prioritized over feature work.
- No response-time SLA is implied by the open-source repo.
- Commercial support, if offered later, should be documented separately from the MIT core.

## Not Planned For Core

- healthcare, WAF, guardrail, payer, or other domain-specific parsing hard-coded into core crates
- hosted-account requirements for local artifact workflows
- silent telemetry in the local CLI/runtime
- using customer data for model training or public benchmark claims without explicit permission
