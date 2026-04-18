# LogicPearl Docs

The README is the shortest path through the main LogicPearl loop:

```text
build -> inspect -> run -> verify -> diff
```

Use these pages when you need the reference material behind that loop.

Long-running `build` and `discover` runs can report phase progress on stderr:

```bash
logicpearl build traces.csv --json --progress > build-result.json
```

The JSON result stays on stdout for piping into tools such as `jq`.
Candidate discovery also reports subphase ticks while enumerating atomic,
numeric, feature-reference, and conjunction candidates.

## Start Here

- [Install](./install.md)
  Verified release downloads, Homebrew, source install, and convenience installer.
- [Terminology](../TERMINOLOGY.md)
  Core vocabulary: traces, observers, pearls, bitmasks, pipelines, and correctness scope.
- [Feature dictionaries](./feature-dictionary.md)
  Reviewer-facing labels, messages, source anchors, and counterfactual hints without changing runtime evaluation.
- [Observation schemas](./observations.md)
  Upstream observed-feature contracts for extraction plugins before review and build.

## Core Contracts

- [Artifacts](./artifacts.md)
  Bundle layout, `artifact.json`, runtime JSON schemas, digest, verify, and compile.
- [Provenance](./provenance.md)
  Build reports, source manifests, generated file hashes, plugin boundary hashes, and privacy posture.
- [Conformance](./conformance.md)
  Runtime parity, formal spec checks, schema fixtures, and reproducibility receipts.

## Integrations

- [Plugins](./plugins.md)
  Local process plugins for observers, trace sources, enrichers, and verifiers.
- [Pipelines](./pipelines.md)
  Multi-stage execution with explicit stage inputs plus first-class override pipelines for layered pearls.
- [Browser runtime](./browser-runtime.md)
  Browser-safe Wasm evaluation through `@logicpearl/browser`.
- [Python runtime](./python-runtime.md)
  In-process Python bindings over `logicpearl-engine`.

## Evidence And Examples

- [Benchmarks](../BENCHMARKS.md)
  Reproducible scorecards and benchmark provenance.
- [Datasets](../DATASETS.md)
  Dataset inventory, licensing, and corpus notes.
- [Advanced guardrail guide](./advanced-guardrail-guide.md)
  Guardrail benchmark and observer workflow.
- [Garden actions demo](../examples/demos/garden_actions/README.md)
  Multi-action policy from reviewed plant-care notes.
- [WAF edge demo](../examples/waf_edge/README.md)
  Pipeline-style edge-routing example.
- [OPA / Rego parity example](../benchmarks/opa_rego/README.md)
  Policy parity workflow against Rego examples.

## Project

- [Roadmap](../ROADMAP.md)
  Current status, stability policy, open-core boundary, and support expectations.
- [Changelog](../CHANGELOG.md)
  User-facing changes by release.
- [Contributing](../CONTRIBUTING.md)
  Contribution process.
- [Security](../SECURITY.md)
  Security reporting.
