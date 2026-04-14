# LogicPearl Docs

The README is the shortest path through the product. `logicpearl quickstart` points to the product loop:

```text
build -> inspect -> run -> verify -> diff
```

Use these pages when you need the reference material behind that loop.

## Start Here

- [Install](./install.md)
  Verified release downloads, Homebrew, source install, and convenience installer.
- [Terminology](../TERMINOLOGY.md)
  Core vocabulary: traces, observers, pearls, bitmasks, pipelines, and correctness scope.
- [Feature dictionaries](./feature-dictionary.md)
  Reviewer-facing labels, messages, source anchors, and counterfactual hints without changing runtime evaluation.

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
  Multi-stage "string of pearls" execution with explicit stage inputs and exports.
- [Browser runtime](./browser-runtime.md)
  Browser-safe Wasm evaluation through `@logicpearl/browser`.

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
