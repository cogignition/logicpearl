# Changelog

This project uses a lightweight semantic-versioning style for meaningful V3 milestones.

We update this file when there is a substantial improvement to:
- the generic engine,
- the artifact/runtime boundary,
- domain architecture,
- benchmark rigor,
- or product-level capabilities.

Small refactors, typo fixes, and narrow test-only changes do not need an entry unless they materially change behavior or trust.

The format is inspired by Keep a Changelog.

## [Unreleased]

### Added
- Native V3 implementations for decision-tree discovery, circuit compilation, and WASM generation.
- Full private claims benchmark stage caching across discovery, refinement, and runtime validation.
- Structured verification provenance in the formal Gate IR, including per-rule `verification_status` and top-level verification summary metadata.
- Benchmark output metadata and artifact manifest generation for the private claims audit benchmark.
- Internal MHK replacement-readiness planning material.
- Claims benchmark artifact validation via `validate_artifacts.py`.
- Generic trace-quality partitioning in the discovery engine with `trusted`, `quarantined`, and `excluded` buckets.
- Generic trace-quality and data-trust handling for pre-discovery validation.
- V3-owned `logicpearl.domains.opa` wrappers for parsing and evaluating Rego policies through the external `opa` tool.
- A V3 `opa_rego` benchmark that compares OPA policy decisions, LogicPearl pearls, emitted Gate IR, and `pearl-runtime` on the same RBAC dataset.

### Changed
- The private healthcare claims benchmark now runs without any direct `cirkit_engine.v2.*` imports.
- Warm full assisted claims runs now reuse cached discovery/refinement/runtime stages and drop from roughly 194s cold to roughly 13s warm.
- The private claims benchmark now distinguishes `z3_verified`, `heuristic_unverified`, and `refined_unverified` rules instead of overstating proof status.

## [0.4.0] - 2026-04-01

### Added
- V3-owned engine adapter seams for discovery, circuit compilation, and WASM compilation.
- Canonical Gate IR emission from the private claims benchmark.
- Rust runtime evaluation of emitted claims Gate IR artifacts.
- Generic safe-rule-authoring design and product workflow docs.
- Product spec for policy change management in enterprise settings.

### Changed
- The private claims benchmark now validates emitted artifacts through the runtime instead of only through the ad hoc Python gate path.
- Runtime batch evaluation now uses the built runtime binary directly for faster iteration.

## [0.3.0] - 2026-04-01

### Added
- Generic feature governance and rule-pruning modules under V3.
- V3-owned rule/gate seam for benchmark orchestration.
- Private claims benchmark quick-iteration mode with cleaner stage timing.
- Interaction pruning and redundancy pruning to reduce proxy-rule explosion.

### Changed
- The private claims benchmark moved away from direct V2 helper usage for pruning/governance logic.
- The assisted private claims benchmark improved from large unknown-rule tails to near-clean confirmed recovery.

## [0.2.0] - 2026-04-01

### Added
- Clean separation of claims domain adapter, demo oracle, and benchmark harness.
- private claims-domain, oracle, and benchmark structure.
- Claims adapter tests and benchmark documentation.

### Changed
- Claims healthcare work no longer lives as one mixed demo script; it is now split into reusable domain code, oracle generation, and benchmark evaluation.

## [0.1.0] - 2026-04-01

### Added
- Initial V3 repo structure with `discovery`, `runtime`, `schema`, `fixtures`, `docs`, and conformance harness.
- First Gate IR schema, docs, valid/invalid fixtures, and Python/Rust parity path.
- `uv`-managed discovery package with typed IR models and loaders.
- Rust runtime crate with IR loading, validation, evaluator, and CLI.
- Cross-implementation conformance harness.
- Observer spec, feature contract, validation stack, and executable observer runner.
- Bitmask and heatmap rendering for demo artifacts.
- V3 patent-aligned architecture docs and glossary/terminology updates.

### Changed
- The project moved from an early mixed architecture toward a clean V3 split between generic engine, domain adapters, demos/oracles, and benchmarks.
