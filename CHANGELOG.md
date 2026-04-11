# Changelog

All notable user-facing changes should be added here.

## Unreleased

### Added
- First-class feature dictionaries for `logicpearl build` and `logicpearl discover` via `--feature-dictionary`, embedding readable feature semantics into emitted artifacts without changing runtime evaluation.
- Dictionary-aware rule text, inspect output, and artifact diffs, including separate diff flags for source/schema changes, learned rule changes, and explanation-only changes.
- Feature dictionary documentation and repository guidance for LLM agents and integration authors.

### Changed
- Aligned Rust workspace and reserved Python package metadata with `@logicpearl/browser` at `0.1.4`.
- Refreshed the Rust lockfile to avoid the yanked `fastrand 2.4.0` transitive dependency.

## 0.1.2 - 2026-04-08

### Added
- Public `logicpearl plugin validate` and `logicpearl plugin run` commands for stage-agnostic plugin validation and smoke testing.
- Public `logicpearl diff` command for semantic artifact diffs that downplay raw bit reordering.
- Canonical plugin payload guidance around `payload.input` for observer, trace-source, enricher, and verify stages.
- Schema-backed plugin contracts in manifests for `payload.input`, `payload.options`, and successful plugin responses.
- Build provenance in `build_report.json`, including plugin manifest details and optional source references.
- Browser runtime tests in the public pre-commit hook alongside the Rust E2E checks.
- `logicpearl run` and `logicpearl pipeline run` now accept `-` or omitted input paths to read JSON from stdin, which makes shell composition and adapter debugging easier without changing runtime semantics.
- First-class `trace_source_plugin` stages in public pipelines, including explicit `payload` and `options` fields for non-object stage input and plugin configuration.
- Public `logicpearl-engine` crate as the library-level execution facade for app backends and services.
- Official `logicpearl` Python package under `reserved-python/logicpearl` as a thin native bridge over `logicpearl-engine`.

### Changed
- Public example plugins use `payload.input`.
- Observer and trace-source flows use the canonical payload shape.
- `logicpearl build` now passes repeated `--trace-plugin-option key=value` entries through to trace-source plugins instead of forcing plugins to smuggle config through input strings.
- README now explicitly tells users when to use the CLI, `logicpearl-engine`, or `@logicpearl/browser`.
- Discovery now suppresses numeric exact-match rules on high-cardinality numeric features and requires minimum support for remaining numeric exact matches, which reduces singleton overfitting in learned artifacts.
