# Changelog

All notable user-facing changes to this public repo should be added here.

## Unreleased

## 0.1.2 - 2026-04-08

### Added
- Public `logicpearl plugin validate` and `logicpearl plugin run` commands for stage-agnostic plugin validation and smoke testing.
- Public `logicpearl diff` command for semantic artifact diffs that downplay raw bit reordering.
- Canonical plugin payload guidance around `payload.input`, with backward-compatible aliases for observer, trace-source, enricher, and verify stages.
- Schema-backed plugin contracts in manifests for `payload.input`, `payload.options`, and successful plugin responses.
- Public plugin migration guide at `docs/plugin-migration.md` for authors updating older manifests and payload handling.
- Build provenance in `build_report.json`, including plugin manifest details and optional source references.
- Browser runtime tests in the public pre-commit hook alongside the Rust E2E checks.
- `logicpearl run` and `logicpearl pipeline run` now accept `-` or omitted input paths to read JSON from stdin, which makes shell composition and adapter debugging easier without changing runtime semantics.
- First-class `trace_source_plugin` stages in public pipelines, including explicit `payload` and `options` fields for non-object stage input and plugin configuration.
- Public `logicpearl-engine` crate as the library-level execution facade for app backends and services.
- Official `logicpearl` Python package under `reserved-python/logicpearl` as a thin native bridge over `logicpearl-engine`.

### Changed
- Public example plugins now prefer `payload.input` while still accepting the older stage-specific aliases.
- Observer and trace-source flows now send the canonical payload shape in addition to compatibility aliases.
- `logicpearl build` now passes repeated `--trace-plugin-option key=value` entries through to trace-source plugins instead of forcing plugins to smuggle config through input strings.
- README now explicitly tells users when to use the CLI, `logicpearl-engine`, or `@logicpearl/browser`.
- Discovery now suppresses numeric exact-match rules on high-cardinality numeric features and requires minimum support for remaining numeric exact matches, which reduces singleton overfitting in learned artifacts.
