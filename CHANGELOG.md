# Changelog

All notable user-facing changes to this public repo should be added here.

## Unreleased

### Added
- Public `logicpearl plugin validate` and `logicpearl plugin run` commands for stage-agnostic plugin validation and smoke testing.
- Public `logicpearl diff` command for semantic artifact diffs that downplay raw bit reordering.
- Canonical plugin payload guidance around `payload.input`, with backward-compatible aliases for observer, trace-source, enricher, and verify stages.
- Build provenance in `build_report.json`, including plugin manifest details and optional source references.
- Browser runtime tests in the public pre-commit hook alongside the Rust E2E checks.

### Changed
- Public example plugins now prefer `payload.input` while still accepting the older stage-specific aliases.
- Observer and trace-source flows now send the canonical payload shape in addition to compatibility aliases.
- Discovery now suppresses numeric exact-match rules on high-cardinality numeric features and requires minimum support for remaining numeric exact matches, which reduces singleton overfitting in learned artifacts.
