# Changelog

All notable user-facing changes should be added here.

## Unreleased

### Added
- Versioned runtime JSON schemas for gate, action, pipeline, rule explanation, feature explanation, runtime result, and artifact error payloads under `schema/`.
- Golden runtime JSON fixtures plus Rust schema-validation coverage for CLI-emitted gate, action, and pipeline results.
- Browser runtime TypeScript declarations and `evaluateJson()` / `evaluateJsonBatch()` helpers for schema-shaped gate and action results.
- Versioned `logicpearl.artifact_manifest.v1` schema-backed artifact manifests for gate, action, and composed pipeline bundles.
- `logicpearl artifact inspect`, `logicpearl artifact digest`, and `logicpearl artifact verify` for public bundle inspection and integrity checks.
- Configurable action-policy rule budgets via `--action-max-rules`, plus support-scaled default budgets for multi-action builds.
- Priority-aware action learning with optional `--action-priority`, so higher-priority actions learn first and lower-priority actions learn against residual rows.
- Pre-commit verification now runs artifact entrypoint smoke tests that cover `inspect`, `run`, and `diff` for bundle directories, `artifact.json`, and direct `pearl.ir.json` paths.
- Versioned `logicpearl.build_provenance.v1` provenance in build reports, including trace hashes, feature dictionary hashes, plugin boundary hashes, redacted build commands, build option hashes, limited environment metadata, and generated artifact file hashes.
- Versioned `logicpearl.source_manifest.v1` support via `logicpearl build --source-manifest`, with validated source metadata attached to build provenance without changing learned logic or runtime behavior.
- Versioned `logicpearl.plugin_run_provenance.v1` metadata for plugin-backed builds, plugin command JSON, and plugin-backed pipeline stages, including manifest, entrypoint, input/request/output, timeout, capability, access posture, row-count, timestamp, and redacted stdio hashes.

### Changed
- `logicpearl run --json` and `logicpearl pipeline run --json` now include `schema_version`, `engine_version`, and a deterministic `artifact_hash` in runtime result payloads.
- `artifact.json` now carries stable v1 bundle metadata including artifact kind, engine version, IR version, artifact hash, file hashes, and build option/input schema digests.
- Pipeline pearl stages now preserve canonical gate runtime details in `stages[].raw_result` while keeping exported fields such as `bitmask` and `allow` available.
- Wasm metadata now carries `engine_version` and `artifact_hash` so browser integrations can return v1 runtime JSON results.
- Action-policy discovery now preserves ordinal/count generalization across lower-priority actions instead of forcing every action route to learn against rows already captured by higher-priority rules.

### Fixed
- Artifact manifests written from relative `--output-dir` paths no longer double-prefix `files.ir`, and CLI/engine loaders tolerate already-written manifests with that redundant artifact-directory prefix.
- `deny.toml` no longer uses cargo-deny keys removed by newer cargo-deny releases, and no longer carries stale license check entries that produced warnings.
- `logicpearl inspect <action_artifact>/pearl.ir.json --json` now recognizes direct action policy IR files instead of trying to parse them as gate IR.

## 0.1.5 - 2026-04-12

### Added
- First-class feature dictionaries for `logicpearl build` and `logicpearl discover` via `--feature-dictionary`, embedding readable feature semantics into emitted artifacts without changing runtime evaluation.
- Dictionary-aware rule text, inspect output, and artifact diffs, including separate diff flags for source/schema changes, learned rule changes, and explanation-only changes.
- Feature dictionary documentation for developers building demos and integrations.
- Multi-action policies for datasets with an action column, so `logicpearl build --action-column next_action` can learn a deterministic policy that chooses actions such as `water`, `fertilize`, `repot`, or `do_nothing`.
- Action policy results now include the selected `action`, the matched-rule `bitmask`, and the rule metadata that explains the result.
- `logicpearl-engine` can load and run action policy bundles for applications that use LogicPearl as a library.
- JSON schema coverage for action policy artifacts.
- `logicpearl build --action-column ... --compile` now emits deployable action policies, including a native runner and, when the local Wasm target is installed, `pearl.wasm` plus `pearl.wasm.meta.json`.
- Action policy builds can now read normalized records from `trace_source` plugins, so adapters can turn source configs or fixtures into action traces before discovery.
- Runtime JSON explanations now include source-grounded feature details for matched rules, including feature labels, source ids, source anchors, state messages, and counterfactual hints when the artifact has feature dictionary metadata.
- The browser runtime can evaluate compiled action-policy Wasm bundles and return the selected action, candidate actions, matched rules, default/no-match state, and ambiguity note from the bitmask and metadata.
- `logicpearl diff` now understands action-policy bundles and reports action set, default action, rule predicate, rule priority, source/schema, and explanation-only changes separately.

### Changed
- Bumped the Rust workspace and package metadata to `0.1.5` for the next release.
- Refreshed the Rust lockfile to avoid the yanked `fastrand 2.4.0` transitive dependency.
- Action builds now produce one normal artifact bundle with `pearl.ir.json`, instead of separate per-action route artifacts.
- `logicpearl inspect` now shows action policies as readable `Action rules:`.
- `logicpearl run --json --explain` now uses a fuller result shape for gates and action policies, including artifact/policy ids, `decision_kind`, bitmask, matched rules, and rule explanations.
- The garden actions demo now uses the shorter config-driven CLI flow, generated feature labels, percent and gallon values in traces, and one inspectable action policy.

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
