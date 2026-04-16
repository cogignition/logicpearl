# Artifacts

A LogicPearl build writes a local artifact bundle. The bundle is the deployable unit for CLI execution, verification, diffs, browser packaging, and provenance review.

## Create A Bundle

```bash
logicpearl build examples/getting_started/decision_traces.csv \
  --output-dir /tmp/logicpearl-output
```

The output directory is the normal CLI entrypoint:

```bash
logicpearl inspect /tmp/logicpearl-output
logicpearl run /tmp/logicpearl-output examples/getting_started/new_input.json
logicpearl run /tmp/logicpearl-output examples/getting_started/new_input.json --json
```

You can also pass `artifact.json` or `pearl.ir.json` directly when a command supports artifact inputs.

## Bundle Layout

The standard bundle contains:

- `artifact.json`
  Versioned artifact manifest. This is the stable public bundle pointer.
- `pearl.ir.json`
  Deterministic gate or action-policy IR.
- `build_report.json`
  Discovery summary, build options digest, provenance block, and generated file hashes.
- `feature_dictionary.generated.json`
  Generated readable feature metadata when no dictionary was supplied.
- `pearl.wasm` and `pearl.wasm.meta.json`
  Optional Wasm deployables after compilation.
- native runner
  Optional same-host or target-specific executable after compilation.

The manifest schema lives at [schema/logicpearl-artifact-manifest-v1.schema.json](../schema/logicpearl-artifact-manifest-v1.schema.json).

## Manifest Contract

`artifact.json` declares:

- `schema_version`
- `artifact_id`
- `artifact_kind`
- `engine_version`
- `ir_version`
- `created_at`
- `artifact_hash`
- `files`
- `file_hashes`
- input, feature dictionary, source manifest, and build option hashes when available

Manifest file paths are bundle members, not arbitrary filesystem pointers. The CLI rejects absolute paths, parent-directory escapes, and symlink escapes for manifest members.

## Runtime JSON

Use `--json` when another system consumes runtime output:

```bash
logicpearl run /tmp/logicpearl-output examples/getting_started/new_input.json --json
```

Runtime result schemas live under [schema](../schema/):

- `logicpearl.runtime_result.v1`
- `logicpearl.gate_result.v1`
- `logicpearl.action_result.v1`
- `logicpearl.pipeline_result.v1`
- `logicpearl.override_pipeline_result.v1`
- `logicpearl.rule_explanation.v1`
- `logicpearl.feature_explanation.v1`
- `logicpearl.artifact_error.v1`

Additive fields are allowed within v1 schemas. Breaking wire-format changes require a new schema version.

Action results include the selected `action`, whether no learned rule matched
(`no_match`), and the configured `default_action`. When an action artifact was
built with `--no-match-action`, the result also carries `no_match_action` and
uses it instead of the business default whenever no action rule fires.

## Inspect, Digest, Verify

Use the artifact commands for bundle review:

```bash
logicpearl artifact inspect /tmp/logicpearl-output --json
logicpearl artifact digest /tmp/logicpearl-output
logicpearl artifact verify /tmp/logicpearl-output
```

`inspect` reports the bundle contract. `digest` prints stable hashes. `verify` checks the manifest, member paths, and file hashes.

## Compile

The CLI can run artifact bundles directly. Compilation is optional:

```bash
logicpearl compile /tmp/logicpearl-output
logicpearl compile /tmp/logicpearl-output --target wasm32-unknown-unknown
```

Same-host native compile is self-contained. Wasm and non-host targets use Cargo and need the requested Rust target plus cached dependencies.

For browser execution, use [browser-runtime.md](./browser-runtime.md) instead of calling raw Wasm exports.

## Diff

Compare two artifact versions after changing traces, dictionaries, constraints, or build options:

```bash
logicpearl diff /tmp/old-pearl /tmp/new-pearl
logicpearl diff /tmp/old-pearl /tmp/new-pearl --json
```

Diff output separates raw rule changes from explanation-only changes when feature dictionary metadata is present.

## What Artifacts Do Not Prove

An artifact proves what it can verify from its inputs and metadata:

- deterministic runtime behavior for normalized inputs
- file integrity within the bundle
- schema shape for public JSON contracts
- parity or spec results when conformance checks were run

It does not prove that the original traces were complete, unbiased, or universally correct. Treat the artifact as a deterministic boundary around a reviewed behavior slice.
