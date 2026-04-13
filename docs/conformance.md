# Conformance

Conformance checks make artifact claims reviewable. They do not replace trace review, but they help prove that a bundle still matches a stated contract.

## Runtime Parity

Build an artifact first:

```bash
logicpearl build examples/getting_started/decision_traces.csv \
  --output-dir /tmp/logicpearl-output
```

Compare an artifact against labeled traces:

```bash
logicpearl conformance runtime-parity \
  /tmp/logicpearl-output \
  examples/getting_started/decision_traces.csv \
  --label-column allowed \
  --json
```

The artifact input can be a bundle directory, `artifact.json`, or `pearl.ir.json`.

Runtime parity answers a narrow question: does this artifact reproduce this labeled trace file?

## Formal Spec Verification

Verify a gate against an explicit formal spec:

```bash
logicpearl conformance spec-verify \
  /tmp/logicpearl-output \
  examples/getting_started/access_policy.spec.json \
  --json
```

Formal spec verification reports whether the artifact is complete for the spec rules and whether it has spurious rules relative to that spec. Strong claims require an explicit spec.

## Reproducibility Manifests

Write a conformance manifest that pins source, data, and artifact files:

```bash
logicpearl conformance write-manifest \
  --output /tmp/logicpearl-output/conformance_manifest.json \
  --artifact pearl=/tmp/logicpearl-output/artifact.json \
  --data traces=examples/getting_started/decision_traces.csv
```

Validate that the pinned files are still fresh:

```bash
logicpearl conformance validate-artifacts /tmp/logicpearl-output/conformance_manifest.json --json
```

Use this when a benchmark, demo, or release note depends on exact local files.

## Runtime Schema Fixtures

Committed fixtures under [fixtures/runtime](../fixtures/runtime/) validate the public runtime JSON contracts:

- `gate_result_v1.json`
- `action_result_v1.json`
- `pipeline_result_v1.json`
- `artifact_error_v1.json`

The schemas live under [schema](../schema/), and Rust E2E tests validate both golden fixtures and CLI-emitted JSON against those schemas.

## Artifact Manifest Tests

Artifact manifest tests cover:

- valid Draft 2020-12 schema shape
- gate, action, and pipeline bundle manifests
- `artifact inspect`, `artifact digest`, and `artifact verify`
- bundle member path confinement
- rejection of absolute paths, parent-directory escapes, and symlink escapes

These checks prevent accidental drift in public bundle contracts.

## What To Claim

Use precise wording:

- "runtime parity against this trace file"
- "schema-valid `logicpearl.gate_result.v1` output"
- "artifact file hashes verified against `artifact.json`"
- "formal spec complete for this spec"

Avoid broad wording like "verified policy" unless the evidence boundary is named.

## Related Docs

- [Artifacts](./artifacts.md)
- [Provenance](./provenance.md)
- [Benchmarks](../BENCHMARKS.md)
- [Datasets](../DATASETS.md)
