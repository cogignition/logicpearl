# Provenance

Provenance records where an artifact came from without making the runtime depend on that metadata.

The local CLI/runtime do not call home during normal use, and they do not collect telemetry or analytics.

## Build Provenance

Every build report includes a `logicpearl.build_provenance.v1` block with stable audit fields such as:

- engine version
- engine commit when available
- redacted build command
- redacted build options and build option hash
- input trace paths, hashes, and row counts
- feature dictionary path and hash when supplied
- source manifest path and hash when supplied
- plugin boundary hashes when plugins run
- generated artifact file hashes
- limited environment summary

Build provenance is written to `build_report.json`:

```bash
logicpearl build examples/getting_started/decision_traces.csv \
  --output-dir /tmp/logicpearl-output

jq '.provenance' /tmp/logicpearl-output/build_report.json
```

The schema lives at [schema/logicpearl-build-provenance-v1.schema.json](../schema/logicpearl-build-provenance-v1.schema.json).

## Rule Evidence

Learned rules carry non-semantic `logicpearl.rule_evidence.v2` metadata in
`rules[].evidence`. Runtime evaluation ignores this field. It exists so review
tools can connect a portable artifact back to the reviewed traces that supported
each rule.

Rule evidence records stable, bounded metadata:

- `support.denied_trace_count`
- `support.allowed_trace_count`
- capped `support.example_traces[]` entries with deterministic
  `trace_row_hash` values plus optional `source_id`, `source_anchor`,
  `citation`, and `quote_hash`
- `reliability` metrics computed from the training set: matched trace count,
  total denied/allowed denominators, precision, recall contribution,
  false-positive rate, and lift
- optional `simplifications[]` entries explaining why discovery dropped
  conjuncts or removed subsumed fragments, including the reason, dropped
  predicate text, before/after rule counts, score changes, and support changes

LogicPearl hashes trace quotes instead of embedding raw quote text in the IR.
That keeps portable artifacts from carrying source-document excerpts or
customer text by default. Store the underlying quote in the trace corpus or a
review system, and use the hash plus citation to verify it.

Inspect rule evidence explicitly:

```bash
logicpearl inspect /tmp/pearl --show-provenance
logicpearl inspect /tmp/pearl --show-provenance --json
```

Evidence-only diffs are reported separately from source-schema, learned-rule,
and rule-explanation changes.

## Source Manifests

Use a source manifest when traces or feature dictionaries came from policy documents, customer exports, public URLs, PDFs, manual policy notes, or synthetic fixtures:

```bash
logicpearl build traces.csv \
  --feature-dictionary feature_dictionary.json \
  --source-manifest sources.json \
  --output-dir /tmp/pearl
```

Generic shape:

```json
{
  "schema_version": "logicpearl.source_manifest.v1",
  "sources": [
    {
      "source_id": "access_policy_notes",
      "kind": "manual_policy",
      "title": "Access policy notes",
      "uri": "docs/policy.md",
      "retrieved_at": "2026-04-13T00:00:00Z",
      "content_hash": "sha256:...",
      "data_classification": "synthetic"
    }
  ]
}
```

The engine validates and hashes the manifest, then attaches it to build provenance. It does not fetch URLs, parse PDFs, or interpret domain-specific source names.

The schema lives at [schema/logicpearl-source-manifest-v1.schema.json](../schema/logicpearl-source-manifest-v1.schema.json).

## Plugin Provenance

Plugin-backed builds, plugin command JSON, and plugin-backed pipeline stages record `logicpearl.plugin_run_provenance.v1` metadata:

- plugin id and version
- manifest hash
- entrypoint hash
- request/input/output hashes
- timeout policy
- declared capabilities
- network and filesystem access posture
- row counts when applicable
- completion timestamp
- redacted stdio hashes

See [plugins.md](./plugins.md) for the plugin trust boundary and execution flags.

The schema lives at [schema/logicpearl-plugin-run-provenance-v1.schema.json](../schema/logicpearl-plugin-run-provenance-v1.schema.json).

## Redaction Policy

Provenance keeps hashes for audit correlation, but it does not store arbitrary free-form values by default.

Values are redacted or hashed by default for:

- plugin options
- source references
- build options
- trace plugin input
- plugin stdout and stderr summaries
- other untrusted free-form text

Only low-sensitivity operational fields are preserved in clear text. That policy is intentional: provenance should make builds reviewable without becoming a secret dump.

## Artifact Hashes

`artifact.json` and `build_report.json` both record generated file hashes. Use the artifact commands to review and verify them:

```bash
logicpearl artifact inspect /tmp/pearl --json
logicpearl artifact digest /tmp/pearl
logicpearl artifact verify /tmp/pearl
```

See [artifacts.md](./artifacts.md) for the full manifest contract.

## Hosted Services

The local workflow must remain usable without a hosted account. If hosted services are offered later, they should document:

- what data they receive
- how long data is retained
- what processing is performed
- whether telemetry exists
- whether customer traces, source manifests, plugin outputs, or artifacts are used for training or benchmarking

Customer data must not be used for training or public benchmark claims without explicit permission.
