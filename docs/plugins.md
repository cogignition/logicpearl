# Plugins

Plugins are optional integration boundaries. They let LogicPearl call local processes that adapt input, generate traces, enrich features, or verify pipeline output.

Treat plugin manifests from other repos, issues, or generated examples as untrusted unless you explicitly trust them.

## Plugin Stages

Supported plugin stages include:

- `observer`
  Turns raw input into normalized features.
- `trace_source`
  Emits decision traces for `logicpearl build`.
- `enricher`
  Adds derived data before discovery or execution.
- `verify`
  Checks an artifact or pipeline result against an external rule.

The core engine does not assign domain meaning to plugin output. Domain integrations own that mapping and should express reviewer-facing meaning through feature dictionaries and source manifests.

## Validate And Run

Validate a manifest without a smoke input:

```bash
logicpearl plugin validate examples/plugins/python_observer/manifest.json
```

Validate and execute a smoke input:

```bash
logicpearl plugin validate examples/plugins/python_observer/manifest.json \
  --input examples/plugins/python_observer/raw_input.json \
  --json
```

Run a plugin directly:

```bash
logicpearl plugin run examples/plugins/python_observer/manifest.json \
  --input examples/plugins/python_observer/raw_input.json \
  --json
```

Run a trace-source plugin:

```bash
logicpearl plugin run examples/plugins/python_trace_source/manifest.json \
  --input-string examples/getting_started/decision_traces.csv \
  --option label_column=allowed \
  --json
```

## Plugin-Backed Builds

Trace-source plugins can feed `logicpearl build`:

```bash
logicpearl build \
  --trace-plugin-manifest examples/plugins/python_trace_source/manifest.json \
  --trace-plugin-input examples/getting_started/decision_traces.csv \
  --trace-plugin-option label_column=allowed \
  --output-dir /tmp/plugin-built-pearl
```

Plugin options and inputs are hashed or redacted in provenance by default.

## Manifest Shape

A minimal manifest declares identity, protocol, stage, entrypoint, schemas, and capabilities:

```json
{
  "name": "python-observer-demo",
  "plugin_id": "python-observer",
  "plugin_version": "0.1.0",
  "protocol_version": "1",
  "language": "python",
  "stage": "observer",
  "entrypoint": ["python3", "plugin.py"],
  "input_schema": {
    "type": "object"
  },
  "output_schema": {
    "type": "object"
  },
  "capabilities": ["raw_json_input", "feature_output"]
}
```

See [examples/plugins/python_observer/manifest.json](../examples/plugins/python_observer/manifest.json) and [examples/plugins/python_trace_source/manifest.json](../examples/plugins/python_trace_source/manifest.json).

## Canonical Payload

Plugin commands wrap simple inputs into a canonical request payload. For most stages:

- use `--input path/to/input.json` for object input
- use `--input-string value` for string input, especially trace-source plugins
- use repeated `--option key=value` entries for plugin options
- use `--raw-payload` only when testing exact protocol payloads

The plugin response must match the manifest output schema.

## Execution Policy

Default plugin execution is intentionally conservative:

- timeouts are applied
- manifest-relative scripts are allowed
- absolute executable or script paths are rejected unless explicitly allowed
- arbitrary `PATH` lookup is rejected unless explicitly allowed
- `timeout_ms=0` is rejected unless explicitly allowed

Trusted-only opt-ins:

```bash
logicpearl plugin run manifest.json --input input.json --allow-no-timeout
logicpearl plugin run manifest.json --input input.json --allow-absolute-plugin-entrypoint
logicpearl plugin run manifest.json --input input.json --allow-plugin-path-lookup
```

These flags are also available on plugin-backed build, verify, benchmark, observer, and pipeline commands where local plugin execution can occur.

Current process sandbox metadata records network and filesystem posture, but process-level network/filesystem isolation is not a hard sandbox. Use OS/container controls when you need hard isolation.

## Provenance

Plugin runs record `logicpearl.plugin_run_provenance.v1` metadata:

- plugin id and version
- manifest hash
- entrypoint hash
- request/input/output hashes
- timeout policy
- declared capabilities
- network/filesystem access posture
- row count when applicable
- redacted stdout and stderr hashes
- completion timestamp

See [provenance.md](./provenance.md) for the redaction and audit policy.

## When To Avoid Plugins

Do not use a plugin when a plain trace file or static artifact is enough. Plugins are for boundaries where something external must run:

- custom parsing
- source export conversion
- runtime observation
- external verification
- integration-specific enrichment

Keep plugin code outside browser-facing packages. Browser integrations should use [browser-runtime.md](./browser-runtime.md) for artifact evaluation only.
