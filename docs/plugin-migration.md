# Plugin Migration Guide

This note is for existing LogicPearl plugin authors updating to the newer public plugin contract.

## What Changed

LogicPearl now treats plugin IO as:

- canonical input: `payload.input`
- optional plugin config: `payload.options`
- schema-backed manifest contracts:
  - `input_schema`
  - `options_schema`
  - `output_schema`

LogicPearl enforces those contracts in:

- `logicpearl plugin validate`
- `logicpearl plugin run`
- `logicpearl build` when using trace-source plugins
- `logicpearl pipeline run` for plugin-backed stages

## What You Should Update

### 1. Read `payload.input` first

Recommended pattern:

```python
payload = request.get("payload", {})
input_value = payload.get("input", payload.get("raw_input"))
```

Use the compatibility alias only as a fallback while migrating.

Current compatibility aliases are:

- observer: `payload.raw_input`
- trace_source: `payload.source`
- enricher: `payload.records`
- verify: `payload.pearl_ir`

### 2. Read explicit config from `payload.options`

Do not smuggle config through the input string or raw JSON unless that is actually the domain input.

Recommended pattern:

```python
options = payload.get("options", {})
label_column = options.get("label_column", "allowed")
```

### 3. Declare schemas in the manifest

Add formal schemas to the plugin manifest when possible:

```json
{
  "input_schema": { "type": "string" },
  "options_schema": {
    "type": "object",
    "required": ["label_column"],
    "properties": {
      "label_column": { "type": "string" }
    }
  },
  "output_schema": {
    "type": "object",
    "required": ["ok", "decision_traces"]
  }
}
```

Supported JSON Schema subset:

- `type`
- `properties`
- `required`
- `items`
- `enum`
- `const`
- `additionalProperties`

## New Pipeline Shape

Pipelines can now use `trace_source_plugin` stages directly.

Use:

- `payload` for stage input
- `options` for plugin config

Example:

```json
{
  "id": "trace_source",
  "kind": "trace_source_plugin",
  "plugin_manifest": "../../plugins/python_trace_source/manifest.json",
  "payload": "$.source",
  "options": {
    "label_column": "$.label_column"
  },
  "export": {
    "decision_traces": "$.decision_traces"
  }
}
```

## Build-Time Trace Plugins

`logicpearl build` now supports repeated trace plugin options:

```bash
logicpearl build \
  --trace-plugin-manifest examples/plugins/python_trace_source/manifest.json \
  --trace-plugin-input examples/getting_started/decision_traces.csv \
  --trace-plugin-option label_column=allowed
```

Those options are forwarded into `payload.options` and are also recorded in `build_report.json`.

## Fastest Way To Check Your Plugin

Use the generic plugin commands first:

```bash
logicpearl plugin validate path/to/manifest.json
logicpearl plugin run path/to/manifest.json --input input.json --json
```

That shows:

- the canonical request envelope LogicPearl sent
- the declared manifest schemas
- the exact response your plugin returned

## Migration Rule

Update your plugin if it currently:

- reads only `payload.raw_input`, `payload.source`, `payload.records`, or `payload.pearl_ir`
- expects config to be embedded into the input value
- has no declared manifest schema even though the input/output shape is stable

If a plugin already reads `payload.input` and `payload.options`, it is probably close to done.
