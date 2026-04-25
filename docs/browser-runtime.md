# Browser Runtime

Use `@logicpearl/browser` for browser-safe evaluation of compiled Wasm artifact bundles.

Do not call raw Wasm exports from application code. The loader owns feature-slot packing, bitmask decoding, metadata lookup, and versioned runtime JSON helpers.

## Status

The package source lives at [packages/logicpearl-browser](../packages/logicpearl-browser/). Until npm publication is ready, reference it as a local workspace or file dependency in browser integration work.

The package README is the API reference: [packages/logicpearl-browser/README.md](../packages/logicpearl-browser/README.md).

## Build A Wasm Bundle

Compile an artifact for browser use:

```bash
logicpearl build examples/getting_started/decision_traces.csv \
  --output-dir /tmp/browser-pearl

logicpearl compile /tmp/browser-pearl --target wasm32-unknown-unknown
```

The bundle should include:

- `artifact.json`
- `pearl.ir.json`
- `pearl.wasm`
- `pearl.wasm.meta.json`

`artifact.json` and `pearl.wasm.meta.json` carry the metadata needed for browser-safe evaluation.
The browser loader requires a v1 `artifact.json` and reads the Wasm paths from
canonical `files.wasm` and `files.wasm_metadata` entries. It does not fall back
to legacy file aliases or infer a conventional directory layout when
`artifact.json` is absent.

Fan-out pipeline artifacts use the same loading path. Build them with a column
that contains a scalar action, comma-separated actions, or an array of actions:

```bash
logicpearl build traces.csv \
  --fanout-column applicable_actions \
  --fanout-actions water,treat_pests,move_to_more_sun \
  --output-dir /tmp/browser-fanout \
  --compile
```

When `wasm32-unknown-unknown` is installed, `--compile` emits a fan-out Wasm
module and metadata. The module exposes one gate evaluator per action;
application code should still call `loadArtifact()` or
`loadArtifactFromBundle()` rather than raw exports.

## Load And Evaluate

```js
import { loadArtifact } from '@logicpearl/browser';

const artifact = await loadArtifact('/artifacts/authz');
const result = artifact.evaluate({
  account_age_days: 12,
  email_verified: true,
  risk_band: 'low',
});

console.log(result.allow);
console.log(result.primaryReason);
console.log(result.counterfactualHints);
```

`evaluate()` returns a browser-friendly shape with camelCase fields and a `BigInt` bitmask.

## Versioned Runtime JSON

Use `evaluateJson()` when an integration needs the same schema-shaped output as `logicpearl run --json`:

```js
const wireResult = artifact.evaluateJson(input);
console.log(wireResult.schema_version);
console.log(wireResult.artifact_hash);
```

`evaluateJson()` returns the snake_case `logicpearl.*_result.v1` shape for schema validation and cross-language handoff.
For action policies, this includes the selected `action`, the configured
`default_action`, `no_match`, and `no_match_action` when the artifact declares a
separate no-match fallback.

For fan-out pipelines, `evaluateJson()` returns
`logicpearl.fanout_result.v1` with `applicable_actions`, a `verdicts` object
keyed by action, and a `stages` array preserving action-gate order. Each verdict
contains the action gate's bitmask, matched rules, artifact identity, and nested
gate result.

## Supported Scope

The browser package currently supports:

- one compiled artifact bundle
- Wasm evaluation
- rule decoding from wasm metadata
- gate bundles
- action-policy bundles
- fan-out pipeline bundles
- versioned runtime JSON helpers

It does not support:

- plugin execution
- filesystem access
- shelling out to local processes
- general plugin-backed pipeline orchestration
- observer synthesis or benchmark workflows

Keep those concerns server-side. If an integration needs plugins, files, secrets, or server-only adapters, use the CLI or Rust engine on the server and expose only the normalized result needed by the browser.

## Trust Boundary

Browser evaluation is deterministic for normalized input and artifact bytes. It does not make the original trace data complete, and it does not validate that an artifact was reviewed.

Use [artifacts.md](./artifacts.md), [provenance.md](./provenance.md), and [conformance.md](./conformance.md) to review bundle integrity, provenance, and parity claims before serving a bundle to clients.
