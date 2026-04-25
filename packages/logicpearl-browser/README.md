# `@logicpearl/browser`

Official browser/runtime loader for LogicPearl Wasm artifact bundles.

This package is the supported JavaScript entrypoint for browser-facing LogicPearl usage.

It exists so application code does **not** need to know about:
- raw Wasm export names
- `BigInt` bitmask decoding
- feature-slot packing
- wasm metadata lookup

## Intended Usage

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

When an integration needs the exact versioned runtime JSON contract, use
`evaluateJson()`:

```js
const wireResult = artifact.evaluateJson(input);
console.log(wireResult.schema_version);
console.log(wireResult.artifact_hash);
```

`evaluate()` keeps the browser-friendly camelCase shape with a `BigInt`
bitmask. `evaluateJson()` returns the snake_case `logicpearl.*_result.v1`
shape for schema validation and cross-language handoff.

For fan-out pipeline bundles, `evaluate()` returns `applicableActions` plus a
per-action `verdicts` object. `evaluateJson()` returns
`logicpearl.fanout_result.v1`, including the same applicable-action list,
per-action gate verdicts, and nested gate-shaped results.

## Distribution

The package source lives in this repository while npm publication is being prepared. During local integration work, reference `packages/logicpearl-browser` as a workspace or file dependency.

## Supported Inputs

`loadArtifact(...)` accepts:
- an artifact directory path or URL
- an `artifact.json` path or URL using `logicpearl.artifact_manifest.v1`

The manifest must declare canonical v1 file keys. Path excerpt:

```json
{
  "schema_version": "logicpearl.artifact_manifest.v1",
  "files": {
    "ir": "pearl.ir.json",
    "wasm": "pearl.wasm",
    "wasm_metadata": "pearl.wasm.meta.json"
  }
}
```

The browser loader does not probe conventional layouts or legacy file aliases
such as `files.wasm_module`; serve the v1 `artifact.json` with the bundle.

`loadArtifactFromBundle(...)` accepts:
- a `logicpearl.artifact_manifest.v1` manifest object
- Wasm module bytes
- wasm metadata JSON

That second form is useful for tests, preloaded assets, and custom caching layers.

## Current Scope

This v1 package supports:
- one compiled LogicPearl artifact bundle
- Wasm evaluation
- rule decoding from wasm metadata
- binary gate and action-policy bundles
- fan-out pipeline bundles

It does **not** support:
- general plugin-backed pipeline orchestration
- observer/plugin execution
- automatic pipeline route evaluation

Keep those concerns above this single-artifact runtime instead of folding them into it.
