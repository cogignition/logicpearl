# `@logicpearl/browser`

> **Note:** This package is not yet published to npm. To use it, copy the `packages/logicpearl-browser` directory into your project or reference it as a local dependency.

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

## Supported Inputs

`loadArtifact(...)` accepts:
- an artifact directory path or URL
- an `artifact.json` path or URL

`loadArtifactFromBundle(...)` accepts:
- a manifest object
- Wasm module bytes
- wasm metadata JSON

That second form is useful for tests, preloaded assets, and custom caching layers.

## Current Scope

This v1 package supports:
- one compiled LogicPearl artifact bundle
- Wasm evaluation
- rule decoding from wasm metadata
- binary gate and action-policy bundles

It does **not** support:
- full string-of-pearls pipeline orchestration
- observer/plugin execution
- automatic pipeline route evaluation

Keep those concerns above this single-artifact runtime instead of folding them into it.
