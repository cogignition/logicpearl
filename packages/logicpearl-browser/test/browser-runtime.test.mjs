import test from 'node:test';
import assert from 'node:assert/strict';

import {
  decodeFiredRules,
  encodeFeatureSlots,
  loadArtifactFromBundle,
  loadArtifact,
  normalizeArtifactReference,
} from '../src/index.js';

const sampleManifest = {
  artifact_version: '1.0',
  artifact_name: 'demo',
  gate_id: 'demo_gate',
  files: {
    pearl_ir: 'pearl.ir.json',
    build_report: 'build_report.json',
    wasm_module: 'demo.pearl.wasm',
    wasm_metadata: 'demo.pearl.wasm.meta.json',
  },
  bundle: {
    bundle_kind: 'direct_pearl_bundle',
    cli_entrypoint: 'artifact.json',
    primary_runtime: 'wasm_module',
  },
};

const sampleMetadata = {
  gate_id: 'demo_gate',
  feature_count: 3,
  features: [
    { id: 'is_admin', index: 0, encoding: 'boolean' },
    { id: 'risk_score', index: 1, encoding: 'numeric' },
    { id: 'risk_band', index: 2, encoding: 'string_code' },
  ],
  string_codes: {
    low: 1,
    medium: 2,
    high: 3,
  },
  rules: [
    { id: 'rule_a', bit: 0, label: 'Rule A', counterfactual_hint: 'Change A' },
    { id: 'rule_b', bit: 2, label: 'Rule B', counterfactual_hint: 'Change B' },
  ],
};

const sampleMetadataWithObjectEncodings = {
  ...sampleMetadata,
  features: sampleMetadata.features.map((feature) => ({
    ...feature,
    encoding: { kind: feature.encoding },
  })),
};

test('normalizeArtifactReference handles bundle dirs and artifact manifests', () => {
  assert.deepEqual(normalizeArtifactReference('/demo/authz'), {
    manifestUrl: '/demo/authz/artifact.json',
    artifactBaseUrl: '/demo/authz',
  });
  assert.deepEqual(normalizeArtifactReference('/demo/authz/artifact.json'), {
    manifestUrl: '/demo/authz/artifact.json',
    artifactBaseUrl: '/demo/authz',
  });
});

test('encodeFeatureSlots maps booleans, numerics, and string codes', () => {
  const slots = encodeFeatureSlots(
    { is_admin: true, risk_score: '42', risk_band: 'high' },
    sampleMetadata
  );
  assert.equal(slots[0], 1);
  assert.equal(slots[1], 42);
  assert.equal(slots[2], 3);
});

test('encodeFeatureSlots supports object-form metadata encodings from wasm metadata', () => {
  const slots = encodeFeatureSlots(
    { is_admin: true, risk_score: '42', risk_band: 'high' },
    sampleMetadataWithObjectEncodings
  );
  assert.equal(slots[0], 1);
  assert.equal(slots[1], 42);
  assert.equal(slots[2], 3);
});

test('decodeFiredRules returns sorted rule metadata from bigint bitmask', () => {
  const fired = decodeFiredRules(5n, sampleMetadata.rules);
  assert.deepEqual(
    fired.map((rule) => rule.id),
    ['rule_a', 'rule_b']
  );
});

test('loadArtifactFromBundle evaluates through the stable browser API', async () => {
  const memory = new WebAssembly.Memory({ initial: 1 });
  let captured = null;
  const artifact = await loadArtifactFromBundle(
    {
      manifest: sampleManifest,
      wasmModule: new ArrayBuffer(8),
      wasmMetadata: sampleMetadata,
    },
    {
      instantiateWasm: async () => ({
        exports: {
          memory,
          logicpearl_alloc() {
            return 0;
          },
          logicpearl_dealloc() {},
          logicpearl_eval_bitmask_slots_f64(ptr, len) {
            captured = Array.from(new Float64Array(memory.buffer, ptr, len));
            return 5n;
          },
        },
      }),
    }
  );

  const result = artifact.evaluate({
    is_admin: false,
    risk_score: 17,
    risk_band: 'medium',
  });

  assert.deepEqual(captured, [0, 17, 2]);
  assert.equal(result.allow, false);
  assert.deepEqual(result.firedRuleIds, ['rule_a', 'rule_b']);
  assert.equal(result.primaryReason?.id, 'rule_a');
  assert.deepEqual(result.counterfactualHints, ['Change A', 'Change B']);
});

test('loadArtifact falls back to conventional pearl.wasm layout when artifact.json is absent', async () => {
  const responses = new Map([
    ['/demo/artifact.json', { ok: false, status: 404 }],
    ['/demo/pearl.wasm', { ok: true, arrayBuffer: async () => new ArrayBuffer(8) }],
    ['/demo/pearl.wasm.meta.json', { ok: true, json: async () => sampleMetadata }],
  ]);

  const artifact = await loadArtifact('/demo', {
    fetchImpl: async (url) => {
      const response = responses.get(url);
      if (!response) throw new Error(`unexpected url ${url}`);
      return response;
    },
    instantiateWasm: async () => ({
      exports: {
        memory: new WebAssembly.Memory({ initial: 1 }),
        logicpearl_alloc() { return 0; },
        logicpearl_dealloc() {},
        logicpearl_eval_bitmask_slots_f64() { return 0n; },
      },
    }),
  });

  const summary = artifact.inspect();
  assert.equal(summary.gateId, 'demo_gate');
  assert.equal(summary.primaryRuntime, 'wasm_module');
});

test('loadArtifact skips artifact.json entirely when conventional layout is requested', async () => {
  const seen = [];
  await loadArtifact('/demo', {
    layout: 'conventional',
    fetchImpl: async (url) => {
      seen.push(url);
      if (url === '/demo/artifact.json') {
        throw new Error('artifact.json should not be requested');
      }
      if (url === '/demo/pearl.wasm') {
        return { ok: true, arrayBuffer: async () => new ArrayBuffer(8) };
      }
      if (url === '/demo/pearl.wasm.meta.json') {
        return { ok: true, json: async () => sampleMetadata };
      }
      throw new Error(`unexpected url ${url}`);
    },
    instantiateWasm: async () => ({
      exports: {
        memory: new WebAssembly.Memory({ initial: 1 }),
        logicpearl_alloc() { return 0; },
        logicpearl_dealloc() {},
        logicpearl_eval_bitmask_slots_f64() { return 0n; },
      },
    }),
  });

  assert.deepEqual(seen, ['/demo/pearl.wasm', '/demo/pearl.wasm.meta.json']);
});
