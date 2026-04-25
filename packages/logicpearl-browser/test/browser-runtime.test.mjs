import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  decodeFiredRules,
  encodeFeatureSlots,
  loadArtifactFromBundle,
  loadArtifact,
  normalizeArtifactReference,
} from '../src/index.js';

const coercionFixture = JSON.parse(
  readFileSync(
    new URL('../../../fixtures/runtime/input_coercion_cases.json', import.meta.url),
    'utf8'
  )
);
const gateResultSchema = JSON.parse(
  readFileSync(
    new URL('../../../schema/logicpearl-gate-result-v1.schema.json', import.meta.url),
    'utf8'
  )
);
const actionResultSchema = JSON.parse(
  readFileSync(
    new URL('../../../schema/logicpearl-action-result-v1.schema.json', import.meta.url),
    'utf8'
  )
);
const fanoutResultSchema = JSON.parse(
  readFileSync(
    new URL('../../../schema/logicpearl-fanout-result-v1.schema.json', import.meta.url),
    'utf8'
  )
);

function validateAgainstSchema(schema, instance) {
  const errors = validateSchemaNode(schema, instance, schema, '$');
  assert.deepEqual(errors, [], JSON.stringify(instance, null, 2));
}

function validateSchemaNode(schema, value, root, path) {
  if (schema.$ref) {
    return validateSchemaNode(resolveSchemaRef(root, schema.$ref), value, root, path);
  }

  if (schema.oneOf) {
    const branchErrors = schema.oneOf.map((branch) =>
      validateSchemaNode(branch, value, root, path)
    );
    const matches = branchErrors.filter((errors) => errors.length === 0).length;
    return matches === 1
      ? []
      : [`${path} should match exactly one oneOf branch; matched ${matches}`];
  }

  const errors = [];
  if (Object.hasOwn(schema, 'const') && value !== schema.const) {
    errors.push(`${path} should equal ${JSON.stringify(schema.const)}`);
  }
  if (schema.type && !schemaTypeMatches(schema.type, value)) {
    errors.push(`${path} should be ${JSON.stringify(schema.type)}`);
    return errors;
  }
  if (schema.pattern && typeof value === 'string' && !new RegExp(schema.pattern).test(value)) {
    errors.push(`${path} should match ${schema.pattern}`);
  }
  if (schema.minLength !== undefined && typeof value === 'string' && value.length < schema.minLength) {
    errors.push(`${path} should have length >= ${schema.minLength}`);
  }
  if (schema.minimum !== undefined && typeof value === 'number' && value < schema.minimum) {
    errors.push(`${path} should be >= ${schema.minimum}`);
  }
  if (schema.required && isPlainObject(value)) {
    for (const key of schema.required) {
      if (!Object.hasOwn(value, key)) errors.push(`${path}.${key} is required`);
    }
  }
  if (schema.properties && isPlainObject(value)) {
    for (const [key, childSchema] of Object.entries(schema.properties)) {
      if (Object.hasOwn(value, key)) {
        errors.push(...validateSchemaNode(childSchema, value[key], root, `${path}.${key}`));
      }
    }
  }
  if (schema.items && Array.isArray(value)) {
    value.forEach((item, index) => {
      errors.push(...validateSchemaNode(schema.items, item, root, `${path}[${index}]`));
    });
  }
  return errors;
}

function resolveSchemaRef(root, ref) {
  assert.ok(ref.startsWith('#/'), `unsupported schema ref ${ref}`);
  return ref
    .slice(2)
    .split('/')
    .reduce((node, part) => node[part.replaceAll('~1', '/').replaceAll('~0', '~')], root);
}

function schemaTypeMatches(type, value) {
  const allowed = Array.isArray(type) ? type : [type];
  return allowed.some((kind) => {
    switch (kind) {
      case 'array':
        return Array.isArray(value);
      case 'boolean':
        return typeof value === 'boolean';
      case 'integer':
        return Number.isInteger(value);
      case 'null':
        return value === null;
      case 'number':
        return typeof value === 'number' && Number.isFinite(value);
      case 'object':
        return isPlainObject(value);
      case 'string':
        return typeof value === 'string';
      default:
        throw new Error(`unsupported schema type ${kind}`);
    }
  });
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

const sampleManifest = {
  schema_version: 'logicpearl.artifact_manifest.v1',
  artifact_id: 'demo_gate',
  artifact_kind: 'gate',
  engine_version: '0.1.5',
  ir_version: '1.0',
  created_at: '2026-04-12T00:00:00Z',
  artifact_hash: 'sha256:4b40f32b955a3f0325b05e39f06534b0aaed8691563d78e73761bd3d54e78a3f',
  files: {
    ir: 'pearl.ir.json',
    build_report: 'build_report.json',
    wasm: 'demo.pearl.wasm',
    wasm_metadata: 'demo.pearl.wasm.meta.json',
  },
};

const sampleMetadata = {
  engine_version: '0.1.5',
  artifact_hash: 'sha256:4b40f32b955a3f0325b05e39f06534b0aaed8691563d78e73761bd3d54e78a3f',
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
    {
      id: 'rule_a',
      bit: 0,
      label: 'Rule A',
      counterfactual_hint: 'Change A',
      features: [
        {
          feature_id: 'risk_score',
          feature_label: 'Risk score',
          source_id: 'risk_policy',
          source_anchor: 'score',
          state_label: 'Elevated risk',
          state_message: 'Risk score is elevated.',
          counterfactual_hint: 'Lower the risk score.',
        },
      ],
    },
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

const sampleActionMetadata = {
  engine_version: '0.1.5',
  artifact_hash: 'sha256:65da6c16f81dd283957eb0c36c6015dbb0a99192022164904d23ce012265a5f9',
  decision_kind: 'action',
  gate_id: 'garden_actions',
  action_policy_id: 'garden_actions',
  default_action: 'do_nothing',
  actions: ['water', 'do_nothing', 'fertilize'],
  feature_count: 2,
  features: [
    { id: 'soil_moisture_pct', index: 0, encoding: 'numeric' },
    { id: 'leaf_paleness_score', index: 1, encoding: 'numeric' },
  ],
  string_codes: {},
  rules: [
    {
      id: 'rule_000',
      bit: 0,
      action: 'water',
      priority: 0,
      label: 'Soil is dry',
      counterfactual_hint: 'Increase moisture',
      features: [
        {
          feature_id: 'soil_moisture_pct',
          feature_label: 'Soil moisture',
          source_id: 'garden_manual',
          source_anchor: 'watering',
          state_label: 'Dry soil',
          state_message: 'Soil moisture is below the watering threshold.',
          counterfactual_hint: 'Increase moisture',
        },
      ],
    },
    {
      id: 'rule_001',
      bit: 1,
      action: 'fertilize',
      priority: 1,
      label: 'Leaves are pale',
      counterfactual_hint: 'Reduce paleness',
    },
  ],
};

const sampleFanoutMetadata = {
  artifact_version: '1.0',
  engine_version: '0.1.5',
  artifact_hash: 'sha256:0bc569d4a84c229cd0ae13d94f8878b0f8e90728881be9a12e4a1c947f74d3fd',
  decision_kind: 'fanout',
  pipeline_id: 'garden_fanout',
  actions: [
    {
      action: 'water',
      id: 'water',
      artifact_id: 'garden_fanout_water',
      artifact_hash: 'sha256:05e08f69c35e2cce7f544f53619ff0424b6b2a1c597c86ac55f630d9927b2740',
      entrypoint: 'logicpearl_eval_bitmask_slots_f64_water',
      status_entrypoint: 'logicpearl_eval_status_slots_f64_water',
      allow_entrypoint: 'logicpearl_eval_allow_slots_f64_water',
      feature_count: 1,
      features: [{ id: 'soil_moisture_pct', index: 0, encoding: 'numeric' }],
      string_codes: {},
      rules: [{ id: 'water_rule', bit: 0, label: 'Soil is dry' }],
    },
    {
      action: 'treat_pests',
      id: 'treat_pests',
      artifact_id: 'garden_fanout_treat_pests',
      artifact_hash: 'sha256:3dbcbf7462a72997f0758ba073cb2f962a9663058d217d3a7dfdc213a4bd94d4',
      entrypoint: 'logicpearl_eval_bitmask_slots_f64_treat_pests',
      status_entrypoint: 'logicpearl_eval_status_slots_f64_treat_pests',
      allow_entrypoint: 'logicpearl_eval_allow_slots_f64_treat_pests',
      feature_count: 1,
      features: [{ id: 'pest_score', index: 0, encoding: 'numeric' }],
      string_codes: {},
      rules: [{ id: 'pest_rule', bit: 1, label: 'Pests are present' }],
    },
  ],
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
    { is_admin: true, risk_score: '42%', risk_band: 'high' },
    sampleMetadata
  );
  assert.equal(slots[0], 1);
  assert.equal(slots[1], 0.42);
  assert.equal(slots[2], 3);
});

test('encodeFeatureSlots matches shared runtime coercion fixtures', () => {
  const metadata = {
    feature_count: coercionFixture.features.length,
    features: coercionFixture.features,
    string_codes: coercionFixture.string_codes,
  };

  for (const fixtureCase of coercionFixture.cases) {
    assert.deepEqual(
      Array.from(encodeFeatureSlots(fixtureCase.input, metadata)),
      fixtureCase.expected_slots,
      fixtureCase.id
    );
  }
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
  assert.equal(result.decisionKind, 'gate');
  assert.equal(result.schemaVersion, 'logicpearl.gate_result.v1');
  assert.equal(result.engineVersion, '0.1.5');
  assert.equal(
    result.artifactHash,
    'sha256:4b40f32b955a3f0325b05e39f06534b0aaed8691563d78e73761bd3d54e78a3f'
  );
  assert.equal(result.artifactId, 'demo_gate');
  assert.equal(result.defaulted, false);
  assert.equal(result.ambiguity, null);
  assert.equal(result.allow, false);
  assert.deepEqual(result.firedRuleIds, ['rule_a', 'rule_b']);
  assert.equal(result.primaryReason?.id, 'rule_a');
  assert.deepEqual(result.counterfactualHints, ['Change A', 'Change B']);
});

test('evaluateJson returns gate runtime JSON v1 shape', async () => {
  const artifact = await loadArtifactFromBundle(
    {
      manifest: sampleManifest,
      wasmModule: new ArrayBuffer(8),
      wasmMetadata: sampleMetadata,
    },
    {
      instantiateWasm: async () => ({
        exports: {
          memory: new WebAssembly.Memory({ initial: 1 }),
          logicpearl_alloc() {
            return 0;
          },
          logicpearl_dealloc() {},
          logicpearl_eval_bitmask_slots_f64() {
            return 5n;
          },
        },
      }),
    }
  );

  const result = artifact.evaluateJson({
    is_admin: false,
    risk_score: 17,
    risk_band: 'medium',
  });

  validateAgainstSchema(gateResultSchema, result);
  assert.equal(result.schema_version, 'logicpearl.gate_result.v1');
  assert.equal(result.engine_version, '0.1.5');
  assert.equal(
    result.artifact_hash,
    'sha256:4b40f32b955a3f0325b05e39f06534b0aaed8691563d78e73761bd3d54e78a3f'
  );
  assert.equal(result.decision_kind, 'gate');
  assert.equal(result.bitmask, '5');
  assert.deepEqual(
    result.matched_rules.map((rule) => rule.id),
    ['rule_a', 'rule_b']
  );
  assert.equal(result.matched_rules[0].message, null);
  assert.deepEqual(result.matched_rules[0].features, [
    {
      feature_id: 'risk_score',
      feature_label: 'Risk score',
      source_id: 'risk_policy',
      source_anchor: 'score',
      state_label: 'Elevated risk',
      state_message: 'Risk score is elevated.',
      counterfactual_hint: 'Lower the risk score.',
    },
  ]);
});

test('loadArtifactFromBundle evaluates action policies from wasm metadata', async () => {
  const artifact = await loadArtifactFromBundle(
    {
      manifest: {
        ...sampleManifest,
        artifact_id: 'garden_actions',
        artifact_kind: 'action',
      },
      wasmModule: new ArrayBuffer(8),
      wasmMetadata: sampleActionMetadata,
    },
    {
      instantiateWasm: async () => ({
        exports: {
          memory: new WebAssembly.Memory({ initial: 1 }),
          logicpearl_alloc() {
            return 0;
          },
          logicpearl_dealloc() {},
          logicpearl_eval_bitmask_slots_f64() {
            return 3n;
          },
        },
      }),
    }
  );

  const result = artifact.evaluate({
    soil_moisture_pct: 0.14,
    leaf_paleness_score: 5,
  });

  assert.equal(result.decisionKind, 'action');
  assert.equal(result.artifactId, 'garden_actions');
  assert.equal(result.actionPolicyId, 'garden_actions');
  assert.equal(result.action, 'water');
  assert.equal(result.schemaVersion, 'logicpearl.action_result.v1');
  assert.equal(result.defaultAction, 'do_nothing');
  assert.equal(result.noMatchAction, null);
  assert.equal(result.defaulted, false);
  assert.equal(result.noMatch, false);
  assert.equal(result.ambiguity, 'multiple action rules matched: water, fertilize');
  assert.deepEqual(result.candidateActions, ['water', 'fertilize']);
  assert.deepEqual(
    result.selectedRules.map((rule) => rule.id),
    ['rule_000']
  );
  assert.deepEqual(result.counterfactualHints, ['Increase moisture']);
});

test('evaluateJson returns action runtime JSON v1 shape', async () => {
  const artifact = await loadArtifactFromBundle(
    {
      manifest: {
        ...sampleManifest,
        artifact_id: 'garden_actions',
        artifact_kind: 'action',
      },
      wasmModule: new ArrayBuffer(8),
      wasmMetadata: sampleActionMetadata,
    },
    {
      instantiateWasm: async () => ({
        exports: {
          memory: new WebAssembly.Memory({ initial: 1 }),
          logicpearl_alloc() {
            return 0;
          },
          logicpearl_dealloc() {},
          logicpearl_eval_bitmask_slots_f64() {
            return 1n;
          },
        },
      }),
    }
  );

  const result = artifact.evaluateJson({
    soil_moisture_pct: 0.12,
    leaf_paleness_score: 0.1,
  });

  validateAgainstSchema(actionResultSchema, result);
  assert.equal(result.schema_version, 'logicpearl.action_result.v1');
  assert.equal(result.action_policy_id, 'garden_actions');
  assert.equal(result.decision_kind, 'action');
  assert.equal(result.action, 'water');
  assert.equal(result.default_action, 'do_nothing');
  assert.equal(result.no_match_action, null);
  assert.equal(result.bitmask, '1');
  assert.equal(result.no_match, false);
  assert.deepEqual(result.candidate_actions, ['water']);
  assert.deepEqual(
    result.selected_rules.map((rule) => rule.id),
    ['rule_000']
  );
  assert.deepEqual(result.selected_rules[0].features, [
    {
      feature_id: 'soil_moisture_pct',
      feature_label: 'Soil moisture',
      source_id: 'garden_manual',
      source_anchor: 'watering',
      state_label: 'Dry soil',
      state_message: 'Soil moisture is below the watering threshold.',
      counterfactual_hint: 'Increase moisture',
    },
  ]);
});

test('loadArtifactFromBundle evaluates fan-out wasm metadata', async () => {
  const memory = new WebAssembly.Memory({ initial: 1 });
  const captured = {};
  const artifact = await loadArtifactFromBundle(
    {
      manifest: {
        ...sampleManifest,
        artifact_id: 'garden_fanout',
        artifact_kind: 'pipeline',
      },
      wasmModule: new ArrayBuffer(8),
      wasmMetadata: sampleFanoutMetadata,
    },
    {
      instantiateWasm: async () => ({
        exports: {
          memory,
          logicpearl_alloc() {
            return 0;
          },
          logicpearl_dealloc() {},
          logicpearl_eval_status_slots_f64_water() {
            return 0;
          },
          logicpearl_eval_bitmask_slots_f64_water(ptr, len) {
            captured.water = Array.from(new Float64Array(memory.buffer, ptr, len));
            return 1n;
          },
          logicpearl_eval_status_slots_f64_treat_pests() {
            return 0;
          },
          logicpearl_eval_bitmask_slots_f64_treat_pests(ptr, len) {
            captured.treat_pests = Array.from(new Float64Array(memory.buffer, ptr, len));
            return 2n;
          },
        },
      }),
    }
  );

  const result = artifact.evaluate({
    soil_moisture_pct: 0.12,
    pest_score: 0.9,
  });

  assert.equal(result.decisionKind, 'fanout');
  assert.equal(result.schemaVersion, 'logicpearl.fanout_result.v1');
  assert.equal(result.pipelineId, 'garden_fanout');
  assert.deepEqual(result.applicableActions, ['water', 'treat_pests']);
  assert.deepEqual(captured, { water: [0.12], treat_pests: [0.9] });
  assert.equal(result.verdicts.water.applies, true);
  assert.equal(result.verdicts.water.result.allow, false);
  assert.deepEqual(
    result.verdicts.treat_pests.matchedRules.map((rule) => rule.id),
    ['pest_rule']
  );
  assert.deepEqual(
    artifact.rules().map((rule) => rule.id),
    ['water_rule', 'pest_rule']
  );
});

test('evaluateJson returns fan-out runtime JSON v1 shape', async () => {
  const artifact = await loadArtifactFromBundle(
    {
      manifest: {
        ...sampleManifest,
        artifact_id: 'garden_fanout',
        artifact_kind: 'pipeline',
      },
      wasmModule: new ArrayBuffer(8),
      wasmMetadata: sampleFanoutMetadata,
    },
    {
      instantiateWasm: async () => ({
        exports: {
          memory: new WebAssembly.Memory({ initial: 1 }),
          logicpearl_alloc() {
            return 0;
          },
          logicpearl_dealloc() {},
          logicpearl_eval_status_slots_f64_water() {
            return 0;
          },
          logicpearl_eval_bitmask_slots_f64_water() {
            return 1n;
          },
          logicpearl_eval_status_slots_f64_treat_pests() {
            return 0;
          },
          logicpearl_eval_bitmask_slots_f64_treat_pests() {
            return 0n;
          },
        },
      }),
    }
  );

  const result = artifact.evaluateJson({
    soil_moisture_pct: 0.12,
    pest_score: 0,
  });

  validateAgainstSchema(fanoutResultSchema, result);
  assert.equal(result.schema_version, 'logicpearl.fanout_result.v1');
  assert.equal(result.decision_kind, 'fanout');
  assert.equal(result.pipeline_id, 'garden_fanout');
  assert.deepEqual(result.applicable_actions, ['water']);
  assert.equal(result.verdicts.water.applies, true);
  assert.equal(result.verdicts.treat_pests.applies, false);
  assert.equal(result.verdicts.water.bitmask, '1');
  assert.equal(result.verdicts.treat_pests.bitmask, '0');
  assert.deepEqual(result.stages.map((stage) => stage.action), ['water', 'treat_pests']);
});

test('evaluateJson returns no_match_action when no action rules fire', async () => {
  const artifact = await loadArtifactFromBundle(
    {
      manifest: {
        ...sampleManifest,
        artifact_id: 'garden_actions',
        artifact_kind: 'action',
      },
      wasmModule: new ArrayBuffer(8),
      wasmMetadata: {
        ...sampleActionMetadata,
        no_match_action: 'insufficient_context',
        actions: ['water', 'do_nothing', 'fertilize', 'insufficient_context'],
      },
    },
    {
      instantiateWasm: async () => ({
        exports: {
          memory: new WebAssembly.Memory({ initial: 1 }),
          logicpearl_alloc() {
            return 0;
          },
          logicpearl_dealloc() {},
          logicpearl_eval_bitmask_slots_f64() {
            return 0n;
          },
        },
      }),
    }
  );

  const result = artifact.evaluateJson({
    soil_moisture_pct: 0.5,
    leaf_paleness_score: 0.1,
  });

  validateAgainstSchema(actionResultSchema, result);
  assert.equal(result.action, 'insufficient_context');
  assert.equal(result.default_action, 'do_nothing');
  assert.equal(result.no_match_action, 'insufficient_context');
  assert.equal(result.defaulted, true);
  assert.equal(result.no_match, true);
  assert.deepEqual(result.matched_rules, []);
  assert.deepEqual(result.selected_rules, []);
  assert.deepEqual(result.candidate_actions, []);
});

test('evaluate treats all u64 bitmask values as valid payloads', async () => {
  const metadata = {
    ...sampleMetadata,
    feature_count: 1,
    features: [{ id: 'enabled', index: 0, encoding: 'boolean' }],
    rules: Array.from({ length: 64 }, (_, bit) => ({
      id: `rule_${bit}`,
      bit,
      label: `Rule ${bit}`,
    })),
  };
  const artifact = await loadArtifactFromBundle(
    {
      manifest: sampleManifest,
      wasmModule: new ArrayBuffer(8),
      wasmMetadata: metadata,
    },
    {
      instantiateWasm: async () => ({
        exports: {
          memory: new WebAssembly.Memory({ initial: 1 }),
          logicpearl_alloc() {
            return 0;
          },
          logicpearl_dealloc() {},
          logicpearl_eval_status_slots_f64() {
            return 0;
          },
          logicpearl_eval_bitmask_slots_f64() {
            return 18446744073709551615n;
          },
        },
      }),
    }
  );

  const result = artifact.evaluate({ enabled: true });

  assert.equal(result.bitmask, 18446744073709551615n);
  assert.equal(result.allow, false);
  assert.equal(result.firedRules.length, 64);
  assert.equal(result.firedRuleIds[0], 'rule_0');
  assert.equal(result.firedRuleIds[63], 'rule_63');
});

test('evaluate rejects slots through explicit wasm status when available', async () => {
  let bitmaskCalled = false;
  const artifact = await loadArtifactFromBundle(
    {
      manifest: sampleManifest,
      wasmModule: new ArrayBuffer(8),
      wasmMetadata: sampleMetadata,
    },
    {
      instantiateWasm: async () => ({
        exports: {
          memory: new WebAssembly.Memory({ initial: 1 }),
          logicpearl_alloc() {
            return 0;
          },
          logicpearl_dealloc() {},
          logicpearl_eval_status_slots_f64() {
            return 2;
          },
          logicpearl_eval_bitmask_slots_f64() {
            bitmaskCalled = true;
            return 0n;
          },
        },
      }),
    }
  );

  assert.throws(
    () => artifact.evaluate({ is_admin: false }),
    /rejected the provided feature slots with status 2/
  );
  assert.equal(bitmaskCalled, false);
});

test('loadArtifactFromBundle requires declared status entrypoint export', async () => {
  await assert.rejects(
    () =>
      loadArtifactFromBundle(
        {
          manifest: sampleManifest,
          wasmModule: new ArrayBuffer(8),
          wasmMetadata: {
            ...sampleMetadata,
            status_entrypoint: 'logicpearl_eval_status_slots_f64',
          },
        },
        {
          instantiateWasm: async () => ({
            exports: {
              memory: new WebAssembly.Memory({ initial: 1 }),
              logicpearl_alloc() {
                return 0;
              },
              logicpearl_dealloc() {},
              logicpearl_eval_bitmask_slots_f64() {
                return 0n;
              },
            },
          }),
        }
      ),
    /declares but does not expose the LogicPearl status ABI/
  );
});

test('loadArtifact resolves Wasm files from the v1 artifact manifest', async () => {
  const responses = new Map([
    ['/demo/artifact.json', { ok: true, json: async () => sampleManifest }],
    ['/demo/demo.pearl.wasm', { ok: true, arrayBuffer: async () => new ArrayBuffer(8) }],
    ['/demo/demo.pearl.wasm.meta.json', { ok: true, json: async () => sampleMetadata }],
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
  assert.equal(summary.artifactId, 'demo_gate');
  assert.equal(summary.gateId, 'demo_gate');
  assert.equal(summary.browserRuntime, 'wasm');
});

test('loadArtifact requires artifact.json instead of probing conventional layouts', async () => {
  const seen = [];
  await assert.rejects(
    () =>
      loadArtifact('/demo', {
        fetchImpl: async (url) => {
          seen.push(url);
          if (url === '/demo/artifact.json') {
            return { ok: false, status: 404 };
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
      }),
    /Failed to load \/demo\/artifact\.json: 404/
  );

  assert.deepEqual(seen, ['/demo/artifact.json']);
});

test('loadArtifact rejects manifests that only declare legacy Wasm file names', async () => {
  const legacyManifest = {
    ...sampleManifest,
    files: {
      ir: 'pearl.ir.json',
      wasm_module: 'pearl.wasm',
      wasm_metadata: 'pearl.wasm.meta.json',
    },
  };

  await assert.rejects(
    () =>
      loadArtifact('/demo', {
        fetchImpl: async (url) => {
          if (url === '/demo/artifact.json') {
            return { ok: true, json: async () => legacyManifest };
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
      }),
    /files\.wasm is required/
  );
});

test('loadArtifactFromBundle requires a v1 artifact manifest object', async () => {
  await assert.rejects(
    () =>
      loadArtifactFromBundle(
        {
          wasmModule: new ArrayBuffer(8),
          wasmMetadata: sampleMetadata,
        },
        {
          instantiateWasm: async () => ({
            exports: {
              memory: new WebAssembly.Memory({ initial: 1 }),
              logicpearl_alloc() { return 0; },
              logicpearl_dealloc() {},
              logicpearl_eval_bitmask_slots_f64() { return 0n; },
            },
          }),
        }
      ),
    /requires an artifact manifest object/
  );

  await assert.rejects(
    () =>
      loadArtifactFromBundle(
        {
          manifest: {
            artifact_version: '1.0',
            artifact_name: 'legacy_gate',
            files: {
              pearl_ir: 'pearl.ir.json',
              wasm_module: 'pearl.wasm',
              wasm_metadata: 'pearl.wasm.meta.json',
            },
          },
          wasmModule: new ArrayBuffer(8),
          wasmMetadata: sampleMetadata,
        },
        {
          instantiateWasm: async () => ({
            exports: {
              memory: new WebAssembly.Memory({ initial: 1 }),
              logicpearl_alloc() { return 0; },
              logicpearl_dealloc() {},
              logicpearl_eval_bitmask_slots_f64() { return 0n; },
            },
          }),
        }
      ),
    /Unsupported artifact manifest schema_version/
  );
});
