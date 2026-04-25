const DEFAULT_BITMASK_ENTRYPOINT = 'logicpearl_eval_bitmask_slots_f64';
const DEFAULT_STATUS_ENTRYPOINT = 'logicpearl_eval_status_slots_f64';
const ARTIFACT_MANIFEST_SCHEMA_VERSION = 'logicpearl.artifact_manifest.v1';

export async function loadArtifact(reference, options = {}) {
  const {
    fetchImpl = globalThis.fetch,
    instantiateWasm = defaultInstantiateWasm,
  } = options;
  if (typeof fetchImpl !== 'function') {
    throw new Error(
      'loadArtifact requires a fetch implementation. Pass { fetchImpl } in non-browser environments.'
    );
  }

  const { manifestUrl, artifactBaseUrl } = normalizeArtifactReference(reference);
  const manifest = requireArtifactManifestV1(await fetchJson(fetchImpl, manifestUrl));
  const wasmModulePath = requireManifestFile(manifest, 'wasm');
  const wasmMetadataPath = requireManifestFile(manifest, 'wasm_metadata');

  const [wasmModule, wasmMetadata] = await Promise.all([
    fetchArrayBuffer(fetchImpl, joinArtifactPath(artifactBaseUrl, wasmModulePath)),
    fetchJson(fetchImpl, joinArtifactPath(artifactBaseUrl, wasmMetadataPath)),
  ]);

  return loadArtifactFromBundle(
    {
      manifest,
      wasmModule,
      wasmMetadata,
      artifactBaseUrl,
      manifestUrl,
    },
    { instantiateWasm }
  );
}

export async function loadArtifactFromBundle(bundle, options = {}) {
  const { instantiateWasm = defaultInstantiateWasm } = options;
  const { manifest, wasmModule, wasmMetadata } = bundle ?? {};
  if (!wasmModule) {
    throw new Error('loadArtifactFromBundle requires wasmModule bytes.');
  }
  if (!wasmMetadata) {
    throw new Error('loadArtifactFromBundle requires wasmMetadata.');
  }
  const resolvedManifest = requireArtifactManifestV1(manifest);

  const instance = await instantiateWasm(wasmModule);
  return new LogicPearlBrowserArtifact({
    manifest: resolvedManifest,
    wasmMetadata,
    instance,
    artifactBaseUrl: bundle.artifactBaseUrl ?? null,
    manifestUrl: bundle.manifestUrl ?? null,
  });
}

export function normalizeArtifactReference(reference) {
  if (reference == null) {
    throw new Error('Artifact reference is required.');
  }

  const raw = String(reference);
  if (raw.endsWith('/artifact.json')) {
    return {
      manifestUrl: raw,
      artifactBaseUrl: raw.slice(0, -'/artifact.json'.length),
    };
  }

  if (raw.endsWith('.json')) {
    const slash = raw.lastIndexOf('/');
    return {
      manifestUrl: raw,
      artifactBaseUrl: slash >= 0 ? raw.slice(0, slash) : '.',
    };
  }

  return {
    manifestUrl: joinArtifactPath(raw, 'artifact.json'),
    artifactBaseUrl: raw.replace(/\/+$/, ''),
  };
}

export class LogicPearlBrowserArtifact {
  constructor({ manifest, wasmMetadata, instance, artifactBaseUrl, manifestUrl }) {
    const exports = instance?.exports ?? {};
    const isFanout = wasmMetadata.decision_kind === 'fanout';
    const bitmaskEntrypoint = wasmMetadata.entrypoint ?? DEFAULT_BITMASK_ENTRYPOINT;
    const statusEntrypoint = wasmMetadata.status_entrypoint ?? DEFAULT_STATUS_ENTRYPOINT;
    const declaresStatusEntrypoint =
      typeof wasmMetadata.status_entrypoint === 'string' &&
      wasmMetadata.status_entrypoint.length > 0;
    if (typeof exports.logicpearl_alloc !== 'function' || !(exports.memory instanceof WebAssembly.Memory)) {
      throw new Error(
        'Loaded wasm module does not expose the expected LogicPearl browser ABI.'
      );
    }
    if (isFanout) {
      for (const action of wasmMetadata.actions ?? []) {
        const actionEntrypoint = action.entrypoint ?? DEFAULT_BITMASK_ENTRYPOINT;
        const actionStatusEntrypoint = action.status_entrypoint ?? DEFAULT_STATUS_ENTRYPOINT;
        if (typeof exports[actionEntrypoint] !== 'function') {
          throw new Error(
            `Loaded fan-out wasm module is missing action entrypoint ${actionEntrypoint}.`
          );
        }
        if (
          typeof action.status_entrypoint === 'string' &&
          action.status_entrypoint.length > 0 &&
          typeof exports[actionStatusEntrypoint] !== 'function'
        ) {
          throw new Error(
            `Loaded fan-out wasm module is missing action status entrypoint ${actionStatusEntrypoint}.`
          );
        }
      }
    } else if (typeof exports[bitmaskEntrypoint] !== 'function') {
      throw new Error(
        'Loaded wasm module does not expose the expected LogicPearl browser ABI.'
      );
    }
    if (!isFanout && declaresStatusEntrypoint && typeof exports[statusEntrypoint] !== 'function') {
      throw new Error(
        'Loaded wasm module declares but does not expose the LogicPearl status ABI.'
      );
    }

    this.manifest = manifest;
    this.metadata = wasmMetadata;
    this.instance = instance;
    this.artifactBaseUrl = artifactBaseUrl;
    this.manifestUrl = manifestUrl;
    this.isFanout = isFanout;
    this.featureCount = wasmMetadata.feature_count;
    this.bitmaskEntrypoint = bitmaskEntrypoint;
    this.statusEntrypoint = statusEntrypoint;
    this.ruleIndex = new Map((wasmMetadata.rules ?? []).map((rule) => [rule.bit, rule]));
    this.stringCodes = new Map(Object.entries(wasmMetadata.string_codes ?? {}));
  }

  inspect() {
    const decisionKind = this.metadata.decision_kind ?? 'gate';
    return {
      decisionKind,
      gateId: this.metadata.gate_id,
      actionPolicyId: this.metadata.action_policy_id ?? null,
      pipelineId: this.metadata.pipeline_id ?? null,
      artifactId: this.manifest.artifact_id,
      artifactKind: this.manifest.artifact_kind,
      engineVersion: this.metadata.engine_version ?? this.manifest.engine_version ?? null,
      artifactHash: this.metadata.artifact_hash ?? this.manifest.artifact_hash ?? null,
      featureCount: this.metadata.feature_count,
      ruleCount: this.isFanout
        ? (this.metadata.actions ?? []).reduce(
            (count, action) => count + (action.rules ?? []).length,
            0
          )
        : (this.metadata.rules ?? []).length,
      artifactBaseUrl: this.artifactBaseUrl,
      manifestUrl: this.manifestUrl,
      browserRuntime: this.manifest.files?.wasm ? 'wasm' : null,
    };
  }

  rules() {
    if (this.isFanout) {
      return (this.metadata.actions ?? []).flatMap((action) =>
        (action.rules ?? []).map((rule) => ({ ...rule, action: action.action }))
      );
    }
    return [...(this.metadata.rules ?? [])];
  }

  evaluate(input) {
    if (this.isFanout) {
      return this.evaluateFanout(input);
    }
    const slots = encodeFeatureSlots(input, this.metadata);
    const exports = this.instance.exports;
    const artifactId =
      this.manifest.artifact_id ??
      this.metadata.action_policy_id ??
      this.metadata.gate_id ??
      'logicpearl_artifact';
    const engineVersion = this.metadata.engine_version ?? this.manifest.engine_version ?? null;
    const artifactHash = this.metadata.artifact_hash ?? this.manifest.artifact_hash ?? null;
    const ptr = exports.logicpearl_alloc(this.featureCount * 8);

    try {
      const view = new Float64Array(exports.memory.buffer, ptr, this.featureCount);
      view.set(slots);
      const statusFn = exports[this.statusEntrypoint];
      if (typeof statusFn === 'function') {
        const status = Number(statusFn(ptr, this.featureCount));
        if (status !== 0) {
          throw new Error(
            `LogicPearl wasm evaluator rejected the provided feature slots with status ${status}.`
          );
        }
      }
      const raw = exports[this.bitmaskEntrypoint](ptr, this.featureCount);
      const bitmask = BigInt(raw);
      const firedRules = decodeFiredRules(bitmask, this.metadata.rules ?? []);
      if ((this.metadata.decision_kind ?? 'gate') === 'action') {
        const orderedRules = [...firedRules].sort(
          (left, right) => (left.priority ?? left.bit) - (right.priority ?? right.bit)
        );
        const candidateActions = dedupe(
          orderedRules.map((rule) => rule.action).filter(Boolean)
        );
        const defaulted = candidateActions.length === 0;
        const action = defaulted
          ? (this.metadata.no_match_action ?? this.metadata.default_action)
          : candidateActions[0];
        const selectedRules = orderedRules.filter((rule) => rule.action === action);
        const ambiguity =
          candidateActions.length > 1
            ? `multiple action rules matched: ${candidateActions.join(', ')}`
            : null;
        return {
          schemaVersion: 'logicpearl.action_result.v1',
          engineVersion,
          artifactHash,
          decisionKind: 'action',
          artifactId,
          policyId: artifactId,
          actionPolicyId: this.metadata.action_policy_id ?? artifactId,
          action,
          defaultAction: this.metadata.default_action,
          noMatchAction: this.metadata.no_match_action ?? null,
          defaulted,
          noMatch: defaulted,
          ambiguity,
          bitmask,
          matchedRuleIds: orderedRules.map((rule) => rule.id),
          matchedRules: orderedRules,
          selectedRules,
          candidateActions,
          primaryReason: selectedRules[0] ?? null,
          counterfactualHints: dedupe(
            selectedRules.map((rule) => rule.counterfactual_hint).filter(Boolean)
          ),
        };
      }
      return {
        schemaVersion: 'logicpearl.gate_result.v1',
        engineVersion,
        artifactHash,
        decisionKind: 'gate',
        artifactId,
        policyId: artifactId,
        gateId: this.metadata.gate_id ?? artifactId,
        allow: firedRules.length === 0,
        defaulted: false,
        ambiguity: null,
        bitmask,
        firedRuleIds: firedRules.map((rule) => rule.id),
        firedRules,
        primaryReason: firedRules[0] ?? null,
        counterfactualHints: dedupe(
          firedRules.map((rule) => rule.counterfactual_hint).filter(Boolean)
        ),
      };
    } finally {
      if (typeof exports.logicpearl_dealloc === 'function') {
        exports.logicpearl_dealloc(ptr, this.featureCount * 8);
      }
    }
  }

  evaluateFanout(input) {
    const artifactId = this.manifest.artifact_id ?? this.metadata.pipeline_id ?? 'logicpearl_fanout';
    const engineVersion = this.metadata.engine_version ?? this.manifest.engine_version ?? null;
    const artifactHash = this.metadata.artifact_hash ?? this.manifest.artifact_hash ?? null;
    const applicableActions = [];
    const verdicts = {};
    const stages = [];

    for (const actionMetadata of this.metadata.actions ?? []) {
      const result = this.evaluateFanoutGate(input, actionMetadata);
      const applies = result.firedRules.length > 0 || result.bitmask !== 0n;
      if (applies) {
        applicableActions.push(actionMetadata.action);
      }
      const verdict = {
        id: actionMetadata.id ?? actionMetadata.action,
        action: actionMetadata.action,
        applies,
        artifactId: result.artifactId,
        artifactHash: result.artifactHash,
        bitmask: result.bitmask,
        matchedRules: result.firedRules,
        result,
      };
      verdicts[actionMetadata.action] = verdict;
      stages.push(verdict);
    }

    return {
      schemaVersion: 'logicpearl.fanout_result.v1',
      engineVersion,
      artifactHash,
      artifactId,
      decisionKind: 'fanout',
      pipelineId: this.metadata.pipeline_id ?? artifactId,
      ok: true,
      applicableActions,
      verdicts,
      output: { applicableActions, verdicts },
      stages,
    };
  }

  evaluateFanoutGate(input, actionMetadata) {
    const slots = encodeFeatureSlots(input, actionMetadata);
    const exports = this.instance.exports;
    const featureCount = actionMetadata.feature_count;
    const ptr = exports.logicpearl_alloc(featureCount * 8);
    try {
      const view = new Float64Array(exports.memory.buffer, ptr, featureCount);
      view.set(slots);
      const statusEntrypoint = actionMetadata.status_entrypoint ?? DEFAULT_STATUS_ENTRYPOINT;
      const statusFn = exports[statusEntrypoint];
      if (typeof statusFn === 'function') {
        const status = Number(statusFn(ptr, featureCount));
        if (status !== 0) {
          throw new Error(
            `LogicPearl fan-out wasm evaluator rejected action ${actionMetadata.action} feature slots with status ${status}.`
          );
        }
      }
      const raw = exports[actionMetadata.entrypoint](ptr, featureCount);
      const bitmask = BigInt(raw);
      const firedRules = decodeFiredRules(bitmask, actionMetadata.rules ?? []);
      return {
        schemaVersion: 'logicpearl.gate_result.v1',
        engineVersion: this.metadata.engine_version ?? this.manifest.engine_version ?? null,
        artifactHash: actionMetadata.artifact_hash ?? null,
        decisionKind: 'gate',
        artifactId: actionMetadata.artifact_id ?? actionMetadata.id ?? actionMetadata.action,
        policyId: actionMetadata.artifact_id ?? actionMetadata.id ?? actionMetadata.action,
        gateId: actionMetadata.artifact_id ?? actionMetadata.id ?? actionMetadata.action,
        allow: firedRules.length === 0,
        defaulted: false,
        ambiguity: null,
        bitmask,
        firedRuleIds: firedRules.map((rule) => rule.id),
        firedRules,
        primaryReason: firedRules[0] ?? null,
        counterfactualHints: dedupe(
          firedRules.map((rule) => rule.counterfactual_hint).filter(Boolean)
        ),
      };
    } finally {
      if (typeof exports.logicpearl_dealloc === 'function') {
        exports.logicpearl_dealloc(ptr, featureCount * 8);
      }
    }
  }

  evaluateBatch(inputs) {
    return inputs.map((input) => this.evaluate(input));
  }

  evaluateJson(input) {
    const result = this.evaluate(input);
    const context = requireRuntimeJsonContext(result);
    if (result.decisionKind === 'action') {
      return {
        schema_version: 'logicpearl.action_result.v1',
        engine_version: context.engineVersion,
        artifact_hash: context.artifactHash,
        artifact_id: result.artifactId,
        policy_id: result.policyId,
        action_policy_id: result.actionPolicyId,
        decision_kind: 'action',
        action: result.action,
        default_action: result.defaultAction,
        no_match_action: result.noMatchAction,
        bitmask: bitmaskToJson(result.bitmask),
        defaulted: result.defaulted,
        no_match: result.noMatch,
        selected_rules: result.selectedRules.map(normalizeActionRuleExplanation),
        matched_rules: result.matchedRules.map(normalizeActionRuleExplanation),
        candidate_actions: result.candidateActions,
        ambiguity: result.ambiguity,
      };
    }
    if (result.decisionKind === 'fanout') {
      const verdicts = Object.fromEntries(
        Object.entries(result.verdicts).map(([action, verdict]) => [
          action,
          normalizeFanoutVerdict(verdict),
        ])
      );
      return {
        schema_version: 'logicpearl.fanout_result.v1',
        engine_version: context.engineVersion,
        artifact_hash: context.artifactHash,
        artifact_id: result.artifactId,
        decision_kind: 'fanout',
        pipeline_id: result.pipelineId,
        ok: result.ok,
        applicable_actions: result.applicableActions,
        verdicts,
        output: {
          applicable_actions: result.applicableActions,
          verdicts,
        },
        stages: result.stages.map(normalizeFanoutVerdict),
      };
    }
    return {
      schema_version: 'logicpearl.gate_result.v1',
      engine_version: context.engineVersion,
      artifact_hash: context.artifactHash,
      artifact_id: result.artifactId,
      policy_id: result.policyId,
      gate_id: result.gateId,
      decision_kind: 'gate',
      allow: result.allow,
      bitmask: bitmaskToJson(result.bitmask),
      defaulted: result.defaulted,
      ambiguity: result.ambiguity,
      matched_rules: result.firedRules.map(normalizeGateRuleExplanation),
    };
  }

  evaluateJsonBatch(inputs) {
    return inputs.map((input) => this.evaluateJson(input));
  }
}

export function encodeFeatureSlots(input, metadata) {
  const values = new Float64Array(metadata.feature_count);
  values.fill(Number.NaN);

  for (const feature of metadata.features ?? []) {
    const rawValue = input?.[feature.id];
    values[feature.index] = encodeFeatureValue(rawValue, feature, metadata.string_codes ?? {});
  }

  return values;
}

export function decodeFiredRules(bitmask, rules) {
  return [...rules]
    .filter((rule) => (bitmask & (1n << BigInt(rule.bit))) !== 0n)
    .sort((left, right) => left.bit - right.bit);
}

function requireRuntimeJsonContext(result) {
  if (!result.engineVersion || !result.artifactHash) {
    throw new Error(
      'Loaded artifact metadata does not include engine_version and artifact_hash required for runtime JSON v1.'
    );
  }
  return {
    engineVersion: result.engineVersion,
    artifactHash: result.artifactHash,
  };
}

function bitmaskToJson(bitmask) {
  return BigInt(bitmask).toString();
}

function normalizeGateRuleExplanation(rule) {
  return {
    id: rule.id,
    bit: rule.bit,
    label: rule.label ?? null,
    message: rule.message ?? null,
    severity: rule.severity ?? null,
    counterfactual_hint: rule.counterfactual_hint ?? null,
    features: normalizeFeatureExplanations(rule.features),
  };
}

function normalizeActionRuleExplanation(rule) {
  return {
    id: rule.id,
    bit: rule.bit,
    action: rule.action,
    priority: rule.priority ?? rule.bit,
    label: rule.label ?? null,
    message: rule.message ?? null,
    severity: rule.severity ?? null,
    counterfactual_hint: rule.counterfactual_hint ?? null,
    features: normalizeFeatureExplanations(rule.features),
  };
}

function normalizeFanoutVerdict(verdict) {
  return {
    id: verdict.id,
    action: verdict.action,
    applies: verdict.applies,
    artifact_id: verdict.artifactId,
    artifact_hash: verdict.artifactHash,
    bitmask: bitmaskToJson(verdict.bitmask),
    matched_rules: verdict.matchedRules.map(normalizeGateRuleExplanation),
    result: normalizeFanoutGateResult(verdict.result),
  };
}

function normalizeFanoutGateResult(result) {
  return {
    schema_version: 'logicpearl.gate_result.v1',
    engine_version: result.engineVersion,
    artifact_hash: result.artifactHash,
    artifact_id: result.artifactId,
    policy_id: result.policyId,
    gate_id: result.gateId,
    decision_kind: 'gate',
    allow: result.allow,
    bitmask: bitmaskToJson(result.bitmask),
    defaulted: result.defaulted,
    ambiguity: result.ambiguity,
    matched_rules: result.firedRules.map(normalizeGateRuleExplanation),
  };
}

function normalizeFeatureExplanations(features) {
  return (features ?? []).map((feature) => ({
    feature_id: feature.feature_id ?? feature.featureId,
    feature_label: feature.feature_label ?? feature.featureLabel ?? null,
    source_id: feature.source_id ?? feature.sourceId ?? null,
    source_anchor: feature.source_anchor ?? feature.sourceAnchor ?? null,
    state_label: feature.state_label ?? feature.stateLabel ?? null,
    state_message: feature.state_message ?? feature.stateMessage ?? null,
    counterfactual_hint: feature.counterfactual_hint ?? feature.counterfactualHint ?? null,
  }));
}

function encodeFeatureValue(rawValue, feature, stringCodes) {
  if (rawValue === undefined || rawValue === null) {
    return Number.NaN;
  }
  const normalizedValue = normalizeRuntimeScalar(rawValue);

  const encodingKind =
    typeof feature.encoding === 'string'
      ? feature.encoding
      : feature.encoding?.kind;

  switch (encodingKind) {
    case 'boolean':
      return normalizedValue === true || normalizedValue === 1 ? 1 : 0;
    case 'numeric': {
      return typeof normalizedValue === 'number' && Number.isFinite(normalizedValue)
        ? normalizedValue
        : Number.NaN;
    }
    case 'string_code': {
      if (typeof normalizedValue !== 'string') {
        return Number.NaN;
      }
      const key = normalizedValue;
      const encoded = stringCodes[key];
      if (encoded === undefined) {
        return Number.NaN;
      }
      return Number(encoded);
    }
    default:
      return Number.NaN;
  }
}

function normalizeRuntimeScalar(rawValue) {
  if (typeof rawValue !== 'string') {
    return rawValue;
  }

  const value = rawValue.trim();
  switch (value.toLowerCase()) {
    case 'true':
    case 'yes':
    case 'y':
    case 'on':
      return true;
    case 'false':
    case 'no':
    case 'n':
    case 'off':
      return false;
    default:
      break;
  }

  const numeric = parseRuntimeNumber(value);
  return numeric ?? value;
}

function parseRuntimeNumber(rawValue) {
  let candidate = rawValue.trim();
  let isPercent = false;
  if (candidate.endsWith('%')) {
    candidate = candidate.slice(0, -1).trim();
    isPercent = true;
  }
  if (/^[$€£¥]/u.test(candidate)) {
    candidate = candidate.slice(1).trim();
  }

  const negativeWrapped = candidate.startsWith('(') && candidate.endsWith(')');
  if (negativeWrapped) {
    candidate = candidate.slice(1, -1).trim();
  }

  let normalized = candidate.replace(/,/g, '');
  if (negativeWrapped) {
    normalized = `-${normalized}`;
  }

  if (!/^[+-]?(?:(?:\d+\.?\d*)|(?:\.\d+))(?:[eE][+-]?\d+)?$/u.test(normalized)) {
    return null;
  }

  const numeric = Number(normalized);
  if (!Number.isFinite(numeric)) {
    return null;
  }
  return isPercent ? numeric / 100 : numeric;
}

async function fetchJson(fetchImpl, url) {
  const response = await fetchImpl(url);
  if (!response?.ok) {
    throw new Error(`Failed to load ${url}: ${response?.status ?? 'unknown status'}`);
  }
  return response.json();
}

async function fetchArrayBuffer(fetchImpl, url) {
  const response = await fetchImpl(url);
  if (!response?.ok) {
    throw new Error(`Failed to load ${url}: ${response?.status ?? 'unknown status'}`);
  }
  return response.arrayBuffer();
}

function requireArtifactManifestV1(manifest) {
  if (!isPlainObject(manifest)) {
    throw new Error('LogicPearl browser loading requires an artifact manifest object.');
  }
  if (manifest.schema_version !== ARTIFACT_MANIFEST_SCHEMA_VERSION) {
    throw new Error(
      `Unsupported artifact manifest schema_version ${JSON.stringify(manifest.schema_version)}; expected ${ARTIFACT_MANIFEST_SCHEMA_VERSION}.`
    );
  }
  for (const field of [
    'artifact_id',
    'artifact_kind',
    'engine_version',
    'ir_version',
    'created_at',
    'artifact_hash',
  ]) {
    if (typeof manifest[field] !== 'string' || manifest[field].length === 0) {
      throw new Error(`Artifact manifest v1 is missing required string field ${field}.`);
    }
  }
  if (!['gate', 'action', 'pipeline'].includes(manifest.artifact_kind)) {
    throw new Error(
      `Artifact manifest v1 has unsupported artifact_kind ${JSON.stringify(manifest.artifact_kind)}.`
    );
  }
  if (!isPlainObject(manifest.files)) {
    throw new Error('Artifact manifest v1 is missing required files object.');
  }
  requireManifestFile(manifest, 'ir');
  return manifest;
}

function requireManifestFile(manifest, key) {
  const value = manifest.files?.[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Artifact manifest v1 files.${key} is required for browser Wasm loading.`);
  }
  return value;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

async function defaultInstantiateWasm(bytes) {
  const { instance } = await WebAssembly.instantiate(bytes, {});
  return instance;
}

function joinArtifactPath(base, relative) {
  if (isAbsoluteUrl(relative) || relative.startsWith('/')) {
    return relative;
  }

  const cleanBase = String(base).replace(/\/+$/, '');
  const cleanRelative = String(relative).replace(/^\.?\//, '');
  if (!cleanBase) {
    return cleanRelative;
  }
  return `${cleanBase}/${cleanRelative}`;
}

function isAbsoluteUrl(value) {
  return /^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(String(value));
}

function dedupe(values) {
  return [...new Set(values)];
}
