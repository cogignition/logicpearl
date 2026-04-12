const DEFAULT_BITMASK_ENTRYPOINT = 'logicpearl_eval_bitmask_slots_f64';
const DEFAULT_STATUS_ENTRYPOINT = 'logicpearl_eval_status_slots_f64';

export async function loadArtifact(reference, options = {}) {
  const {
    fetchImpl = globalThis.fetch,
    instantiateWasm = defaultInstantiateWasm,
    layout = 'auto',
  } = options;
  if (typeof fetchImpl !== 'function') {
    throw new Error(
      'loadArtifact requires a fetch implementation. Pass { fetchImpl } in non-browser environments.'
    );
  }

  const { manifestUrl, artifactBaseUrl } = normalizeArtifactReference(reference);
  let manifest = null;
  if (layout !== 'conventional') {
    try {
      manifest = await fetchJson(fetchImpl, manifestUrl);
    } catch (error) {
      if (!isMissingResourceError(error)) {
        throw error;
      }
    }
  }

  const wasmModulePath =
    manifest?.files?.wasm_module ??
    manifest?.bundle?.deployables?.find((item) => item.kind === 'wasm_module')?.path ??
    'pearl.wasm';
  if (!wasmModulePath) {
    throw new Error('Artifact manifest does not declare a wasm_module deployable.');
  }

  const wasmMetadataPath =
    manifest?.files?.wasm_metadata ??
    manifest?.bundle?.metadata_files?.find((item) => item.kind === 'wasm_metadata')?.path ??
    'pearl.wasm.meta.json';
  if (!wasmMetadataPath) {
    throw new Error('Artifact manifest does not declare wasm metadata.');
  }

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
      manifestUrl: manifest ? manifestUrl : null,
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
  const resolvedManifest =
    manifest ??
    buildFallbackManifest({
      gateId: wasmMetadata.gate_id ?? wasmMetadata.action_policy_id,
      decisionKind: wasmMetadata.decision_kind,
    });

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
    const bitmaskEntrypoint = wasmMetadata.entrypoint ?? DEFAULT_BITMASK_ENTRYPOINT;
    const statusEntrypoint = wasmMetadata.status_entrypoint ?? DEFAULT_STATUS_ENTRYPOINT;
    const declaresStatusEntrypoint =
      typeof wasmMetadata.status_entrypoint === 'string' &&
      wasmMetadata.status_entrypoint.length > 0;
    if (
      typeof exports.logicpearl_alloc !== 'function' ||
      typeof exports[bitmaskEntrypoint] !== 'function' ||
      !(exports.memory instanceof WebAssembly.Memory)
    ) {
      throw new Error(
        'Loaded wasm module does not expose the expected LogicPearl browser ABI.'
      );
    }
    if (declaresStatusEntrypoint && typeof exports[statusEntrypoint] !== 'function') {
      throw new Error(
        'Loaded wasm module declares but does not expose the LogicPearl status ABI.'
      );
    }

    this.manifest = manifest;
    this.metadata = wasmMetadata;
    this.instance = instance;
    this.artifactBaseUrl = artifactBaseUrl;
    this.manifestUrl = manifestUrl;
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
      artifactName: this.manifest.artifact_name,
      featureCount: this.metadata.feature_count,
      ruleCount: (this.metadata.rules ?? []).length,
      artifactVersion: this.manifest.artifact_version,
      artifactBaseUrl: this.artifactBaseUrl,
      manifestUrl: this.manifestUrl,
      primaryRuntime: this.manifest.bundle?.primary_runtime ?? null,
    };
  }

  rules() {
    return [...(this.metadata.rules ?? [])];
  }

  evaluate(input) {
    const slots = encodeFeatureSlots(input, this.metadata);
    const exports = this.instance.exports;
    const artifactId =
      this.metadata.action_policy_id ??
      this.metadata.gate_id ??
      this.manifest.artifact_name ??
      'logicpearl_artifact';
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
          ? this.metadata.default_action
          : candidateActions[0];
        const selectedRules = orderedRules.filter((rule) => rule.action === action);
        const ambiguity =
          candidateActions.length > 1
            ? `multiple action rules matched: ${candidateActions.join(', ')}`
            : null;
        return {
          decisionKind: 'action',
          artifactId,
          policyId: artifactId,
          actionPolicyId: this.metadata.action_policy_id ?? artifactId,
          action,
          defaulted,
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

  evaluateBatch(inputs) {
    return inputs.map((input) => this.evaluate(input));
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

function encodeFeatureValue(rawValue, feature, stringCodes) {
  if (rawValue === undefined || rawValue === null) {
    return Number.NaN;
  }

  const encodingKind =
    typeof feature.encoding === 'string'
      ? feature.encoding
      : feature.encoding?.kind;

  switch (encodingKind) {
    case 'boolean':
      return rawValue === true || rawValue === 1 || rawValue === 'true' ? 1 : 0;
    case 'numeric': {
      const numeric = parseNumericValue(rawValue);
      return Number.isFinite(numeric) ? numeric : Number.NaN;
    }
    case 'string_code': {
      const key = String(rawValue);
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

function parseNumericValue(rawValue) {
  if (typeof rawValue === 'number') {
    return rawValue;
  }
  const raw = String(rawValue).trim();
  const isPercent = raw.endsWith('%');
  let normalized = isPercent ? raw.slice(0, -1).trim() : raw;
  normalized = normalized.replace(/,/g, '').replace(/^[$€£¥]/, '').trim();
  const numeric = Number(normalized);
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

function buildFallbackManifest({ gateId, decisionKind }) {
  return {
    artifact_version: '1.0',
    artifact_name: gateId ?? 'logicpearl_artifact',
    artifact_kind: decisionKind === 'action' ? 'action_policy' : undefined,
    gate_id: gateId ?? 'logicpearl_artifact',
    files: {
      pearl_ir: 'pearl.ir.json',
      build_report: 'build_report.json',
      native_binary: null,
      wasm_module: 'pearl.wasm',
      wasm_metadata: 'pearl.wasm.meta.json',
    },
    bundle: {
      bundle_kind: 'conventional_directory_bundle',
      cli_entrypoint: 'artifact.json',
      primary_runtime: 'wasm_module',
      deployables: [
        { kind: 'wasm_module', path: 'pearl.wasm' },
      ],
      metadata_files: [
        { kind: 'wasm_metadata', path: 'pearl.wasm.meta.json', companion_to: 'pearl.wasm' },
      ],
    },
  };
}

function isMissingResourceError(error) {
  return error instanceof Error && /Failed to load .*: 404\b/.test(error.message);
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
