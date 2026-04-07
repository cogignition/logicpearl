const WASM_ERROR_SENTINEL = 18446744073709551615n;

export async function loadArtifact(reference, options = {}) {
  const { fetchImpl = globalThis.fetch, instantiateWasm = defaultInstantiateWasm } = options;
  if (typeof fetchImpl !== 'function') {
    throw new Error(
      'loadArtifact requires a fetch implementation. Pass { fetchImpl } in non-browser environments.'
    );
  }

  const { manifestUrl, artifactBaseUrl } = normalizeArtifactReference(reference);
  let manifest = null;
  try {
    manifest = await fetchJson(fetchImpl, manifestUrl);
  } catch (error) {
    if (!isMissingResourceError(error)) {
      throw error;
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
      gateId: wasmMetadata.gate_id,
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
    if (
      typeof exports.logicpearl_alloc !== 'function' ||
      typeof exports.logicpearl_eval_bitmask_slots_f64 !== 'function' ||
      !(exports.memory instanceof WebAssembly.Memory)
    ) {
      throw new Error(
        'Loaded wasm module does not expose the expected LogicPearl browser ABI.'
      );
    }

    this.manifest = manifest;
    this.metadata = wasmMetadata;
    this.instance = instance;
    this.artifactBaseUrl = artifactBaseUrl;
    this.manifestUrl = manifestUrl;
    this.featureCount = wasmMetadata.feature_count;
    this.ruleIndex = new Map((wasmMetadata.rules ?? []).map((rule) => [rule.bit, rule]));
    this.stringCodes = new Map(Object.entries(wasmMetadata.string_codes ?? {}));
  }

  inspect() {
    return {
      gateId: this.metadata.gate_id,
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
    const ptr = exports.logicpearl_alloc(this.featureCount * 8);

    try {
      const view = new Float64Array(exports.memory.buffer, ptr, this.featureCount);
      view.set(slots);
      const raw = exports.logicpearl_eval_bitmask_slots_f64(ptr, this.featureCount);
      const bitmask = BigInt(raw);
      if (bitmask === WASM_ERROR_SENTINEL) {
        throw new Error('LogicPearl wasm evaluator rejected the provided feature slots.');
      }
      const firedRules = decodeFiredRules(bitmask, this.metadata.rules ?? []);
      return {
        allow: firedRules.length === 0,
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

  switch (feature.encoding) {
    case 'boolean':
      return rawValue === true || rawValue === 1 || rawValue === 'true' ? 1 : 0;
    case 'numeric': {
      const numeric = Number(rawValue);
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

function buildFallbackManifest({ gateId }) {
  return {
    artifact_version: '1.0',
    artifact_name: gateId ?? 'logicpearl_artifact',
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
