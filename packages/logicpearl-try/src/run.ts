import { loadArtifact } from '@logicpearl/browser';
import { readFile, stat } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

export interface Artifact {
  manifest: {
    artifact_name?: string;
    default_action?: string;
    actions?: string[];
  };
  metadata: {
    features: Array<{
      id: string;
      index: number;
      type?: string;
      encoding?: { kind?: string } | string;
    }>;
    rules?: Array<{
      id: string;
      bit: number;
      label?: string;
      message?: string;
      counterfactual_hint?: string;
      action?: string;
    }>;
    gate_id?: string;
    string_codes?: Record<string, number>;
    feature_extraction_prompt_template?: string;
  };
  featureCount: number;
  evaluate: (input: Record<string, unknown>) => {
    allow: boolean;
    bitmask?: bigint;
    firedRules: Array<{
      id: string;
      bit: number;
      label?: string;
      message?: string;
      counterfactual_hint?: string;
      action?: string;
    }>;
    primaryReason: unknown;
    counterfactualHints: string[];
  };
  rules: () => Array<unknown>;
  inspect: () => {
    gateId: string;
    artifactName: string;
    featureCount: number;
    ruleCount: number;
    artifactVersion: string;
  };
}

export interface RunOptions {
  artifactUrl: string;
  facts: Record<string, unknown>;
}

export interface RunResult {
  artifact: Artifact;
  facts: Record<string, unknown>;
  verdict: string;
  allow: boolean;
  firedRules: Array<{
    id: string;
    label?: string;
    message?: string;
    counterfactual_hint?: string;
    action?: string;
  }>;
  latencyMs: number;
  bitmask: string;
}

// File-system fetch shim so artifact paths like ./artifacts/... work.
async function localFetch(url: string): Promise<Response> {
  if (url.startsWith('http://') || url.startsWith('https://')) {
    return fetch(url);
  }
  const path = url.startsWith('file://') ? new URL(url).pathname : url;
  const buf = await readFile(resolve(path));
  return {
    ok: true,
    status: 200,
    headers: new Headers(),
    async arrayBuffer() {
      return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
    },
    async json() {
      return JSON.parse(buf.toString('utf-8'));
    },
    async text() {
      return buf.toString('utf-8');
    },
  } as unknown as Response;
}

export async function loadFromPathOrUrl(ref: string): Promise<Artifact> {
  // Accept: URL, local file path (absolute or relative), or package-root-relative path.
  let effective = ref;
  if (!ref.startsWith('http') && !ref.startsWith('file://')) {
    // Resolve relative paths against cwd.
    effective = resolve(ref);
  }
  const artifact = (await loadArtifact(effective, {
    fetchImpl: localFetch as typeof fetch,
  })) as unknown as Artifact;
  return artifact;
}

export async function runEvaluate(opts: RunOptions): Promise<RunResult> {
  const artifact = await loadFromPathOrUrl(opts.artifactUrl);
  const t0 = performance.now();
  const result = artifact.evaluate(opts.facts);
  const latencyMs = Math.round((performance.now() - t0) * 100) / 100;

  const defaultAction = (artifact.manifest.default_action || 'approve').toUpperCase();
  const firedAction = result.firedRules[0]?.action?.toUpperCase();
  const verdict = result.allow ? defaultAction : firedAction || 'DENY';

  const rules = artifact.metadata.rules ?? [];
  const bits = rules.map((r) =>
    result.firedRules.find((f) => f.bit === r.bit) ? '1' : '0',
  );
  const bitmask = '0b' + (bits.length > 0 ? bits.reverse().join('') : '0');

  return {
    artifact,
    facts: opts.facts,
    verdict,
    allow: result.allow,
    firedRules: result.firedRules,
    latencyMs,
    bitmask,
  };
}

export async function fileExists(p: string): Promise<boolean> {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}
