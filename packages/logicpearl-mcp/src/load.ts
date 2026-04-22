import { loadArtifact } from '@logicpearl/browser';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

export interface LoadedArtifact {
  manifest: Record<string, unknown> & {
    artifact_name?: string;
    artifact_id?: string;
    default_action?: string;
    actions?: string[];
  };
  metadata: Record<string, unknown> & {
    gate_id?: string;
    features?: Array<Record<string, unknown>>;
    rules?: Array<Record<string, unknown>>;
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
  inspect: () => {
    gateId: string;
    artifactName: string;
    featureCount: number;
    ruleCount: number;
    artifactVersion: string;
  };
}

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

const cache = new Map<string, Promise<LoadedArtifact>>();

export function loadFromPathOrUrl(ref: string): Promise<LoadedArtifact> {
  let effective = ref;
  if (!ref.startsWith('http') && !ref.startsWith('file://')) {
    effective = resolve(ref);
  }
  const cached = cache.get(effective);
  if (cached) return cached;
  const p = loadArtifact(effective, {
    fetchImpl: localFetch as typeof fetch,
  }) as Promise<LoadedArtifact>;
  cache.set(effective, p);
  return p;
}

export function clearCache(): void {
  cache.clear();
}
