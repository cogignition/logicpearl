import { loadArtifact } from '@logicpearl/browser';
import type {
  BrowserActionEvaluation,
  BrowserEvaluation,
  BrowserGateEvaluation,
  BrowserRuleMetadata,
  LogicPearlBrowserArtifact,
} from '@logicpearl/browser';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

type ArtifactManifest = Record<string, unknown> & {
  artifact_name?: string;
  artifact_id?: string;
  default_action?: string;
  actions?: string[];
};

type ArtifactMetadata = Record<string, unknown> & {
  gate_id?: string;
  action_policy_id?: string;
  decision_kind?: 'gate' | 'action';
  features?: Array<Record<string, unknown>>;
  rules?: Array<Record<string, unknown>>;
  string_codes?: Record<string, number>;
  feature_extraction_prompt_template?: string;
};

export interface LoadedArtifact extends LogicPearlBrowserArtifact {
  manifest: ArtifactManifest;
  metadata: ArtifactMetadata;
  featureCount: number;
  inspect: () => {
    decisionKind?: 'gate' | 'action';
    gateId?: string;
    actionPolicyId?: string | null;
    artifactId?: string;
    artifactKind?: string;
    featureCount: number;
    ruleCount: number;
    engineVersion?: string | null;
  };
}

async function localFetch(url: string): Promise<Response> {
  if (url.startsWith('http://') || url.startsWith('https://')) {
    return fetch(url);
  }
  const path = url.startsWith('file://') ? fileURLToPath(url) : resolve(url);
  const buf = await readFile(path);
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
  const p = (loadArtifact(effective, {
    fetchImpl: localFetch as typeof fetch,
  }) as Promise<LoadedArtifact>).catch((error) => {
    cache.delete(effective);
    throw error;
  });
  cache.set(effective, p);
  return p;
}

export function clearCache(): void {
  cache.clear();
}

export function isActionEvaluation(
  result: BrowserEvaluation,
): result is BrowserActionEvaluation {
  return result.decisionKind === 'action';
}

export function isGateEvaluation(
  result: BrowserEvaluation,
): result is BrowserGateEvaluation {
  return result.decisionKind === 'gate';
}

export function drivingRules(result: BrowserEvaluation): BrowserRuleMetadata[] {
  return isActionEvaluation(result) ? result.selectedRules : result.firedRules;
}

export function matchedRules(result: BrowserEvaluation): BrowserRuleMetadata[] {
  return isActionEvaluation(result) ? result.matchedRules : result.firedRules;
}
