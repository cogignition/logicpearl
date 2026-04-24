import { loadArtifact } from '@logicpearl/browser';
import type {
  BrowserActionEvaluation,
  BrowserEvaluation,
  BrowserGateEvaluation,
  BrowserRuleMetadata,
  LogicPearlBrowserArtifact,
} from '@logicpearl/browser';
import { readFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

type ArtifactManifest = {
  artifact_name?: string;
  artifact_id?: string;
  default_action?: string;
  actions?: string[];
};

type ArtifactMetadata = {
  decision_kind?: 'gate' | 'action';
  features: Array<{
    id: string;
    index: number;
    type?: string;
    encoding?: { kind?: string } | string;
  }>;
  rules?: BrowserRule[];
  gate_id?: string;
  action_policy_id?: string;
  string_codes?: Record<string, number>;
  feature_extraction_prompt_template?: string;
};

export interface BrowserRule extends BrowserRuleMetadata {
  id: string;
  bit: number;
  label?: string;
  message?: string;
  counterfactual_hint?: string;
  action?: string;
}

export interface Artifact extends LogicPearlBrowserArtifact {
  manifest: ArtifactManifest;
  metadata: ArtifactMetadata;
  featureCount: number;
  rules: () => BrowserRule[];
  inspect: () => {
    decisionKind?: 'gate' | 'action';
    gateId?: string;
    actionPolicyId?: string | null;
    featureCount: number;
    ruleCount: number;
    artifactId?: string;
  };
}

export interface RunOptions {
  artifactUrl: string;
  facts: Record<string, unknown>;
}

export interface RunResult {
  artifact: Artifact;
  facts: Record<string, unknown>;
  decisionKind: 'gate' | 'action';
  verdict: string;
  allow: boolean | null;
  action: string | null;
  defaultAction: string | null;
  defaulted: boolean;
  firedRules: BrowserRule[];
  matchedRules: BrowserRule[];
  latencyMs: number;
  bitmask: string;
}

// File-system fetch shim so artifact paths like ./artifacts/... work.
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
  const firedRules = selectDecisionRules(result);
  const matchedRules = selectMatchedRules(result);
  const verdict = isActionEvaluation(result)
    ? result.action.toUpperCase()
    : result.allow
      ? (artifact.manifest.default_action ?? 'approve').toUpperCase()
      : firedRules[0]?.action?.toUpperCase() || 'DENY';

  const rules = artifact.metadata.rules ?? [];
  const bits = rules.map((r) =>
    matchedRules.find((f) => f.bit === r.bit) ? '1' : '0',
  );
  const bitmask = '0b' + (bits.length > 0 ? bits.reverse().join('') : '0');

  return {
    artifact,
    facts: opts.facts,
    decisionKind: result.decisionKind,
    verdict,
    allow: isActionEvaluation(result) ? null : result.allow,
    action: isActionEvaluation(result) ? result.action : null,
    defaultAction: isActionEvaluation(result)
      ? result.defaultAction
      : artifact.manifest.default_action ?? null,
    defaulted: result.defaulted,
    firedRules,
    matchedRules,
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

function isActionEvaluation(
  result: BrowserEvaluation,
): result is BrowserActionEvaluation {
  return result.decisionKind === 'action';
}

function selectDecisionRules(result: BrowserEvaluation): BrowserRule[] {
  return isActionEvaluation(result)
    ? (result.selectedRules as BrowserRule[])
    : (result.firedRules as BrowserRule[]);
}

function selectMatchedRules(result: BrowserEvaluation): BrowserRule[] {
  return isActionEvaluation(result)
    ? (result.matchedRules as BrowserRule[])
    : (result.firedRules as BrowserRule[]);
}
