import {
  drivingRules,
  isActionEvaluation,
  loadFromPathOrUrl,
  matchedRules,
} from '../load.js';

export const EVALUATE_TOOL = {
  name: 'logicpearl_evaluate',
  description:
    'Deterministically evaluate a compiled LogicPearl rule artifact against a feature vector. ' +
    'Returns a verdict (e.g. APPROVE / DENY / ROUTE_TO_*), which rules fired, and a replayable bitmask. ' +
    'Same inputs always produce the same output — no randomness, no model temperature. ' +
    'Call this before committing to a decision whenever the task involves policy gates, eligibility checks, ' +
    'or routing rules that have been compiled into a LogicPearl artifact.',
  inputSchema: {
    type: 'object',
    properties: {
      artifact: {
        type: 'string',
        description:
          'Optional path or URL to a LogicPearl artifact.json. If omitted, the default refund-eligibility artifact shipped with the server is used.',
      },
      facts: {
        type: 'object',
        description:
          'Feature vector for evaluation. Call logicpearl_describe_artifact first to learn the schema (feature ids, types, allowed string codes).',
      },
    },
    required: ['facts'],
  },
} as const;

export interface EvaluateArgs {
  artifact?: string;
  facts: Record<string, unknown>;
}

export async function runEvaluateTool(
  args: EvaluateArgs,
  defaultArtifact: string,
): Promise<unknown> {
  const artifactRef = args.artifact ?? defaultArtifact;
  const artifact = await loadFromPathOrUrl(artifactRef);
  const t0 = performance.now();
  const result = artifact.evaluate(args.facts);
  const latencyMs = Math.round((performance.now() - t0) * 1000) / 1000;
  const selectedRules = drivingRules(result);
  const allMatchedRules = matchedRules(result);

  const verdict = isActionEvaluation(result)
    ? result.action.toUpperCase()
    : result.allow
      ? (artifact.manifest.default_action ?? 'approve').toString().toUpperCase()
      : selectedRules[0]?.action?.toUpperCase() || 'DENY';

  const rules = (artifact.metadata.rules ?? []) as Array<Record<string, unknown>>;
  const bits = rules.map((r) =>
    allMatchedRules.find((f) => f.bit === (r.bit as number)) ? '1' : '0',
  );
  const bitmask = '0b' + (bits.length > 0 ? bits.reverse().join('') : '0');

  return {
    decision_kind: result.decisionKind,
    verdict,
    allow: isActionEvaluation(result) ? null : result.allow,
    action: isActionEvaluation(result) ? result.action : null,
    default_action: isActionEvaluation(result)
      ? result.defaultAction
      : artifact.manifest.default_action ?? null,
    defaulted: result.defaulted,
    fired_rules: selectedRules.map((r) => ({
      id: r.id,
      action: r.action,
      label: r.label,
      counterfactual_hint: r.counterfactual_hint,
    })),
    matched_rules: allMatchedRules.map((r) => ({
      id: r.id,
      action: r.action,
      label: r.label,
      counterfactual_hint: r.counterfactual_hint,
    })),
    counterfactual_hints: result.counterfactualHints,
    bitmask,
    latency_ms: latencyMs,
    artifact: {
      name:
        artifact.manifest.artifact_name ??
        artifact.manifest.artifact_id ??
        artifact.metadata.action_policy_id ??
        artifact.metadata.gate_id ??
        'unknown',
      ref: artifactRef,
    },
  };
}
