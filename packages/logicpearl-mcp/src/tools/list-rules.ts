import { loadFromPathOrUrl } from '../load.js';

export const LIST_RULES_TOOL = {
  name: 'logicpearl_list_rules',
  description:
    'List every rule compiled into a LogicPearl artifact: rule id, action, human-readable label, ' +
    'the features it touches, and a counterfactual hint explaining what would flip the decision. ' +
    'Use this when the model needs to explain WHY a particular verdict is the policy, or to surface ' +
    'the exact rule that fired.',
  inputSchema: {
    type: 'object',
    properties: {
      artifact: {
        type: 'string',
        description:
          'Optional path or URL to a LogicPearl artifact.json. If omitted, the default refund-eligibility artifact shipped with the server is used.',
      },
    },
  },
} as const;

export interface ListRulesArgs {
  artifact?: string;
}

export async function runListRulesTool(
  args: ListRulesArgs,
  defaultArtifact: string,
): Promise<unknown> {
  const artifactRef = args.artifact ?? defaultArtifact;
  const artifact = await loadFromPathOrUrl(artifactRef);

  const rules = (artifact.metadata.rules ?? []) as Array<Record<string, unknown>>;
  return {
    ref: artifactRef,
    rule_count: rules.length,
    rules: rules.map((r) => ({
      id: r.id,
      bit: r.bit,
      priority: r.priority,
      action: r.action,
      label: r.label,
      message: r.message,
      counterfactual_hint: r.counterfactual_hint,
      features: Array.isArray(r.features)
        ? (r.features as Array<Record<string, unknown>>).map((f) => ({
            feature_id: f.feature_id,
            feature_label: f.feature_label,
          }))
        : [],
    })),
  };
}
