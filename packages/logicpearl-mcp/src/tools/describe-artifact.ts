import { loadFromPathOrUrl } from '../load.js';

export const DESCRIBE_ARTIFACT_TOOL = {
  name: 'logicpearl_describe_artifact',
  description:
    'Return the schema of a LogicPearl artifact: feature ids and types, allowed string codes, ' +
    'actions, default action, and a short description of each rule. ' +
    'Call this first to understand what inputs logicpearl_evaluate expects and what the possible verdicts are.',
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

export interface DescribeArgs {
  artifact?: string;
}

export async function runDescribeArtifactTool(
  args: DescribeArgs,
  defaultArtifact: string,
): Promise<unknown> {
  const artifactRef = args.artifact ?? defaultArtifact;
  const artifact = await loadFromPathOrUrl(artifactRef);

  const features = (artifact.metadata.features ?? []) as Array<Record<string, unknown>>;
  const rules = (artifact.metadata.rules ?? []) as Array<Record<string, unknown>>;
  const stringCodes = artifact.metadata.string_codes ?? {};

  return {
    name: artifact.manifest.artifact_name ?? artifact.manifest.artifact_id ?? artifact.metadata.gate_id ?? 'unknown',
    ref: artifactRef,
    default_action: artifact.manifest.default_action,
    actions: artifact.manifest.actions,
    features: features.map((f) => ({
      id: f.id,
      type: f.type,
      encoding: f.encoding,
    })),
    string_codes: stringCodes,
    rules: rules.map((r) => ({
      id: r.id,
      action: r.action,
      label: r.label,
      counterfactual_hint: r.counterfactual_hint,
    })),
    feature_extraction_prompt_template: artifact.metadata.feature_extraction_prompt_template ?? null,
  };
}
