import pc from 'picocolors';
import { RunResult, Artifact } from './run.js';
import { VERSION } from './version.js';
import {
  box,
  formatFacts,
  formatFiredRules,
  formatVerdict,
  hr,
  stripAnsi,
} from './render.js';

export interface RenderOptions {
  usingEmbedded?: boolean;
}

export function renderDefault(result: RunResult, opts: RenderOptions = {}): string {
  const { artifact, facts, verdict, decisionKind, allow, firedRules, latencyMs, defaulted } = result;
  const ruleCount = artifact.metadata.rules?.length ?? 0;
  const wasmSize = approximateWasmKb(artifact);
  const name =
    artifact.manifest.artifact_name ??
    (artifact.manifest as Record<string, unknown>).artifact_id as string | undefined ??
    artifact.metadata.action_policy_id ??
    artifact.metadata.gate_id ??
    'artifact';
  const policyId = artifact.metadata.action_policy_id ?? artifact.metadata.gate_id ?? 'unknown';
  const kindLabel = decisionKind === 'action' ? 'Policy' : 'Gate';
  const outcomeLabel = decisionKind === 'action'
    ? (defaulted ? 'Outcome: default action selected.' : 'Selected rules:')
    : allow
      ? 'Outcome: all gates pass.'
      : 'Fired rules:';

  // Orient a first-time reader in 3 lines before any data.
  const preamble = opts.usingEmbedded
    ? [
        pc.bold(pc.cyan('LogicPearl')) + pc.dim(' — a deterministic rule engine for agents and services.'),
        pc.dim('Same input always produces the same verdict, with a signed rule trace.'),
        pc.dim('This runs the bundled ') + pc.bold('sample refund policy') + pc.dim(' as a demo.') +
          pc.dim(' Your own policies compile to the same artifact shape.'),
        '',
      ]
    : [
        pc.bold(pc.cyan('LogicPearl')) + pc.dim(' — evaluating your artifact.'),
        '',
      ];

  const headerBox = box('LogicPearl · try  v' + VERSION, [
    '',
    `${pc.dim('Artifact')}   ${pc.bold(name)}`,
    `${pc.dim(kindLabel)}     ${pc.cyan(policyId)}`,
    `${pc.dim('Features')}   ${artifact.featureCount}`,
    `${pc.dim('Rules')}      ${ruleCount}`,
    `${pc.dim('Size')}       ${wasmSize}`,
    '',
  ]);

  const parts = [
    ...preamble,
    headerBox,
    '',
    pc.dim(opts.usingEmbedded
      ? 'Sample input (a real customer request, shipped with the package):'
      : 'Input:'),
    formatFacts(facts),
    '',
    hr(),
    `${pc.bold('Verdict:')}  ${formatVerdict(verdict)}` +
      `  ${pc.dim('(' + latencyMs + ' ms · ' + firedRules.length + ' of ' + ruleCount + ' decision-driving rules)')}`,
    hr(),
    '',
    pc.bold(
      decisionKind === 'gate' && allow
        ? pc.green(outcomeLabel)
        : pc.dim(outcomeLabel),
    ),
    decisionKind === 'gate' && allow ? '' : formatFiredRules(firedRules),
    '',
    pc.dim('Same input → same verdict, every run, every deployment.'),
    '',
  ];

  if (opts.usingEmbedded) {
    parts.push(pc.dim('Try next:'));
    parts.push(
      '  ' + pc.green('npx @logicpearl/try --explain') +
        pc.dim('                 # see what an LLM does with this'),
    );
    parts.push(
      '  ' + pc.green('npx @logicpearl/try --from-text "…"') +
        pc.dim('             # 3-stage pipeline demo'),
    );
    parts.push(
      '  ' + pc.green('npx @logicpearl/try --artifact <your-url>') +
        pc.dim('       # evaluate your own compiled rules'),
    );
    parts.push(
      '  ' + pc.green('npx @logicpearl/mcp install') +
        pc.dim('                    # plug into Claude Desktop / Cursor'),
    );
    parts.push('');
  }

  return parts.join('\n');
}

interface DescribePayload {
  artifact_name: string;
  decision_kind: 'gate' | 'action';
  policy_id: string;
  feature_count: number;
  features: Array<{
    id: string;
    type: string;
    encoding: string;
    allowed_values?: string[];
  }>;
  rule_count: number;
  rules: Array<{
    id: string;
    bit: number;
    label?: string;
    action?: string;
    counterfactual_hint?: string;
  }>;
}

export function renderDescribe(
  artifact: Artifact,
  opts: { json: boolean },
): DescribePayload | string {
  const payload: DescribePayload = {
    artifact_name: artifact.manifest.artifact_name ?? 'artifact',
    decision_kind: artifact.metadata.decision_kind ?? 'gate',
    policy_id: artifact.metadata.action_policy_id ?? artifact.metadata.gate_id ?? 'unknown',
    feature_count: artifact.featureCount,
    features: artifact.metadata.features.map((f) => {
      const encoding =
        typeof f.encoding === 'string' ? f.encoding : f.encoding?.kind ?? 'unknown';
      const result: DescribePayload['features'][number] = {
        id: f.id,
        type: f.type ?? 'unknown',
        encoding,
      };
      if (f.type === 'string' && artifact.metadata.string_codes) {
        const allowed = Object.keys(artifact.metadata.string_codes);
        if (allowed.length > 0) result.allowed_values = allowed;
      }
      return result;
    }),
    rule_count: artifact.metadata.rules?.length ?? 0,
    rules: (artifact.metadata.rules ?? []).map((r) => ({
      id: r.id,
      bit: r.bit,
      label: r.label,
      action: r.action,
      counterfactual_hint: r.counterfactual_hint,
    })),
  };

  if (opts.json) return payload;

  const out: string[] = [];
  out.push(pc.bold(pc.cyan(payload.artifact_name)) + '  ' + pc.dim('(' + payload.policy_id + ')'));
  out.push('');
  out.push(pc.bold(`Features  (${payload.feature_count})`));
  for (const f of payload.features) {
    const type = pc.dim(`[${f.type} / ${f.encoding}]`);
    const allowed = f.allowed_values
      ? pc.dim(' ∈ {' + f.allowed_values.join(', ') + '}')
      : '';
    out.push(`  ${pc.green(f.id)} ${type}${allowed}`);
  }
  out.push('');
  out.push(pc.bold(`Rules  (${payload.rule_count})`));
  for (const r of payload.rules) {
    const action = r.action ? pc.yellow(` → ${r.action}`) : '';
    const label = r.label ? pc.dim('     ' + r.label) : '';
    out.push(`  ${pc.green(r.id)}${action}`);
    if (label) out.push(label);
  }
  out.push('');
  return out.join('\n');
}

export function renderJson(result: RunResult): unknown {
  return {
    artifact: result.artifact.manifest.artifact_name,
    decision_kind: result.decisionKind,
    gate_id: result.decisionKind === 'gate' ? result.artifact.metadata.gate_id : null,
    action_policy_id:
      result.decisionKind === 'action' ? result.artifact.metadata.action_policy_id : null,
    verdict: result.verdict,
    allow: result.allow,
    action: result.action,
    default_action: result.defaultAction,
    defaulted: result.defaulted,
    bitmask: result.bitmask,
    fired_rule_count: result.firedRules.length,
    fired_rules: result.firedRules.map((r) => ({
      id: r.id,
      label: r.label,
      action: r.action,
      counterfactual_hint: r.counterfactual_hint,
    })),
    matched_rule_count: result.matchedRules.length,
    matched_rules: result.matchedRules.map((r) => ({
      id: r.id,
      label: r.label,
      action: r.action,
      counterfactual_hint: r.counterfactual_hint,
    })),
    latency_ms: result.latencyMs,
    features: result.facts,
  };
}

// Re-exports for cli.ts convenience.
export { renderExplain } from './explain.js';
export { renderFromText } from './from-text.js';

function approximateWasmKb(artifact: Artifact): string {
  // We don't currently have direct bytes on the artifact. Approximate from feature count.
  // The caller has already loaded it; we can report metadata-derived size.
  const rules = artifact.metadata.rules?.length ?? 0;
  const approx = 4 + rules * 0.4 + artifact.featureCount * 0.3;
  return `~${approx.toFixed(1)} KB`;
}
