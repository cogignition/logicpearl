import pc from 'picocolors';

type Verdict = 'APPROVE' | 'DENY' | 'ROUTE_TO_REVIEW' | 'ROUTE_TO_FINANCE' | string;

export function box(title: string, lines: string[]): string {
  // Interior width: the space between │ and │, excluding margins.
  // We want 2 chars of left padding ("  ") and 1 char of right padding (" ").
  const titleBare = stripAnsi(title);
  const maxBodyWidth = Math.max(0, ...lines.map((l) => stripAnsi(l).length));
  const interior = Math.max(titleBare.length + 4, maxBodyWidth + 3);
  // Top: ╭─ TITLE ─── ... ╮  — uses interior + 2 dashes (the "─" after ╭ and before ╮)
  const topDashes = interior - titleBare.length - 3; // minus leading "─ ", the title, trailing " "
  const top = '╭─ ' + title + ' ' + '─'.repeat(Math.max(0, topDashes)) + '╮';
  const bottom = '╰' + '─'.repeat(interior + 2) + '╯';
  const body = lines
    .map((l) => {
      const pad = interior - stripAnsi(l).length - 2;
      return '│  ' + l + ' '.repeat(Math.max(0, pad)) + ' │';
    })
    .join('\n');
  return [top, body, bottom].join('\n');
}

export function rule(width: number = 56): string {
  return pc.dim('─'.repeat(width));
}

export function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1B\[[0-9;]*[A-Za-z]/g, '');
}

export function verdictColor(verdict: Verdict): (s: string) => string {
  if (verdict === 'APPROVE') return pc.green;
  if (verdict === 'DENY') return pc.red;
  if (verdict.startsWith('ROUTE_TO')) return pc.yellow;
  return pc.cyan;
}

export function formatVerdict(verdict: Verdict): string {
  return verdictColor(verdict)(pc.bold(verdict));
}

export function formatValue(v: unknown): string {
  if (v === null || v === undefined) return pc.dim('null');
  if (typeof v === 'boolean') return v ? pc.green('true') : pc.red('false');
  if (typeof v === 'number') return pc.yellow(String(v));
  if (typeof v === 'string') return pc.cyan(`"${v}"`);
  return JSON.stringify(v);
}

export function formatFacts(facts: Record<string, unknown>): string {
  const maxKey = Math.max(...Object.keys(facts).map((k) => k.length));
  return Object.entries(facts)
    .map(([k, v]) => `  ${pc.dim(k.padEnd(maxKey))}  ${formatValue(v)}`)
    .join('\n');
}

export function hr(): string {
  return pc.dim('─'.repeat(56));
}

export interface FiredRule {
  id: string;
  label?: string;
  message?: string;
  counterfactual_hint?: string;
  action?: string;
}

export function formatFiredRules(rules: FiredRule[]): string {
  if (rules.length === 0) {
    return pc.green('  ✓ No rules fired. All gates pass.');
  }
  return rules
    .map((r) => {
      const label = r.label || r.message || r.id;
      const hint = r.counterfactual_hint
        ? `\n      ${pc.dim('↳ ' + r.counterfactual_hint)}`
        : '';
      return `  ${pc.red('•')}  ${pc.bold(r.id)}${pc.dim(':')} ${label}${hint}`;
    })
    .join('\n');
}

export function header(): string {
  return pc.bold(pc.cyan('LogicPearl · try'));
}

export function kbd(s: string): string {
  return pc.bgBlack(pc.white(` ${s} `));
}
