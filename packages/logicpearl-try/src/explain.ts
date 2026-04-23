import pc from 'picocolors';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { RunResult } from './run.js';
import { formatVerdict, hr, box } from './render.js';

export interface CapturedRun {
  run: number;
  model: string;
  captured_at: string;
  response_time_ms: number;
  response: string;
  annotation: {
    kind: 'correct' | 'wrong' | 'hedged' | 'hallucinated' | 'partial';
    note: string;
  };
}

export interface CaptureFile {
  artifact_name: string;
  capture_methodology: string;
  prompt_hash: string;
  sample_input: Record<string, unknown>;
  runs: CapturedRun[];
}

const MARKER: Record<CapturedRun['annotation']['kind'], string> = {
  correct: pc.green('✓'),
  wrong: pc.red('✗'),
  hedged: pc.yellow('⚠'),
  hallucinated: pc.red('❓'),
  partial: pc.yellow('⚡'),
};

export interface ExplainOptions {
  result: RunResult;
  live: boolean;
  json: boolean;
  captureDir: string;
}

export async function runExplain(opts: ExplainOptions): Promise<void> {
  if (opts.live) {
    return runLive(opts);
  }
  return runCaptured(opts);
}

async function runCaptured(opts: ExplainOptions): Promise<void> {
  const capturePath = resolve(opts.captureDir, 'claude-sonnet-5-runs.json');
  let data: CaptureFile;
  try {
    const raw = await readFile(capturePath, 'utf-8');
    data = JSON.parse(raw);
  } catch {
    console.error(pc.red('✗ ') + 'Could not load captured LLM runs.');
    console.error(pc.dim('  Expected file: ' + capturePath));
    console.error(pc.dim('  Was this package installed from npm? Try reinstalling.'));
    process.exit(1);
  }

  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          captures: data.runs,
          logicpearl_verdict: {
            verdict: opts.result.verdict,
            fired_rules: opts.result.firedRules.map((r) => r.id),
            latency_ms: opts.result.latencyMs,
            bitmask: opts.result.bitmask,
          },
        },
        null,
        2,
      ),
    );
    return;
  }

  console.log(renderExplain(opts.result, data));
}

export function renderExplain(result: RunResult, captures: CaptureFile): string {
  const parts: string[] = [];
  const totalMs = captures.runs.reduce((acc, r) => acc + r.response_time_ms, 0);
  const avgMs = Math.round(totalMs / Math.max(1, captures.runs.length));
  const model = captures.runs[0]?.model ?? 'Claude';
  parts.push(
    box('LogicPearl vs. LLM', [
      '',
      `${pc.dim('Same refund policy, same input.')}`,
      `${pc.dim('Below:')} ${pc.bold(model)}, 5 serial runs`,
      `${pc.dim('captured ' + (captures.runs[0]?.captured_at ?? '?') + ', default temperature.')}`,
      '',
    ]),
  );
  parts.push('');

  for (const run of captures.runs) {
    const marker = MARKER[run.annotation.kind];
    const time = pc.dim(`(${(run.response_time_ms / 1000).toFixed(1)}s)`);
    const header = `  ${pc.bold('Run ' + run.run)}  ${time}  ${marker}  `;
    const response = truncate(run.response, 220);
    parts.push(header + pc.dim(wrapText(response, 62, 22)));
    parts.push('      ' + pc.dim(pc.italic(run.annotation.note)));
    parts.push('');
  }

  parts.push(hr());
  parts.push('');
  parts.push(
    `  ${pc.bold('LogicPearl verdict:')}  ${formatVerdict(result.verdict)}  ` +
      pc.dim(`(${result.latencyMs} ms · ${result.firedRules.length} of ${(result.artifact.metadata.rules ?? []).length} rules fired)`),
  );
  if (result.firedRules.length > 0) {
    parts.push('');
    parts.push('  ' + pc.dim('Fired rules:'));
    for (const r of result.firedRules) {
      parts.push('    ' + pc.red('•') + ' ' + r.id + pc.dim(' — ' + (r.label ?? '')));
    }
  }
  parts.push('');
  parts.push(hr());
  parts.push('');
  // Tally LLM verdicts to surface the agree/disagree contrast.
  const verdictPattern = /(APPROVE|DENY|ROUTE_TO_REVIEW|ROUTE_TO_FINANCE)/;
  const llmVerdicts = captures.runs.map((r) => {
    const m = verdictPattern.exec(r.response);
    return m ? m[1] : 'unclear';
  });
  const agreed = llmVerdicts.filter((v) => v === result.verdict).length;
  const disagreed = captures.runs.length - agreed;

  parts.push(pc.bold('What just happened:'));
  parts.push('');
  parts.push(pc.dim('  The LLM took ') + pc.bold(`~${avgMs} ms`) + pc.dim(' per run (5 runs, total ~') +
    pc.bold(`${Math.round(totalMs)} ms`) + pc.dim(').'));
  parts.push(pc.dim('  LogicPearl took ') + pc.bold(`${result.latencyMs} ms`) + pc.dim(' once, and returns the same bitmask every run.'));
  parts.push('');
  if (disagreed === captures.runs.length) {
    parts.push(pc.dim('  Of 5 LLM runs, ') + pc.bold(pc.red(`all ${disagreed} disagreed`)) + pc.dim(' with the compiled artifact.'));
    parts.push(pc.dim('  The LLM read the policy prose and applied it one way; the artifact enforces'));
    parts.push(pc.dim('  the compiled policy another way. Both are "reasonable." One is deterministic.'));
  } else if (disagreed > 0) {
    parts.push(pc.dim('  Of 5 LLM runs, ') + pc.bold(pc.red(`${disagreed} disagreed`)) + pc.dim(` with the artifact; ${agreed} agreed.`));
    parts.push(pc.dim('  Same input. Same policy. Different verdicts. No way to replay the exact decision later.'));
  } else {
    parts.push(pc.dim('  All 5 LLM runs agreed with the artifact on this case — but the prose varies'));
    parts.push(pc.dim('  every time, and you paid latency + tokens for an answer you could have cached.'));
  }
  parts.push('');
  parts.push(pc.dim('  Pick your policy of record:'));
  parts.push(pc.dim('    • ') + pc.bold('Artifact: ') + pc.dim(`signed, diff-able, `) + pc.bold(`~${Math.round(avgMs / Math.max(result.latencyMs, 0.01))}× faster`) + pc.dim(`, $0 per call, byte-identical every run.`));
  parts.push(pc.dim('    • ') + pc.bold('LLM: ') + pc.dim('reads prose, handles novelty, but ') + pc.bold(`can disagree with itself and with you`) + pc.dim('.'));
  parts.push('');
  parts.push(hr());
  parts.push('');
  parts.push(pc.dim('These captures are real runs, not fabricated. Model: ') + pc.bold(model) + pc.dim('.'));
  parts.push(pc.dim('See: ') + pc.cyan('node_modules/@logicpearl/try/captures/claude-sonnet-5-runs.json'));
  parts.push(pc.dim('Run live against your own key: ') + pc.green('npx @logicpearl/try --explain --live'));
  parts.push('');
  return parts.join('\n');
}

async function runLive(opts: ExplainOptions): Promise<void> {
  const { liveExplain } = await import('./llm.js');
  await liveExplain(opts);
}

function truncate(s: string, max: number): string {
  const normalized = s.replace(/\s+/g, ' ').trim();
  if (normalized.length <= max) return '"' + normalized + '"';
  return '"' + normalized.slice(0, max).trim() + '…"';
}

function wrapText(s: string, width: number, indent: number): string {
  const pad = ' '.repeat(indent);
  const words = s.split(/(\s+)/);
  const lines: string[] = [];
  let cur = '';
  for (const w of words) {
    if ((cur + w).length > width && cur.length > 0) {
      lines.push(cur.trimEnd());
      cur = w.trimStart();
    } else {
      cur += w;
    }
  }
  if (cur.trim().length > 0) lines.push(cur.trimEnd());
  return lines.join('\n' + pad);
}
