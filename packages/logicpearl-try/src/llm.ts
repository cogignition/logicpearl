import pc from 'picocolors';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import type { ExplainOptions, CapturedRun, CaptureFile } from './explain.js';
import { formatVerdict, hr, box } from './render.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

async function readPolicy(): Promise<string> {
  const path = resolve(__dirname, '..', 'captures', 'policy.md');
  return readFile(path, 'utf-8');
}

async function readPrompt(): Promise<string> {
  const path = resolve(__dirname, '..', 'captures', 'prompt.txt');
  return readFile(path, 'utf-8');
}

export interface LiveRunResult {
  run: number;
  response: string;
  response_time_ms: number;
  model: string;
}

export async function callClaudeOnce(
  apiKey: string,
  systemPrompt: string,
  userPrompt: string,
  run: number,
  model: string = 'claude-sonnet-4-20250514',
): Promise<LiveRunResult> {
  const t0 = Date.now();
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model,
      max_tokens: 512,
      system: systemPrompt,
      messages: [{ role: 'user', content: userPrompt }],
    }),
  });
  const elapsed = Date.now() - t0;
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Claude API error ${res.status}: ${text.slice(0, 200)}`);
  }
  const data = (await res.json()) as { content: Array<{ text?: string }> };
  const response = data.content.map((c) => c.text ?? '').join('').trim();
  return { run, response, response_time_ms: elapsed, model };
}

export async function callOpenAIOnce(
  apiKey: string,
  systemPrompt: string,
  userPrompt: string,
  run: number,
  model: string = 'gpt-4o',
): Promise<LiveRunResult> {
  const t0 = Date.now();
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      max_tokens: 512,
    }),
  });
  const elapsed = Date.now() - t0;
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`OpenAI API error ${res.status}: ${text.slice(0, 200)}`);
  }
  const data = (await res.json()) as {
    choices: Array<{ message: { content?: string } }>;
  };
  const response = (data.choices[0]?.message?.content ?? '').trim();
  return { run, response, response_time_ms: elapsed, model };
}

export async function liveExplain(opts: ExplainOptions): Promise<void> {
  const anthropicKey = process.env.ANTHROPIC_API_KEY;
  const openaiKey = process.env.OPENAI_API_KEY;

  if (!anthropicKey && !openaiKey) {
    console.error(pc.red('✗ ') + '--live requires an LLM API key.');
    console.error('');
    console.error('  Set one of:');
    console.error('    ' + pc.bold('ANTHROPIC_API_KEY') + '    (Claude, recommended for consistency with captures)');
    console.error('    ' + pc.bold('OPENAI_API_KEY') + '       (GPT-4 / GPT-4o)');
    console.error('');
    console.error('  Or drop --live to see the 5 captured runs we shipped:');
    console.error('    ' + pc.green('npx @logicpearl/try --explain'));
    console.error('');
    process.exit(1);
  }

  const policy = await readPolicy();
  const promptBase = await readPrompt();
  const systemPrompt = `You are a refund policy assistant.\n\nHere is our company's refund policy:\n\n${policy}`;

  const request = JSON.stringify(opts.result.facts, null, 2);
  const userPrompt = promptBase.replace('{{REQUEST_JSON}}', request);

  const useClaude = Boolean(anthropicKey);
  const model = useClaude ? 'claude-sonnet-4-20250514' : 'gpt-4o';

  console.log(pc.dim(`⏳ Calling ${model}, 5x in parallel…`));
  console.log(pc.dim('   (costs ~$0.02)'));
  console.log();

  const runner = useClaude
    ? (n: number) => callClaudeOnce(anthropicKey!, systemPrompt, userPrompt, n, model)
    : (n: number) => callOpenAIOnce(openaiKey!, systemPrompt, userPrompt, n, model);

  const runs = await Promise.allSettled([1, 2, 3, 4, 5].map((n) => runner(n)));

  const successful: LiveRunResult[] = [];
  for (const r of runs) {
    if (r.status === 'fulfilled') successful.push(r.value);
    else {
      console.error(pc.red('  ✗ ') + pc.dim(r.reason?.message ?? 'unknown error'));
    }
  }
  if (successful.length === 0) {
    console.error(pc.red('✗ ') + 'All live calls failed.');
    console.error(pc.dim('  Try the captured-mode demo: ') + pc.green('npx @logicpearl/try --explain'));
    process.exit(1);
  }

  const capture: CaptureFile = {
    artifact_name: opts.result.artifact.manifest.artifact_name ?? 'artifact',
    capture_methodology: 'live',
    prompt_hash: 'runtime',
    sample_input: opts.result.facts,
    runs: successful.map<CapturedRun>((r) => ({
      run: r.run,
      model: r.model,
      captured_at: new Date().toISOString(),
      response_time_ms: r.response_time_ms,
      response: r.response,
      annotation: { kind: 'partial', note: '(annotation not computed for live runs)' },
    })),
  };

  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          captures: capture.runs,
          logicpearl_verdict: {
            decision_kind: opts.result.decisionKind,
            verdict: opts.result.verdict,
            action: opts.result.action,
            fired_rules: opts.result.firedRules.map((r) => r.id),
            latency_ms: opts.result.latencyMs,
          },
        },
        null,
        2,
      ),
    );
    return;
  }

  const { renderExplain } = await import('./explain.js');
  console.log(renderExplain(opts.result, capture));
}
