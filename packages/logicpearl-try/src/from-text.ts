import pc from 'picocolors';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { loadFromPathOrUrl, runEvaluate } from './run.js';
import { formatFacts, formatVerdict, hr, box } from './render.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export interface FromTextOptions {
  text: string;
  artifactRef: string;
  proveIt: boolean;
  json: boolean;
}

const EXTRACTION_SCHEMA_INSTRUCTION = `
Return ONLY a JSON object with these exact 8 keys. Omit everything else.
No backticks. No explanation. Just JSON.
`;

export async function runFromText(opts: FromTextOptions): Promise<void> {
  const apiKey = process.env.ANTHROPIC_API_KEY ?? process.env.OPENAI_API_KEY;
  if (!apiKey) {
    console.error(pc.red('✗ ') + '--from-text requires an LLM API key for extraction and verbalization.');
    console.error('');
    console.error('  Set one of:');
    console.error('    ' + pc.bold('ANTHROPIC_API_KEY'));
    console.error('    ' + pc.bold('OPENAI_API_KEY'));
    console.error('');
    process.exit(1);
  }

  const artifact = await loadFromPathOrUrl(opts.artifactRef);
  const extractionTemplate = artifact.metadata.feature_extraction_prompt_template;

  if (!extractionTemplate) {
    console.error(pc.red('✗ ') + 'This artifact does not ship a feature_extraction_prompt_template.');
    console.error('  --from-text needs one to know how to extract features from prose.');
    process.exit(1);
  }

  const useClaude = Boolean(process.env.ANTHROPIC_API_KEY);
  const runCount = opts.proveIt ? 5 : 1;

  if (opts.proveIt) {
    await runProveIt(opts, artifact, extractionTemplate, useClaude);
  } else {
    await runOnce(opts, artifact, extractionTemplate, useClaude);
  }
}

interface PipelineRun {
  extracted: Record<string, unknown>;
  extractionMs: number;
  decisionKind: 'gate' | 'action';
  verdict: string;
  action: string | null;
  firedRules: string[];
  evalMs: number;
  response: string;
  verbalizationMs: number;
}

async function runOnce(
  opts: FromTextOptions,
  artifact: Awaited<ReturnType<typeof loadFromPathOrUrl>>,
  extractionTemplate: string,
  useClaude: boolean,
): Promise<void> {
  if (!opts.json) {
    console.log(
      box('LogicPearl · try · from text', [
        '',
        `${pc.dim('User asked:')}`,
        `  ${pc.italic('"' + opts.text + '"')}`,
        '',
      ]),
    );
    console.log();
  }

  // Step 1 — extraction
  if (!opts.json) process.stdout.write(pc.dim('Step 1 — LLM extracts features … '));
  const step1 = await extractFeatures(opts.text, extractionTemplate, useClaude);
  if (!opts.json) console.log(pc.dim(`(${step1.elapsedMs} ms)`));
  if (!opts.json) {
    console.log();
    console.log('  Extracted feature vector:');
    console.log(indent(formatFacts(step1.features), 4));
    console.log();
  }

  // Step 2 — evaluation
  if (!opts.json) process.stdout.write(pc.dim('Step 2 — LogicPearl evaluates … '));
  const { artifactUrl } = { artifactUrl: opts.artifactRef };
  const result = await runEvaluate({ artifactUrl, facts: step1.features });
  if (!opts.json) console.log(pc.dim(`(${result.latencyMs} ms)`));
  if (!opts.json) {
    console.log();
    console.log(`  ${pc.bold('Verdict:')}  ${formatVerdict(result.verdict)}`);
    if (result.firedRules.length > 0) {
      console.log(
        '  ' +
          pc.dim(result.decisionKind === 'action' ? 'Selected rules:' : 'Fired rules:'),
      );
      for (const r of result.firedRules) {
        console.log('    ' + pc.red('•') + ' ' + r.id + pc.dim(' — ' + (r.label ?? '')));
      }
    }
    console.log();
  }

  // Step 3 — verbalization
  if (!opts.json) process.stdout.write(pc.dim('Step 3 — LLM writes natural-language response … '));
  const step3 = await verbalizeVerdict(opts.text, step1.features, result, useClaude);
  if (!opts.json) console.log(pc.dim(`(${step3.elapsedMs} ms)`));
  if (!opts.json) {
    console.log();
    console.log('  ' + pc.italic(wrap(step3.response, 68, 2)));
    console.log();
    console.log(hr());
    console.log();
    console.log(
      pc.dim('Same text → same extraction → same verdict → stable response.'),
    );
    console.log(
      pc.dim('The extraction step will vary across runs; the verdict will not.'),
    );
    console.log();
    console.log(pc.dim('Run 5x to see which stages vary:'));
    console.log(
      '  ' +
        pc.green('npx @logicpearl/try --from-text "' +
          truncate(opts.text, 40) +
          '" --prove-it'),
    );
    console.log();
  }

  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          user_text: opts.text,
          pipeline: {
            step1_extraction: {
              features: step1.features,
              elapsed_ms: step1.elapsedMs,
            },
            step2_evaluation: {
              decision_kind: result.decisionKind,
              verdict: result.verdict,
              allow: result.allow,
              action: result.action,
              default_action: result.defaultAction,
              defaulted: result.defaulted,
              fired_rules: result.firedRules.map((r) => r.id),
              matched_rules: result.matchedRules.map((r) => r.id),
              latency_ms: result.latencyMs,
            },
            step3_verbalization: {
              response: step3.response,
              elapsed_ms: step3.elapsedMs,
            },
          },
        },
        null,
        2,
      ),
    );
  }
}

async function runProveIt(
  opts: FromTextOptions,
  artifact: Awaited<ReturnType<typeof loadFromPathOrUrl>>,
  extractionTemplate: string,
  useClaude: boolean,
): Promise<void> {
  if (!opts.json) {
    console.log(
      box('LogicPearl · try · from text · --prove-it', [
        '',
        `${pc.dim('Running the full 3-stage pipeline 5 times.')}`,
        `${pc.dim('Watch which stages vary.')}`,
        '',
      ]),
    );
    console.log();
    console.log(pc.dim('User asked: ') + pc.italic('"' + opts.text + '"'));
    console.log();
  }

  const runs: PipelineRun[] = [];
  for (let n = 1; n <= 5; n++) {
    const step1 = await extractFeatures(opts.text, extractionTemplate, useClaude);
    const result = await runEvaluate({ artifactUrl: opts.artifactRef, facts: step1.features });
    const step3 = await verbalizeVerdict(opts.text, step1.features, result, useClaude);
    runs.push({
      extracted: step1.features,
      extractionMs: step1.elapsedMs,
      decisionKind: result.decisionKind,
      verdict: result.verdict,
      action: result.action,
      firedRules: result.firedRules.map((r) => r.id),
      evalMs: result.latencyMs,
      response: step3.response,
      verbalizationMs: step3.elapsedMs,
    });
    if (!opts.json) {
      process.stdout.write(
        pc.dim(`  Run ${n}/5: `) +
          pc.cyan(`extraction ${step1.elapsedMs}ms`) +
          pc.dim(' → ') +
          formatVerdict(result.verdict) +
          pc.dim(` (${result.latencyMs}ms)`) +
          pc.dim(` → verbalization ${step3.elapsedMs}ms\n`),
      );
    }
  }

  if (!opts.json) {
    console.log();
    console.log(hr());
    console.log();
    // Show the variance.
    const verdicts = new Set(runs.map((r) => r.verdict));
    const extractions = new Set(runs.map((r) => JSON.stringify(r.extracted)));
    const responses = new Set(runs.map((r) => r.response));

    console.log(pc.bold('Variance across 5 runs:'));
    console.log('  ' + (extractions.size === 1 ? pc.green('✓') : pc.yellow('⚠')) +
      ` Extraction:       ${extractions.size === 1 ? 'identical across all 5 runs' : `${extractions.size} distinct variants`}`);
    console.log('  ' + (verdicts.size === 1 ? pc.green('✓') : pc.red('✗')) +
      ` LogicPearl verdict: ${verdicts.size === 1 ? pc.green('BYTE-IDENTICAL across all 5 runs') : `${verdicts.size} distinct verdicts`}`);
    console.log('  ' + (responses.size === 1 ? pc.green('✓') : pc.yellow('⚠')) +
      ` Verbalization:     ${responses.size === 1 ? 'identical' : `${responses.size} distinct phrasings`}`);
    console.log();
    if (verdicts.size === 1) {
      console.log(pc.bold('  The decision is the stable part. The LLM does the rest.'));
    }
    console.log();
  }

  if (opts.json) {
    console.log(JSON.stringify({ user_text: opts.text, runs }, null, 2));
  }
}

// ---- LLM helpers ----

interface ExtractionResult {
  features: Record<string, unknown>;
  elapsedMs: number;
}

async function extractFeatures(
  userText: string,
  extractionTemplate: string,
  useClaude: boolean,
): Promise<ExtractionResult> {
  const systemPrompt = extractionTemplate + '\n\n' + EXTRACTION_SCHEMA_INSTRUCTION;
  const userPrompt = `User said: """${userText}"""\n\nExtract the feature vector as JSON.`;
  const t0 = Date.now();
  const response = useClaude
    ? await callClaude(systemPrompt, userPrompt, 400)
    : await callOpenAI(systemPrompt, userPrompt, 400);
  const elapsed = Date.now() - t0;
  const features = parseJsonLoose(response);
  // Normalize bools that may come back as true/false strings or 0/1.
  const normalized: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(features)) {
    if (v === 'true' || v === true) normalized[k] = 1;
    else if (v === 'false' || v === false) normalized[k] = 0;
    else normalized[k] = v;
  }
  return { features: normalized, elapsedMs: elapsed };
}

interface VerbalizationResult {
  response: string;
  elapsedMs: number;
}

async function verbalizeVerdict(
  userText: string,
  features: Record<string, unknown>,
  result: Awaited<ReturnType<typeof runEvaluate>>,
  useClaude: boolean,
): Promise<VerbalizationResult> {
  const systemPrompt =
    'You translate a deterministic refund verdict into a short, polite, 2-3 sentence response to the customer. ' +
    'Do not make up rules; only reference the fired rules below if any. Do not hedge; the decision is final.';
  const userPrompt =
    `Customer said: "${userText}"\n\n` +
    `Feature vector: ${JSON.stringify(features)}\n\n` +
    `Decision kind: ${result.decisionKind}\n` +
    `Verdict: ${result.verdict}\n` +
    `Decision-driving rules: ${JSON.stringify(result.firedRules.map((r) => r.label ?? r.id))}\n\n` +
    'Respond directly to the customer.';
  const t0 = Date.now();
  const response = useClaude
    ? await callClaude(systemPrompt, userPrompt, 300)
    : await callOpenAI(systemPrompt, userPrompt, 300);
  const elapsed = Date.now() - t0;
  return { response: response.trim(), elapsedMs: elapsed };
}

async function callClaude(system: string, user: string, maxTokens: number): Promise<string> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) throw new Error('ANTHROPIC_API_KEY not set');
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: maxTokens,
      system,
      messages: [{ role: 'user', content: user }],
    }),
  });
  if (!res.ok) throw new Error(`Claude API error ${res.status}: ${(await res.text()).slice(0, 200)}`);
  const data = (await res.json()) as { content: Array<{ text?: string }> };
  return data.content.map((c) => c.text ?? '').join('');
}

async function callOpenAI(system: string, user: string, maxTokens: number): Promise<string> {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) throw new Error('OPENAI_API_KEY not set');
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: 'gpt-4o',
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user },
      ],
      max_tokens: maxTokens,
    }),
  });
  if (!res.ok) throw new Error(`OpenAI API error ${res.status}: ${(await res.text()).slice(0, 200)}`);
  const data = (await res.json()) as { choices: Array<{ message: { content?: string } }> };
  return data.choices[0]?.message?.content ?? '';
}

function parseJsonLoose(s: string): Record<string, unknown> {
  // Tolerate markdown fences and leading/trailing text the model sometimes emits.
  let cleaned = s.trim();
  if (cleaned.startsWith('```')) {
    cleaned = cleaned.replace(/^```(json)?\s*/, '').replace(/```\s*$/, '');
  }
  const start = cleaned.indexOf('{');
  const end = cleaned.lastIndexOf('}');
  if (start >= 0 && end > start) cleaned = cleaned.slice(start, end + 1);
  return JSON.parse(cleaned);
}

function indent(s: string, n: number): string {
  const pad = ' '.repeat(n);
  return s.split('\n').map((l) => pad + l).join('\n');
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max - 1) + '…';
}

function wrap(s: string, width: number, indentN: number): string {
  const words = s.split(/\s+/);
  const pad = ' '.repeat(indentN);
  const lines: string[] = [];
  let cur = '';
  for (const w of words) {
    if ((cur + ' ' + w).trim().length > width && cur) {
      lines.push(cur);
      cur = w;
    } else {
      cur = (cur + ' ' + w).trim();
    }
  }
  if (cur) lines.push(cur);
  return lines.join('\n' + pad);
}

export function renderFromText(): string {
  return '';
}
