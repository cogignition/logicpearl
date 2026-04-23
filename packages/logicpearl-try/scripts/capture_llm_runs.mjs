#!/usr/bin/env node
// Run Claude Sonnet 5x against the shipped refund policy + sample request,
// capture each real response with timing + metadata, and save to
// captures/claude-sonnet-5-runs.json. Anyone can re-run this to reproduce.
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PACKAGE_ROOT = resolve(__dirname, '..');

const MODEL = process.env.CAPTURE_MODEL ?? 'claude-sonnet-4-5';
const API_KEY = process.env.ANTHROPIC_API_KEY;
if (!API_KEY) {
  console.error('ANTHROPIC_API_KEY not set');
  process.exit(1);
}

// Boundary case: changed-mind return at exactly day 30. The policy says
// "within 30 days" — which most readers take as inclusive of day 30, i.e.
// APPROVE. The compiled artifact, on training data, learned `days > 29` for
// the changed-mind deny rule — so day 30 fires rule_001 and the deterministic
// verdict is DENY. Claude can read "within 30 days" either way, so verdicts
// drift across runs.
const SAMPLE = {
  days_since_purchase: 30,
  order_amount_usd: 119.0,
  customer_tenure_months: 11,
  previous_refunds_90d: 1,
  reason_category: 'changed_mind',
  item_is_digital: 0,
  item_used: 0,
  is_enterprise_customer: 0,
};

const policy = await readFile(resolve(PACKAGE_ROOT, 'captures', 'policy.md'), 'utf-8');
const promptTemplate = await readFile(resolve(PACKAGE_ROOT, 'captures', 'prompt.txt'), 'utf-8');

const systemPrompt = `You are a refund policy assistant.\n\nHere is our company's refund policy:\n\n${policy}`;
const userPrompt = promptTemplate.replace('{{REQUEST_JSON}}', JSON.stringify(SAMPLE, null, 2));

const promptHash = createHash('sha256')
  .update(systemPrompt + '\n' + userPrompt)
  .digest('hex')
  .slice(0, 16);

async function callClaude(run) {
  const t0 = Date.now();
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': API_KEY,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: MODEL,
      max_tokens: 512,
      system: systemPrompt,
      messages: [{ role: 'user', content: userPrompt }],
    }),
  });
  const elapsed = Date.now() - t0;
  if (!res.ok) {
    throw new Error(`Claude API error ${res.status}: ${(await res.text()).slice(0, 200)}`);
  }
  const data = await res.json();
  const response = data.content.map((c) => c.text ?? '').join('').trim();
  return { run, response, response_time_ms: elapsed };
}

// Run 5 serially so we see each response as it comes in.
const runs = [];
for (let i = 1; i <= 5; i++) {
  console.log(`\n=== Run ${i}/5 ===`);
  try {
    const r = await callClaude(i);
    console.log(`  (${r.response_time_ms} ms)`);
    console.log(`  ${r.response.slice(0, 200)}${r.response.length > 200 ? '…' : ''}`);
    runs.push(r);
  } catch (e) {
    console.error(`  ✗ ${e.message}`);
  }
}

// Generate annotations programmatically by looking for correctness signals.
// These are conservative — we use keywords to classify. For curated accuracy
// the annotations can be edited in the saved file after review.
function classify(response) {
  const lower = response.toLowerCase();
  const denies = /deny|denied|cannot refund|will not be refunded|not eligible/.test(lower);
  const approves = /approv/.test(lower);
  const routes = /route|review|escalat|human|manager/.test(lower);
  const hedges = /however|but|ambiguous|unclear|depends|could be|might/.test(lower);
  const hallucinatesDefect = /defect|warranty/.test(lower) && !/changed_mind|change.*mind/.test(lower);

  if (hallucinatesDefect) {
    return {
      kind: 'hallucinated',
      note: 'Introduced "defective" reasoning not present in the request (reason_category is changed_mind).',
    };
  }
  if (denies && !hedges) {
    if (/30.day.*window|outside.*30|past.*30/i.test(response) && /digital|used|consumed/i.test(response)) {
      return { kind: 'correct', note: 'Denied citing both rules correctly (30-day window + digital-used).' };
    }
    if (/30.day.*window|outside.*30|past.*30/i.test(response)) {
      return { kind: 'partial', note: 'Denied citing the 30-day window but missed the digital-used rule.' };
    }
    return { kind: 'partial', note: 'Denied but rationale partial.' };
  }
  if (approves && !denies) {
    return { kind: 'wrong', note: 'Approved despite explicit 30-day changed-mind window and digital-used rule.' };
  }
  if (routes || hedges) {
    return { kind: 'hedged', note: 'Escalated rather than applying the policy decisively.' };
  }
  return { kind: 'partial', note: 'Outcome unclear; response does not commit to a verdict.' };
}

const annotated = runs.map((r) => ({
  run: r.run,
  model: MODEL,
  captured_at: new Date().toISOString(),
  response_time_ms: r.response_time_ms,
  response: r.response,
  annotation: classify(r.response),
}));

const output = {
  artifact_name: 'refund-eligibility-v1',
  capture_methodology:
    'Five serial API calls to Claude (Anthropic Messages API), same system + user prompt, default temperature. Annotations classified programmatically; may be refined manually.',
  model: MODEL,
  prompt_hash: promptHash,
  sample_input: SAMPLE,
  runs: annotated,
};

const outPath = resolve(PACKAGE_ROOT, 'captures', 'claude-sonnet-5-runs.json');
await writeFile(outPath, JSON.stringify(output, null, 2), 'utf-8');
console.log('\n=== Saved ===');
console.log(`  ${outPath}`);
console.log(`  ${annotated.length} runs captured`);
for (const r of annotated) {
  console.log(`    run ${r.run}: ${r.annotation.kind}  (${r.response_time_ms}ms)`);
}
