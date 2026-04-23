#!/usr/bin/env node
import mri from 'mri';
import pc from 'picocolors';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { runEvaluate } from './run.js';
import { renderDefault, renderDescribe, renderJson, renderExplain, renderFromText } from './render-views.js';
import { VERSION } from './version.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// Embedded default artifact: ../../artifacts/refund-eligibility-v1/artifact.json
// relative to dist/ after compile; relative to src/ during dev.
const EMBEDDED_ARTIFACT = resolve(__dirname, '..', 'artifacts', 'refund-eligibility-v1', 'artifact.json');

// Boundary case. Changed-mind return at day 30 exactly. The policy prose says
// "within 30 days" — most readers treat that as inclusive (APPROVE). The
// compiled artifact learned `days > 29` for the changed-mind deny rule on the
// training data, so at day 30 rule_001 fires and the deterministic verdict is
// DENY. Claude interprets "within 30 days" differently across runs, so the
// 5-run capture usually shows a mix of DENY / APPROVE / ROUTE verdicts.
const EMBEDDED_SAMPLE: Record<string, unknown> = {
  days_since_purchase: 30,
  order_amount_usd: 119.0,
  customer_tenure_months: 11,
  previous_refunds_90d: 1,
  reason_category: 'changed_mind',
  item_is_digital: 0,
  item_used: 0,
  is_enterprise_customer: 0,
};

interface Argv {
  _: string[];
  help?: boolean;
  h?: boolean;
  version?: boolean;
  v?: boolean;
  artifact?: string;
  facts?: string;
  'facts-file'?: string;
  describe?: boolean;
  explain?: boolean;
  live?: boolean;
  'from-text'?: string;
  'prove-it'?: boolean;
  json?: boolean;
}

const HELP = `
${pc.bold(pc.cyan('LogicPearl · try'))}  ${pc.dim('v' + VERSION)}

  Kick the tires on LogicPearl. One command, deterministic verdicts, no setup.

${pc.bold('Usage:')}
  ${pc.green('npx @logicpearl/try')}                           Refund demo with the embedded sample
  ${pc.green('npx @logicpearl/try --facts <json>')}            Custom input against the embedded artifact
  ${pc.green('npx @logicpearl/try --facts-file <path>')}       Input from a JSON file
  ${pc.green('npx @logicpearl/try --artifact <url>')}          Use a different compiled artifact
  ${pc.green('npx @logicpearl/try --describe')}                Show feature + rule schema only
  ${pc.green('npx @logicpearl/try --explain')}                 Side-by-side vs 5 pre-captured LLM runs
  ${pc.green('npx @logicpearl/try --explain --live')}          Against a real LLM (needs API key)
  ${pc.green('npx @logicpearl/try --from-text "..."')}         3-stage pipeline: LLM → LogicPearl → LLM
  ${pc.green('npx @logicpearl/try --from-text "..." --prove-it')}  Run the pipeline 5x to show what varies
  ${pc.green('npx @logicpearl/try --json')}                    Machine-readable output

${pc.bold('Docs:')}   https://logicpearl.com/quickstart
${pc.bold('MCP:')}    ${pc.green('npx @logicpearl/mcp install')}   (plug LogicPearl into Claude Desktop / Cursor)
`;

function die(message: string, exitCode: number = 1): never {
  console.error(pc.red('✗ ') + message);
  process.exit(exitCode);
}

async function parseFacts(argv: Argv): Promise<Record<string, unknown> | null> {
  if (argv.facts) {
    try {
      return JSON.parse(argv.facts);
    } catch (err) {
      die(
        `--facts could not be parsed as JSON.\n  ${pc.dim((err as Error).message)}\n  Tip: use --facts-file for multi-line JSON.`,
      );
    }
  }
  if (argv['facts-file']) {
    try {
      const raw = await readFile(resolve(argv['facts-file']), 'utf-8');
      return JSON.parse(raw);
    } catch (err) {
      die(
        `--facts-file could not be loaded.\n  ${pc.dim((err as Error).message)}\n  Path: ${argv['facts-file']}`,
      );
    }
  }
  return null;
}

async function main() {
  const argv = mri(process.argv.slice(2), {
    boolean: ['help', 'version', 'describe', 'explain', 'live', 'prove-it', 'json'],
    string: ['artifact', 'facts', 'facts-file', 'from-text'],
    alias: { h: 'help', v: 'version' },
  }) as unknown as Argv;

  if (argv.help || argv.h) {
    console.log(HELP);
    return;
  }
  if (argv.version || argv.v) {
    console.log(VERSION);
    return;
  }

  const artifactRef = argv.artifact ?? EMBEDDED_ARTIFACT;
  const userFacts = await parseFacts(argv);

  // --from-text is its own pipeline; doesn't use --facts.
  if (argv['from-text']) {
    const { runFromText } = await import('./from-text.js');
    await runFromText({
      text: argv['from-text'],
      artifactRef,
      proveIt: Boolean(argv['prove-it']),
      json: Boolean(argv.json),
    });
    return;
  }

  // --describe: show schema, skip evaluation.
  if (argv.describe) {
    const { loadFromPathOrUrl } = await import('./run.js');
    const artifact = await loadFromPathOrUrl(artifactRef);
    if (argv.json) {
      console.log(JSON.stringify(renderDescribe(artifact, { json: true }), null, 2));
    } else {
      console.log(renderDescribe(artifact, { json: false }));
    }
    return;
  }

  // Evaluate with the embedded sample or user-provided facts.
  const facts = userFacts ?? EMBEDDED_SAMPLE;
  const result = await runEvaluate({ artifactUrl: artifactRef, facts });

  // --explain: add the side-by-side LLM comparison.
  if (argv.explain) {
    const { runExplain } = await import('./explain.js');
    await runExplain({
      result,
      live: Boolean(argv.live),
      json: Boolean(argv.json),
      captureDir: resolve(__dirname, '..', 'captures'),
    });
    return;
  }

  // Default: pretty output.
  if (argv.json) {
    console.log(JSON.stringify(renderJson(result), null, 2));
  } else {
    console.log(renderDefault(result, { usingEmbedded: !userFacts && !argv.artifact }));
  }
}

main().catch((err) => {
  die(`${(err as Error).message}\n${pc.dim((err as Error).stack ?? '')}`);
});
