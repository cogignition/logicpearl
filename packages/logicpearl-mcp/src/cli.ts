#!/usr/bin/env node
import mri from 'mri';
import pc from 'picocolors';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { VERSION } from './version.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// Default artifact ships with the package, relative to dist/
const DEFAULT_ARTIFACT = resolve(__dirname, '..', 'artifacts', 'refund-eligibility-v1', 'artifact.json');

const HELP = `
${pc.bold(pc.cyan('LogicPearl MCP server'))}  ${pc.dim('v' + VERSION)}

  Expose LogicPearl's deterministic rule engine to MCP-compatible hosts
  (Claude Desktop, Cursor, etc.) over stdio.

${pc.bold('Usage:')}
  ${pc.green('npx @logicpearl/mcp install')}            Auto-configure Claude Desktop + Cursor
  ${pc.green('npx @logicpearl/mcp install --host claude')}   Install for Claude Desktop only
  ${pc.green('npx @logicpearl/mcp install --host cursor')}   Install for Cursor only
  ${pc.green('npx @logicpearl/mcp install --dry-run')}       Print changes without writing
  ${pc.green('npx @logicpearl/mcp start')}              Run the server in the foreground (for testing)
  ${pc.green('npx @logicpearl/mcp')}                    Same as \`start\` — run the server

${pc.bold('Flags:')}
  ${pc.dim('--artifact <path>')}     Override the default artifact
  ${pc.dim('--help')}, ${pc.dim('-h')}            Show this message
  ${pc.dim('--version')}, ${pc.dim('-v')}         Print version

${pc.bold('Tools exposed:')}
  ${pc.cyan('logicpearl_evaluate')}          Evaluate a feature vector → verdict + fired rules
  ${pc.cyan('logicpearl_describe_artifact')} Features, string codes, rules, actions
  ${pc.cyan('logicpearl_list_rules')}        Enumerate every rule with counterfactual hints

${pc.bold('Docs:')}   https://logicpearl.com/developers/mcp
`;

interface Argv {
  _: string[];
  help?: boolean;
  h?: boolean;
  version?: boolean;
  v?: boolean;
  host?: string;
  'dry-run'?: boolean;
  artifact?: string;
}

function die(message: string, code: number = 1): never {
  console.error(pc.red('✗ ') + message);
  process.exit(code);
}

async function main() {
  const argv = mri(process.argv.slice(2), {
    boolean: ['help', 'version', 'dry-run'],
    string: ['host', 'artifact'],
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

  const subcommand = argv._[0] ?? 'start';
  const artifactRef = argv.artifact ?? DEFAULT_ARTIFACT;

  if (subcommand === 'install') {
    const { runInstall } = await import('./install.js');
    await runInstall({
      host: argv.host,
      dryRun: Boolean(argv['dry-run']),
      artifactRef,
    });
    return;
  }
  if (subcommand === 'start') {
    const { startServer } = await import('./server.js');
    await startServer({ defaultArtifact: artifactRef });
    return;
  }

  die(`Unknown subcommand: ${subcommand}. Try --help.`);
}

main().catch((err) => {
  die(`${(err as Error).message}\n${pc.dim((err as Error).stack ?? '')}`);
});
