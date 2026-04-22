import pc from 'picocolors';
import { readFile, writeFile, copyFile, mkdir, stat } from 'node:fs/promises';
import { homedir, platform } from 'node:os';
import { dirname, join } from 'node:path';

export interface InstallOptions {
  host?: string;
  dryRun: boolean;
  artifactRef: string;
}

interface HostTarget {
  id: 'claude-desktop' | 'cursor';
  label: string;
  configPath: string;
  mcpKey: string;
}

function resolveHosts(): HostTarget[] {
  const home = homedir();
  const plat = platform();
  const hosts: HostTarget[] = [];

  // Claude Desktop
  if (plat === 'darwin') {
    hosts.push({
      id: 'claude-desktop',
      label: 'Claude Desktop',
      configPath: join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
      mcpKey: 'mcpServers',
    });
  } else if (plat === 'win32') {
    const appdata = process.env.APPDATA ?? join(home, 'AppData', 'Roaming');
    hosts.push({
      id: 'claude-desktop',
      label: 'Claude Desktop',
      configPath: join(appdata, 'Claude', 'claude_desktop_config.json'),
      mcpKey: 'mcpServers',
    });
  } else {
    hosts.push({
      id: 'claude-desktop',
      label: 'Claude Desktop',
      configPath: join(home, '.config', 'Claude', 'claude_desktop_config.json'),
      mcpKey: 'mcpServers',
    });
  }

  // Cursor
  hosts.push({
    id: 'cursor',
    label: 'Cursor',
    configPath: join(home, '.cursor', 'mcp.json'),
    mcpKey: 'mcpServers',
  });

  return hosts;
}

async function fileExists(p: string): Promise<boolean> {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}

function timestamp(): string {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

async function applyToHost(target: HostTarget, opts: InstallOptions): Promise<boolean> {
  console.log(pc.bold(target.label) + pc.dim('  ' + target.configPath));

  let config: Record<string, unknown> = {};
  const exists = await fileExists(target.configPath);
  if (exists) {
    try {
      const raw = await readFile(target.configPath, 'utf-8');
      config = raw.trim() ? JSON.parse(raw) : {};
    } catch (err) {
      console.log(pc.red('  ✗ ') + 'Existing config is not valid JSON — skipping this host.');
      console.log(pc.dim('    ' + (err as Error).message));
      return false;
    }
  }

  const servers = (config[target.mcpKey] as Record<string, unknown> | undefined) ?? {};
  const existing = servers['logicpearl'];
  if (existing) {
    console.log(pc.yellow('  ⚠ ') + 'logicpearl entry already present — will overwrite with the latest config.');
  }

  const entry = {
    command: 'npx',
    args: ['-y', '@logicpearl/mcp', 'start'],
  };
  servers['logicpearl'] = entry;
  config[target.mcpKey] = servers;

  const serialized = JSON.stringify(config, null, 2) + '\n';

  if (opts.dryRun) {
    console.log(pc.dim('  (dry-run) would write:'));
    for (const line of serialized.split('\n')) {
      console.log(pc.dim('    ' + line));
    }
    return true;
  }

  await mkdir(dirname(target.configPath), { recursive: true });

  if (exists) {
    const backup = `${target.configPath}.${timestamp()}.bak`;
    await copyFile(target.configPath, backup);
    console.log(pc.dim('  · backup saved: ') + backup);
  }
  await writeFile(target.configPath, serialized, 'utf-8');
  console.log(pc.green('  ✓ ') + (existing ? 'updated' : 'added') + ' logicpearl entry');
  return true;
}

export async function runInstall(opts: InstallOptions): Promise<void> {
  const allHosts = resolveHosts();
  const selected = opts.host
    ? allHosts.filter((h) => h.id === opts.host || h.id.startsWith(opts.host!))
    : allHosts;

  if (selected.length === 0) {
    console.error(pc.red('✗ ') + `No MCP host matched "${opts.host}". Try one of: ${allHosts.map((h) => h.id).join(', ')}`);
    process.exit(1);
  }

  console.log(pc.bold(pc.cyan('LogicPearl MCP · install')));
  console.log();
  if (opts.dryRun) {
    console.log(pc.dim('Dry run — no files will be written.'));
    console.log();
  }

  let ok = 0;
  for (const host of selected) {
    const done = await applyToHost(host, opts);
    if (done) ok++;
    console.log();
  }

  console.log(pc.dim('─'.repeat(56)));
  console.log();
  if (ok === 0) {
    console.log(pc.red('✗ ') + 'No hosts were configured.');
    process.exit(1);
  }
  console.log(pc.green('✓ ') + `Configured ${ok} host${ok === 1 ? '' : 's'}.`);
  console.log();
  console.log(pc.bold('Next:'));
  console.log(pc.dim('  1. Quit and relaunch the host app so it picks up the new config.'));
  console.log(pc.dim('  2. In a chat, try: ') + pc.italic('"List the rules in the refund-eligibility artifact."'));
  console.log(pc.dim('  3. The host will call the ') + pc.cyan('logicpearl_list_rules') + pc.dim(' tool.'));
  console.log();
  console.log(pc.dim('Docs: ') + pc.cyan('https://logicpearl.com/developers/mcp'));
  console.log();
}
