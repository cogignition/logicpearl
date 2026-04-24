import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, cp, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { clearCache, loadFromPathOrUrl } from '../dist/load.js';

const ARTIFACT_DIR = resolve(
  process.cwd(),
  'artifacts',
  'refund-eligibility-v1',
);

test('loadFromPathOrUrl loads file URLs with spaces in the path', async () => {
  clearCache();
  const tempDir = await mkdtemp(join(tmpdir(), 'logicpearl-mcp-'));
  const targetDir = join(tempDir, 'artifact with space');
  await cp(ARTIFACT_DIR, targetDir, { recursive: true });

  const artifact = await loadFromPathOrUrl(
    pathToFileURL(join(targetDir, 'artifact.json')).href,
  );

  assert.equal(artifact.inspect().decisionKind, 'action');
  assert.equal(artifact.manifest.artifact_id, 'refund_eligibility_v1');
});

test('loadFromPathOrUrl evicts rejected cache entries', async () => {
  clearCache();
  const tempDir = await mkdtemp(join(tmpdir(), 'logicpearl-mcp-cache-'));
  const targetDir = join(tempDir, 'artifact');
  const artifactRef = join(targetDir, 'artifact.json');

  await assert.rejects(() => loadFromPathOrUrl(artifactRef));

  await mkdir(targetDir, { recursive: true });
  await cp(ARTIFACT_DIR, targetDir, { recursive: true });

  const artifact = await loadFromPathOrUrl(artifactRef);
  assert.equal(artifact.manifest.artifact_id, 'refund_eligibility_v1');
});
