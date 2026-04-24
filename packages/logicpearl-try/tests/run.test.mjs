import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, cp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { loadFromPathOrUrl, runEvaluate } from '../dist/run.js';

const ARTIFACT_REF = resolve(
  process.cwd(),
  'artifacts',
  'refund-eligibility-v1',
  'artifact.json',
);

const SAMPLE_FACTS = {
  days_since_purchase: 30,
  order_amount_usd: 119,
  customer_tenure_months: 11,
  previous_refunds_90d: 1,
  reason_category: 'changed_mind',
  item_is_digital: 0,
  item_used: 0,
  is_enterprise_customer: 0,
};

test('runEvaluate normalizes action artifact results', async () => {
  const result = await runEvaluate({
    artifactUrl: ARTIFACT_REF,
    facts: SAMPLE_FACTS,
  });

  assert.equal(result.decisionKind, 'action');
  assert.equal(result.verdict, 'DENY');
  assert.equal(result.allow, null);
  assert.equal(result.action, 'deny');
  assert.equal(result.defaultAction, 'approve');
  assert.equal(result.firedRules[0]?.id, 'rule_001');
  assert.equal(result.matchedRules[0]?.id, 'rule_001');
});

test('loadFromPathOrUrl accepts file URLs with spaces', async () => {
  const tempDir = await mkdtemp(join(tmpdir(), 'logicpearl-try-'));
  const targetDir = join(tempDir, 'artifact with space');
  await cp(resolve(process.cwd(), 'artifacts', 'refund-eligibility-v1'), targetDir, {
    recursive: true,
  });

  const artifact = await loadFromPathOrUrl(
    pathToFileURL(join(targetDir, 'artifact.json')).href,
  );

  assert.equal(artifact.inspect().decisionKind, 'action');
});
