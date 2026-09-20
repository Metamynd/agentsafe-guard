// missing-config.smoke.mjs — proves a fresh clone (which never contains the gitignored
// agent.metamynd.json) gets the NEXT STEP, not a bare ENOENT (beta regression 2026-09-20, BR-004).
//
//   node missing-config.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createGuardFromConfig, createGuard } from './agentsafe-guard.mjs';

const dir = mkdtempSync(join(tmpdir(), 'agentsafe-missing-config-'));
let failed = 0;
async function check(name, fn) {
  try { await fn(); console.log(`  PASS  ${name}`); }
  catch (e) { failed++; console.log(`  FAIL  ${name}\n        ${e.message}`); }
}
const rejects = async (p) => { try { await p; } catch (e) { return e; } throw new Error('expected a rejection'); };

try {
  const missing = join(dir, 'agent.metamynd.json');

  await check('createGuardFromConfig: missing file names the resolved path and every way to get one', async () => {
    const e = await rejects(createGuardFromConfig(missing));
    assert.match(e.message, /no agent config at/);
    assert.ok(e.message.includes(missing), 'shows the absolute path it looked at');
    assert.match(e.message, /npx create-metamynd-agent/);
    assert.match(e.message, /download its configuration/);
    assert.match(e.message, /gitignored/, 'explains WHY a fresh clone lacks it');
    assert.match(e.message, /metamynd\.ai\/developers\/quickstart/);
    assert.doesNotMatch(e.message, /ENOENT/, 'no bare ENOENT');
  });

  await check('createGuard({ configPath }): same actionable message', async () => {
    let err;
    try { createGuard({ configPath: missing }); } catch (e) { err = e; }
    assert.ok(err, 'threw');
    assert.match(err.message, /createGuard: no agent config at/);
    assert.match(err.message, /npx create-metamynd-agent/);
  });

  await check('a config that exists but is not JSON says so and does not suggest a re-scaffold', async () => {
    const bad = join(dir, 'broken.json');
    writeFileSync(bad, '{ "agentDid": ');
    const e = await rejects(createGuardFromConfig(bad));
    assert.match(e.message, /is not valid JSON/);
    assert.match(e.message, /Re-download/);
    assert.doesNotMatch(e.message, /no agent config at/);
  });

  await check('a present, valid config still loads (no regression)', async () => {
    const ok = join(dir, 'ok.json');
    writeFileSync(ok, JSON.stringify({ apiBase: 'https://example.test/api/v1', agentDid: 'did:hedera:testnet:zX_0.0.1', agentKey: '302e020100300506032b657004220420' + '11'.repeat(32) }));
    const g = await createGuardFromConfig(ok);
    assert.ok(g && typeof g.guardTool === 'function');
  });
} finally {
  rmSync(dir, { recursive: true, force: true });
}

if (failed) { console.log(`\nFAIL — ${failed} case(s) failed`); process.exit(1); }
console.log('\nPASS — missing-config smoke');
