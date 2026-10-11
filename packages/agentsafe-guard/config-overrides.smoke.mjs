// config-overrides.smoke.mjs — the config loader's two pre-beta findings (independent eval 2026-10-11):
//   L5  createGuardFromConfig(path, { apiBase }) silently ignored apiBase and kept calling the file's apiBase
//       (production), so a developer pointing at staging or a local gate hit production instead.
//   L6  an agent.metamynd.json saved with a UTF-8 BOM (Notepad, other Windows tools) failed as "not valid JSON".
//
//   node config-overrides.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createGuardFromConfig, createGuard } from './agentsafe-guard.mjs';

const dir = mkdtempSync(join(tmpdir(), 'agentsafe-config-overrides-'));
let failed = 0;
async function check(name, fn) {
  try { await fn(); console.log(`  PASS  ${name}`); }
  catch (e) { failed++; console.log(`  FAIL  ${name}\n        ${e.message}`); }
}

const FILE_API = 'https://production.example.test/api/v1';
const CONFIG = { apiBase: FILE_API, agentDid: 'did:hedera:testnet:zX_0.0.1', agentKey: '302e020100300506032b657004220420' + '11'.repeat(32) };

/** The URL the guard's next remote authorize() is sent to (fetch is stubbed — nothing leaves the process). */
async function authorizeUrl(guard) {
  const realFetch = globalThis.fetch;
  let url = null;
  globalThis.fetch = async (u) => { url = String(u); return new Response(JSON.stringify({ data: { decision: 'block', reasonCode: 'STUB' } }), { status: 200 }); };
  try { await guard.authorize({ action: 'search-flights', amount: 0 }); } finally { globalThis.fetch = realFetch; }
  assert.ok(url, 'authorize() made a request');
  return url;
}

try {
  const path = join(dir, 'agent.metamynd.json');
  writeFileSync(path, JSON.stringify(CONFIG));

  await check('L5: with no override the guard calls the config file\'s apiBase (no regression)', async () => {
    const url = await authorizeUrl(await createGuardFromConfig(path, { mode: 'remote' }));
    assert.ok(url.startsWith(FILE_API + '/'), url);
  });

  await check('L5: createGuardFromConfig(path, { apiBase }) calls the override, not the file\'s apiBase', async () => {
    const url = await authorizeUrl(await createGuardFromConfig(path, { mode: 'remote', apiBase: 'http://127.0.0.1:9/api/v1' }));
    assert.ok(url.startsWith('http://127.0.0.1:9/api/v1/'), url);
  });

  await check('L5: the { api } alias still overrides too, and wins when both are given', async () => {
    const url = await authorizeUrl(await createGuardFromConfig(path, { mode: 'remote', api: 'http://localhost:9926/api/v1' }));
    assert.ok(url.startsWith('http://localhost:9926/api/v1/'), url);
    const both = await authorizeUrl(await createGuardFromConfig(path, { mode: 'remote', api: 'http://a.test/api/v1', apiBase: 'http://b.test/api/v1' }));
    assert.ok(both.startsWith('http://a.test/api/v1/'), both);
  });

  await check('L5: createGuard({ configPath, apiBase }) honours the override as well', async () => {
    const url = await authorizeUrl(createGuard({ configPath: path, mode: 'remote', apiBase: 'http://127.0.0.1:9/api/v1' }));
    assert.ok(url.startsWith('http://127.0.0.1:9/api/v1/'), url);
  });

  await check('L6: a config file that starts with a UTF-8 BOM loads', async () => {
    const bom = join(dir, 'bom.json');
    writeFileSync(bom, '\uFEFF' + JSON.stringify(CONFIG, null, 2), 'utf8');
    const url = await authorizeUrl(await createGuardFromConfig(bom, { mode: 'remote' }));
    assert.ok(url.startsWith(FILE_API + '/'), url);
    const g = createGuard({ configPath: bom });
    assert.equal(g.agentDid, CONFIG.agentDid);
  });

  await check('L6: a BOM in the middle of the file is still invalid JSON (only the leading mark is stripped)', async () => {
    const mid = join(dir, 'mid.json');
    writeFileSync(mid, '{\uFEFF"agentDid": "x"}', 'utf8');
    let err;
    try { await createGuardFromConfig(mid); } catch (e) { err = e; }
    assert.ok(err, 'rejected');
    assert.match(err.message, /is not valid JSON/);
  });
} finally {
  rmSync(dir, { recursive: true, force: true });
}

if (failed) { console.log(`\nFAIL — ${failed} case(s) failed`); process.exit(1); }
console.log('\nPASS — config-overrides smoke');
