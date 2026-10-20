// routes-file.smoke.mjs — a routes file that exists but cannot be parsed stops server.mjs instead of starting it with zero
// governed routes (an unparseable file used to read as "no routes file", so every request passed through ungoverned). Only a MISSING file means "nothing governed".
//
//   node routes-file.smoke.mjs
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServiceIdentity } from './service-identity.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const dir = mkdtempSync(join(tmpdir(), 'gw-routes-'));
const { serviceDid, serviceKey } = createServiceIdentity();
const ROUTE = [{ method: 'POST', path: '/perform', action: 'records-update', valueFields: [], allowedFields: [] }];

/** Start server.mjs on a routes file; resolve with how it ended: `listening` (then killed) or `exited` with its output. */
function start(routesPath) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [join(here, 'server.mjs')], {
      env: { ...process.env, PORT: '0', AGENTSAFE_ROUTES: routesPath, AGENTSAFE_ALLOWED_AGENTS: 'any', SERVICE_DID: serviceDid, SERVICE_KEY: serviceKey, MAGP_API: 'http://127.0.0.1:9/api/v1', AGENTSAFE_UPSTREAM: 'http://127.0.0.1:9' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    const onData = (d) => {
      out += d;
      if (out.includes('interception gateway on')) { child.kill(); resolve({ outcome: 'listening', out }); }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('exit', (code) => resolve({ outcome: 'exited', code, out }));
    setTimeout(() => { child.kill(); resolve({ outcome: 'timeout', out }); }, 15000).unref();
  });
}

let failed = 0;
async function check(label, fn) {
  try { await fn(); console.log(`ok    ${label}`); } catch (e) { failed++; console.log(`FAIL  ${label}\n      ${e.message}`); }
}

try {
  await check('an unparseable routes file stops the gateway, naming the file', async () => {
    const p = join(dir, 'broken.json');
    writeFileSync(p, '[{ "method": "POST", "path": "/perform", ');
    const r = await start(p);
    assert.equal(r.outcome, 'exited', r.out);
    assert.notEqual(r.code, 0);
    assert.match(r.out, /not valid JSON/);
  });

  await check('a routes file that is not an array stops the gateway', async () => {
    const p = join(dir, 'object.json');
    writeFileSync(p, JSON.stringify({ routes: ROUTE }));
    const r = await start(p);
    assert.equal(r.outcome, 'exited', r.out);
    assert.match(r.out, /must be a JSON array/);
  });

  await check('a routes file with a UTF-8 BOM is read', async () => {
    const p = join(dir, 'bom.json');
    writeFileSync(p, '\uFEFF' + JSON.stringify(ROUTE));
    const r = await start(p);
    assert.equal(r.outcome, 'listening', r.out);
    assert.match(r.out, /1 protected route/);
  });

  await check('a missing routes file still starts a pass-through proxy, with the warning', async () => {
    const r = await start(join(dir, 'absent.json'));
    assert.equal(r.outcome, 'listening', r.out);
    assert.match(r.out, /no routes file/);
  });
} finally {
  rmSync(dir, { recursive: true, force: true });
}

if (failed) { console.log(`\n${failed} failing`); process.exit(1); }
console.log('\nPASS — an unreadable routes file never starts an ungoverned gateway.');
