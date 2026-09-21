// harness-gateway-bind.smoke.mjs — the scaffolded `--harness --gateway` process is run for real and
// attacked. It exists because the previous template ran the tool with whatever `args` the agent sent,
// NOT the values the agent signed: a request signed for $250 to an approved merchant executed as $5,000
// to another one (HTTP 200, the tool ran). The generated gateway now contains no enforcement logic of
// its own — it is @metamynd/agentsafe-http-gateway, the same component the hosted scaffold uses.
//
// What this proves, against the generated file exactly as a user gets it:
//   - an honest request runs the tool;
//   - signed 250 / body 5000 to a different merchant is refused before the tool runs;
//   - an extra body key (`surcharge`), a missing or string-typed amount, and the OLD `{ signed, args }`
//     body with no signature header are all refused before the tool runs;
//   - the real policy still decides (cap, ungranted action), and an unknown route is refused;
//   - the non-financial gateway refuses ANY body key.
//
//   node harness-gateway-bind.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createGuard } from '../agentsafe-guard/agentsafe-guard.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const INTEGRATIONS = resolve(HERE, '..');

let failed = 0;
async function check(name, fn) {
  try { await fn(); console.log(`ok    ${name}`); } catch (e) { failed++; console.log(`FAIL  ${name}\n      ${e.message}`); }
}

function link(dir, pkg, target) {
  const nm = join(dir, 'node_modules', '@metamynd');
  mkdirSync(nm, { recursive: true });
  if (!existsSync(join(nm, pkg))) symlinkSync(target, join(nm, pkg), 'junction');
}

async function freePort() {
  const probe = net.createServer();
  await new Promise((r) => probe.listen(0, '127.0.0.1', r));
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));
  return port;
}

/** Scaffold `--harness --gateway`, link the real packages, start the generated gateway. */
async function startGateway(label, extraArgs) {
  const outDir = mkdtempSync(join(tmpdir(), `metamynd-harness-bind-${label}-`));
  execFileSync(process.execPath, [
    process.env.SCAFFOLDER_UNDER_TEST ?? join(HERE, 'index.mjs'), '--harness', '--gateway', '--yes', '--name', 'Bind Test', '--scope', 'flight-purchase',
    '--per-txn-max', '500', '--out', outDir, ...extraArgs,
  ], { stdio: 'pipe' });
  const gwDir = join(outDir, 'harness-gateway');
  link(gwDir, 'agentsafe-mcp-guard', join(INTEGRATIONS, 'agentsafe-mcp-guard'));
  link(gwDir, 'agentsafe-http-gateway', join(INTEGRATIONS, 'agentsafe-http-gateway'));
  const port = await freePort();
  const child = spawn(process.execPath, ['harness-gateway.mjs'], { cwd: gwDir, env: { ...process.env, PORT: String(port) }, stdio: ['ignore', 'pipe', 'pipe'] });
  const state = { log: '' };
  child.stdout.on('data', (d) => { state.log += d; });
  child.stderr.on('data', (d) => { state.log += d; });
  const deadline = Date.now() + 15000;
  while (!/listening on/.test(state.log) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
  assert.match(state.log, /listening on/, 'generated gateway did not start:\n' + state.log);
  const cfg = JSON.parse(readFileSync(join(outDir, 'agent.metamynd.json'), 'utf8'));
  const guard = createGuard({ api: 'local', agentDid: cfg.agentDid, agentKey: cfg.agentKey });
  const url = `http://127.0.0.1:${port}`;
  const toolRuns = () => (state.log.match(/ALLOW \//g) ?? []).length;
  const sign = (o) => guard.buildSignedRequest({ context: { tool: 'flight-purchase', riskLevel: 'low' }, ...o });
  const post = async (path, { header, body }) => {
    const headers = { 'content-type': 'application/json' };
    if (header) headers['x-magp-request'] = JSON.stringify(header);
    const r = await fetch(url + path, { method: 'POST', headers, body: typeof body === 'string' ? body : JSON.stringify(body ?? {}) });
    return { status: r.status, body: await r.json().catch(() => null) };
  };
  return { outDir, child, state, sign, post, toolRuns, stop: async () => {
    // Wait for THIS child's exit first: on Windows the killed process still holds its cwd, and deleting the
    // directory under it fails with EPERM. Cleanup of a temp dir is best-effort and must never fail the test.
    if (child.exitCode === null) await new Promise((r) => { child.once('exit', r); child.kill(); });
    try { rmSync(outDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch { /* left in the OS temp dir */ }
  } };
}

const good = { action: 'flight-purchase', amount: 250, currency: 'USD', merchant: 'skyward-air' };

const fin = await startGateway('fin', []);
try {
  await check('the generated gateway contains no enforcement logic of its own (route.run is never handed unchecked args)', async () => {
    const src = readFileSync(join(fin.outDir, 'harness-gateway', 'harness-gateway.mjs'), 'utf8');
    assert.match(src, /createHttpGateway/);
    assert.doesNotMatch(src, /const \{ signed, args \} = JSON\.parse/, 'the old unbound `{ signed, args }` body is gone');
    assert.match(src, /allowedFields: \['amount', 'currency', 'merchant'\]/);
  });

  await check('an honest request runs the tool once', async () => {
    const before = fin.toolRuns();
    const r = await fin.post('/book-flight', { header: await fin.sign(good), body: { amount: 250, currency: 'USD', merchant: 'skyward-air' } });
    assert.equal(r.status, 200); assert.equal(r.body.pnr, 'PNR-DEMO');
    assert.equal(fin.toolRuns(), before + 1);
  });

  await check('THE FINDING: signed $250 / skyward-air, body $5,000 / attacker-llc is refused and the tool never runs', async () => {
    const before = fin.toolRuns();
    const r = await fin.post('/book-flight', { header: await fin.sign(good), body: { amount: 5000, currency: 'USD', merchant: 'attacker-llc' } });
    assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND');
    assert.equal(fin.toolRuns(), before, 'the tool must not have run');
  });

  await check('a body that changes only the amount, or only the merchant, is refused', async () => {
    const before = fin.toolRuns();
    let r = await fin.post('/book-flight', { header: await fin.sign(good), body: { amount: 5000, currency: 'USD', merchant: 'skyward-air' } });
    assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND'); assert.equal(r.body.field, 'amount');
    r = await fin.post('/book-flight', { header: await fin.sign(good), body: { amount: 250, currency: 'USD', merchant: 'attacker-llc' } });
    assert.equal(r.body.reasonCode, 'PAYLOAD_NOT_BOUND'); assert.equal(r.body.field, 'merchant');
    assert.equal(fin.toolRuns(), before);
  });

  await check('an extra body key (surcharge) the signature does not cover is refused', async () => {
    const before = fin.toolRuns();
    const r = await fin.post('/book-flight', { header: await fin.sign(good), body: { amount: 250, currency: 'USD', merchant: 'skyward-air', surcharge: 4750 } });
    assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
    assert.equal(fin.toolRuns(), before);
  });

  await check('a missing amount, a string amount, and a nested amount are each refused', async () => {
    const before = fin.toolRuns();
    for (const body of [{ merchant: 'skyward-air' }, { amount: '250', merchant: 'skyward-air' }, { merchant: 'skyward-air', booking: { amount: 5000 } }]) {
      const r = await fin.post('/book-flight', { header: await fin.sign(good), body });
      assert.equal(r.status, 403, JSON.stringify(body)); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE', JSON.stringify(body));
    }
    assert.equal(fin.toolRuns(), before);
  });

  await check('the OLD body shape ({ signed, args }, no signature header) is refused: nothing signed authorises it', async () => {
    const before = fin.toolRuns();
    const signed = await fin.sign(good);
    const r = await fin.post('/book-flight', { body: { signed, args: { amount: 5000, merchant: 'attacker-llc' } } });
    assert.equal(r.status, 401); assert.equal(r.body.reasonCode, 'MISSING_GOVERNANCE');
    assert.equal(fin.toolRuns(), before);
  });

  await check('the real policy still decides: over the cap, and an action the mandate never granted', async () => {
    const before = fin.toolRuns();
    let r = await fin.post('/book-flight', { header: await fin.sign({ ...good, amount: 600 }), body: { amount: 600, currency: 'USD', merchant: 'skyward-air' } });
    assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'SOP_SPEND_CAP');
    r = await fin.post('/raise-limit', { header: await fin.sign({ ...good, action: 'permissions.update' }), body: {} });
    assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'NO_PERMISSION_FOR_ACTION');
    assert.equal(fin.toolRuns(), before);
  });

  await check('an unknown route is refused (deny-by-default), and a path variant cannot reach a governed tool ungoverned', async () => {
    const before = fin.toolRuns();
    let r = await fin.post('/wire-funds', { header: await fin.sign(good), body: { amount: 250 } });
    assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'ROUTE_NOT_ALLOWED');
    r = await fin.post('/book-flight/../raise-limit', { header: await fin.sign(good), body: {} });
    assert.equal(r.status, 403);
    assert.equal(fin.toolRuns(), before);
  });
} finally {
  await fin.stop();
}

const nf = await startGateway('nf', ['--non-financial']);
try {
  await check('non-financial: the tool reads nothing from the body, so an empty body runs and ANY key is refused', async () => {
    const base = { action: 'flight-purchase', context: { tool: 'flight-purchase', riskLevel: 'low' } };
    // (the scope is the mandate's scope; a neutral scaffold signs no amount or merchant)
    const before = nf.toolRuns();
    let r = await nf.post('/perform', { header: await nf.sign(base), body: {} });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(nf.toolRuns(), before + 1);
    r = await nf.post('/perform', { header: await nf.sign(base), body: { recipient: 'someone-else' } });
    assert.equal(r.status, 403); assert.equal(r.body.reasonCode, 'PAYLOAD_UNBINDABLE');
    assert.equal(nf.toolRuns(), before + 1, 'the refused request must not have run the tool');
  });
} finally {
  await nf.stop();
}

// The HOSTED financial scaffold needs a live login to run, so it is checked structurally: both halves must
// agree on the body (the agent sends ONLY the tool's fields; the gateway names exactly those), because the
// default allowlist would otherwise refuse the generated agent's own request.
await check('hosted financial scaffold: agent body and gateway allowedFields agree, and riskLevel stays out of the tool body', async () => {
  process.env.CREATE_METAMYND_AGENT_NO_MAIN = '1';
  const { scaffoldProject } = await import('./index.mjs');
  const out = mkdtempSync(join(tmpdir(), 'metamynd-hosted-fin-'));
  const realLog = console.log; console.log = () => {};
  try {
    scaffoldProject({ outDir: out, config: { apiBase: 'http://127.0.0.1:1', agentDid: 'did:key:zStub', agentKey: 'aa', identityId: 'stub', keyVerified: true, mandate: { scope: 'flight-purchase' } }, slug: 'fin', scope: 'flight-purchase', perTxnMax: 500, currency: 'USD', merchant: 'skyward-air', sandbox: false, withGateway: true });
  } finally { console.log = realLog; }
  const gw = readFileSync(join(out, 'gateway', 'server.mjs'), 'utf8');
  const agent = readFileSync(join(out, 'index.mjs'), 'utf8');
  assert.match(gw, /valueFields: \['amount', 'merchant'\], allowedFields: \['amount', 'currency', 'merchant'\]/);
  assert.match(agent, /body: JSON\.stringify\(\{ amount: args\.amount, merchant: args\.merchant, currency: /);
  assert.doesNotMatch(agent, /body: JSON\.stringify\(args\)/, 'the agent must not ship its whole argument object to the gateway');
  rmSync(out, { recursive: true, force: true });
});

if (failed) { console.log(`\n${failed} check(s) FAILED`); process.exit(1); }
console.log('\nPASS — the generated harness gateway binds executed arguments to the signed request, refuses unknown fields, and carries no enforcement logic of its own.');
