// owner-session.smoke.mjs — the hosted CLI survives an expired owner access token (pre-beta rerun 6, CLI login
// expiry follow-up to #926: an owner access token now lives 15 minutes; the refresh token renews it).
//
// A stand-in platform answers the endpoints the hosted CLI calls with an owner token (provisioning, verify-key,
// counterparty registration) with 401 for any token it has marked expired. The REAL CLI (main()) runs against it:
//  - an expired token is renewed once through POST /auth/refresh-token and the call is retried once;
//  - a refresh the platform refuses falls back to one fresh sign-in with the credentials given to this run;
//  - a 401 that survives the renewal is reported, not retried forever;
//  - the sign-in comes after everything that needs no token (here, the rule-pack lookup), and the password is
//    written nowhere.
//
//   node owner-session.smoke.mjs   → PASS when every case holds.
process.env.CREATE_METAMYND_AGENT_NO_MAIN = '1';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const { ownerLogin, ownerPost } = await import('./index.mjs');

let failed = 0;
async function check(name, fn) {
  try { await fn(); console.log(`ok    ${name}`); }
  catch (e) { failed++; console.log(`FAIL  ${name}\n      ${e.message}`); }
}
const strip = (t) => t.replace(/\x1b\[[0-9;]*m/g, '');

const PASSWORD = 'pw-never-written-3f9c';
const POLICY_KEY = 'ab'.repeat(32);
const AGENT_DID = 'did:key:z6MkStandInAgentForOwnerSessionSmoke';

// ---- the stand-in platform ----
let mode = 'refresh'; // 'refresh' | 'relogin' | 'dead' | 'fresh'
let seq = 0;
const live = new Set(); // access tokens the platform currently accepts
const calls = []; // [method path token] in order
const owned = (path) => path === '/api/v1/echo' || path === '/api/v1/onboarding/agent' || path === '/api/v1/onboarding/requests' || path.startsWith('/api/v1/policy/counterparties') || /\/verify-key$/.test(path);

const server = http.createServer((req, res) => {
  res.setHeader('content-type', 'application/json');
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    let body = {};
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { /* not JSON */ }
    const token = (req.headers.authorization ?? '').replace(/^Bearer /, '') || null;
    calls.push({ method: req.method, path: req.url, token, body });
    const send = (status, json) => { res.statusCode = status; res.end(JSON.stringify(json)); };

    if (req.method === 'GET' && req.url.startsWith('/api/v1/onboarding/rule-packs')) {
      if (req.url === '/api/v1/onboarding/rule-packs') return send(200, { data: [{ key: 'spend-basic', label: 'Spend guardrails', requiresSpend: true }] });
      return send(200, { data: { molecules: [{ id: 'cap', name: 'Per-transaction cap', combinator: 'any', atoms: [{ id: 'a', predicate: 'amount-over', config: { limit: 500 } }], decision: 'block', reasonCode: 'SOP_SPEND_CAP' }] } });
    }
    if (req.method === 'POST' && req.url === '/api/v1/auth/login') {
      if (body.password !== PASSWORD) return send(401, { message: 'Invalid credentials' });
      const at = `at-${++seq}`;
      // The FIRST sign-in of a run hands out a token that is already expired (as if the owner sat at the prompts),
      // except in 'fresh' mode. Any later sign-in hands out a live one — unless the platform is 'dead'.
      if (mode === 'fresh' || (seq > 1 && mode !== 'dead')) live.add(at);
      return send(200, { success: true, data: { accessToken: at, refreshToken: `rt-${seq}` } });
    }
    if (req.method === 'POST' && req.url === '/api/v1/auth/refresh-token') {
      if (mode !== 'refresh' || !/^rt-/.test(body.refreshToken ?? '')) return send(401, { message: 'Unauthorized' });
      const at = `at-refreshed-${++seq}`;
      live.add(at);
      return send(200, { accessToken: at, refreshToken: `rt-rotated-${seq}`, expiredAt: Date.now() + 900000 });
    }
    if (owned(req.url) && !live.has(token)) return send(401, { message: 'Unauthorized' });
    if (req.method === 'POST' && req.url === '/api/v1/onboarding/agent') {
      return send(200, { success: true, data: { apiBase: `http://127.0.0.1:${server.address().port}/api/v1`, agentDid: AGENT_DID, identityId: 'id-1', challenge: 'prove-me', ownerPrincipal: 'did:hedera:testnet:zStandInOwner_0.0.900', mandate: { scope: body.scope }, standards: [], issuer: { policyKey: POLICY_KEY } } });
    }
    if (req.method === 'POST' && /\/verify-key$/.test(req.url)) return send(200, { success: true, data: { verified: true } });
    if (req.method === 'POST' && req.url === '/api/v1/policy/counterparties/challenge') return send(200, { success: true, data: { message: 'challenge-text', challengeToken: 'ct-1' } });
    if (req.method === 'POST' && req.url === '/api/v1/policy/counterparties') return send(200, { success: true, message: 'registered' });
    if (req.method === 'POST' && req.url === '/api/v1/echo') return send(200, { success: true, data: { token } });
    send(404, { message: 'not modelled' });
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const API = `http://127.0.0.1:${server.address().port}/api/v1`;
const reset = (m) => { mode = m; seq = 0; live.clear(); calls.length = 0; };

function runNode(args, { cwd, env = {}, timeout = 60000 } = {}) {
  return new Promise((resolvePromise) => {
    const child = spawn(process.execPath, args, { cwd, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    const timer = setTimeout(() => { child.kill(); stderr += '\n[test] timed out'; }, timeout);
    child.on('close', (status) => { clearTimeout(timer); resolvePromise({ status, stdout: strip(stdout), stderr: strip(stderr) }); });
  });
}

const workdir = mkdtempSync(join(tmpdir(), 'metamynd-owner-session-'));
const cli = (out, extra = []) => runNode(
  [join(HERE, 'index.mjs'), '--yes', '--api', API, '--email', 'owner@example.test', '--password', PASSWORD, '--scope', 'flight-purchase', '--byok', '--out', out, ...extra],
  { cwd: workdir, env: { CREATE_METAMYND_AGENT_NO_MAIN: '' } },
);
const ownerCalls = () => calls.filter((x) => owned(x.path));
function filesUnder(dir) {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? (n === 'node_modules' ? [] : filesUnder(p)) : [p];
  });
}

try {
  await check('unit: ownerPost renews an expired token through the refresh token and retries the call once', async () => {
    reset('refresh');
    const session = await ownerLogin(API, 'owner@example.test', PASSWORD);
    assert.equal(session.token, 'at-1');
    const log = console.log;
    console.log = () => {};
    let res;
    try { res = await ownerPost(session, '/echo', {}); } finally { console.log = log; }
    assert.deepEqual(calls.filter((x) => x.path === '/api/v1/echo').map((x) => x.token), ['at-1', session.token], 'one call, one retry with the new token');
    assert.match(session.token, /^at-refreshed-/, 'the session carries the renewed access token');
    assert.match(session.refreshToken, /^rt-rotated-/, 'and the ROTATED refresh token');
    assert.equal(res?.data?.token, session.token);
  });

  await check('hosted CLI: an expired token at provisioning is refreshed once, and every owner call succeeds', async () => {
    reset('refresh');
    const out = join(workdir, 'refresh');
    const r = await cli(out);
    assert.equal(r.status, 0, 'exited ' + r.status + ':\n' + r.stdout + r.stderr);
    assert.match(r.stdout, /owner session had expired; renewed it and retried/);
    assert.equal(calls.filter((x) => x.path === '/api/v1/auth/refresh-token').length, 1, 'one refresh');
    assert.equal(calls.filter((x) => x.path === '/api/v1/auth/login').length, 1, 'no second sign-in was needed');
    const prov = calls.filter((x) => x.path === '/api/v1/onboarding/agent');
    assert.deepEqual(prov.map((x) => x.token), ['at-1', prov[1].token], 'provisioned on the retry');
    assert.match(prov[1].token, /^at-refreshed-/);
    // Every later owner call carries the renewed token (no second 401 round-trip).
    for (const x of ownerCalls().slice(2)) assert.match(x.token, /^at-refreshed-/, `${x.path} used the renewed token`);
    assert.ok(calls.some((x) => x.path === '/api/v1/policy/counterparties'), 'the gateway was registered with the renewed token');
    assert.ok(calls.some((x) => /\/verify-key$/.test(x.path)), 'the BYOK key was verified with the renewed token');
    assert.match(r.stdout, /key verified/);
    assert.doesNotMatch(r.stdout, /could not register the gateway/);
  });

  await check('hosted CLI: a refused refresh falls back to one fresh sign-in with the credentials given to this run', async () => {
    reset('relogin');
    const out = join(workdir, 'relogin');
    const r = await cli(out);
    assert.equal(r.status, 0, 'exited ' + r.status + ':\n' + r.stdout + r.stderr);
    assert.equal(calls.filter((x) => x.path === '/api/v1/auth/login').length, 2, 'the original sign-in plus one renewal');
    assert.deepEqual(calls.filter((x) => x.path === '/api/v1/onboarding/agent').map((x) => x.token), ['at-1', 'at-2']);
    // The password lives in memory only: nothing the CLI wrote carries it.
    for (const f of filesUnder(out)) assert.ok(!readFileSync(f, 'utf8').includes(PASSWORD), `${f} must not contain the password`);
  });

  await check('hosted CLI: a 401 that survives the renewal is reported, retried once only, and nothing is scaffolded', async () => {
    reset('dead');
    const out = join(workdir, 'dead');
    const r = await cli(out);
    assert.notEqual(r.status, 0);
    assert.match(r.stdout + r.stderr, /\/onboarding\/agent → HTTP 401/);
    assert.equal(calls.filter((x) => x.path === '/api/v1/onboarding/agent').length, 2, 'one call, one retry — never a loop');
    assert.ok(!existsSync(join(out, 'agent.metamynd.json')), 'nothing scaffolded');
  });

  await check('hosted CLI: a live token is used as-is (no refresh), and the sign-in comes after the token-free rule-pack lookup', async () => {
    reset('fresh');
    const policy = join(workdir, 'pack.json');
    writeFileSync(policy, JSON.stringify({ name: 'Pack Agent', scope: 'flight-purchase', rulePack: 'spend-basic' }));
    const r = await cli(join(workdir, 'fresh'), ['--config', policy, '--no-gateway']);
    assert.equal(r.status, 0, 'exited ' + r.status + ':\n' + r.stdout + r.stderr);
    assert.equal(calls.filter((x) => x.path === '/api/v1/auth/refresh-token').length, 0);
    assert.doesNotMatch(r.stdout, /renewed it and retried/);
    const order = calls.map((x) => x.path);
    const login = order.indexOf('/api/v1/auth/login');
    assert.ok(login > order.findIndex((p) => p.startsWith('/api/v1/onboarding/rule-packs')), `signed in after the rule-pack lookup: ${order.join(', ')}`);
    assert.equal(order[login + 1], '/api/v1/onboarding/agent', 'and provisioned straight after signing in');
  });

  await check('the generated gateway README says an owner token lasts 15 minutes and how to get a fresh one', () => {
    const readme = readFileSync(join(workdir, 'refresh', 'gateway', 'README.md'), 'utf8');
    assert.match(readme, /lasts \*\*15 minutes\*\*/);
    assert.match(readme, /POST \/auth\/login/);
    assert.match(readme, /data\.accessToken/);
  });
} finally {
  server.close();
  rmSync(workdir, { recursive: true, force: true });
}

if (failed) { console.error(`\n${failed} case(s) FAILED`); process.exit(1); }
console.log('\nPASS — an expired owner token is renewed once (refresh, else re-sign-in) and the call retried once.');
