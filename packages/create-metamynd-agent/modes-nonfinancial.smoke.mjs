// modes-nonfinancial.smoke.mjs — `--non-financial` in --sandbox, --request and --claim, run through the REAL CLI.
//
// Each mode used to refuse the flag (they still generated a payment demo). They now honour it, and the point of
// this test is the part that is easy to get wrong: what happens when the SERVER cannot. An older server ignores a
// field it does not know, and for these modes "ignored" means "issued spend authority nobody asked for" - a $10,000
// / $1,000 mandate, or a shared payment agent. The CLI must notice and stop, not scaffold a payment-free project on
// top of it.
//
// The CLI is spawned as a child (black box: real argument parsing, real HTTP) against a stand-in server that can
// behave like a current server or an old one.
//
//   node modes-nonfinancial.smoke.mjs   -> PASS when every case matches.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, 'index.mjs');
const strip = (t) => t.replace(/\x1b\[[0-9;]*m/g, '');
const FINANCIAL_LEAK = /flight|bookflight|book-flight|pnr|\busd\b|per-transaction|spend cap|payAmount|cumulativeSpend|amount-unknown|AIRLINE/i;

let failed = 0;
async function check(name, fn) {
  try { await fn(); console.log(`ok    ${name}`); }
  catch (e) { failed++; console.log(`FAIL  ${name}\n      ${e.message}`); }
}

// ---- a stand-in server: current or old ----
const DID = 'did:hedera:testnet:zStandIn_0.0.1';
const KEY = 'a'.repeat(64);
let modern = true; // false = a server that predates non-financial sandbox/requests (it ignores the new field)
let claimConfig = null; // what GET .../claim returns as the approved config
const seen = { sandbox: [], requests: [], claims: 0 };

const baseConfig = (scope) => ({ apiBase: '', agentDid: DID, agentKey: KEY, identityId: 'stand-in', keyVerified: true, mandate: { scope, policyId: null }, standards: [], bundleUrl: `x/policy/bundle/${DID}` });

const server = http.createServer((req, res) => {
  res.setHeader('content-type', 'application/json');
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    let body = {};
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { /* not JSON */ }
    if (req.method === 'POST' && req.url === '/api/v1/auth/login') return res.end(JSON.stringify({ success: true, data: { accessToken: 'tok' } }));
    if (req.method === 'POST' && req.url === '/api/v1/onboarding/sandbox') {
      seen.sandbox.push(body);
      if (modern && body.financial === false) {
        return res.end(JSON.stringify({ success: true, data: { ...baseConfig('perform-action'), financial: false, sandbox: true, merchants: [] } }));
      }
      // The shared PAYMENT agent - what an old server returns whatever was asked, and what a financial caller wants.
      return res.end(JSON.stringify({ success: true, data: { ...baseConfig('flight-purchase'), ...(modern ? { financial: true } : {}), sandbox: true, tier: 'conservative', maxAmount: 5000, perTxnMax: 500, merchants: ['skyward-air'] } }));
    }
    if (req.method === 'POST' && req.url === '/api/v1/onboarding/requests') {
      seen.requests.push(body);
      return res.end(JSON.stringify({ success: true, data: { requestId: 'req-42', claimToken: 'claim-tok', status: 'pending', ownerEmail: body.ownerEmail, ...(modern ? { financial: body.financial !== false } : {}) } }));
    }
    if (req.method === 'GET' && /^\/api\/v1\/onboarding\/requests\/[^/]+\/claim$/.test(req.url)) {
      seen.claims++;
      return res.end(JSON.stringify({ success: true, data: { status: 'approved', config: claimConfig } }));
    }
    res.statusCode = 404;
    res.end(JSON.stringify({ success: false, message: `stand-in: no route ${req.method} ${req.url}` }));
  });
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const API = `http://127.0.0.1:${server.address().port}/api/v1`;

const workdir = mkdtempSync(join(tmpdir(), 'metamynd-modes-nf-'));
// Belt and braces: EVERY child CLI runs with fetch() unable to reach anything but loopback. The default API is
// production, and an earlier version of this test reached it by accident; now even a regression that ignores --api or
// METAMYND_API fails the test (a blocked fetch) instead of touching a real server.
const BLOCKER = join(workdir, 'block-remote-fetch.cjs');
writeFileSync(BLOCKER, [
  "const real = globalThis.fetch;",
  "globalThis.fetch = (u, ...rest) => {",
  "  const host = new URL(String(u?.url ?? u)).hostname;",
  "  if (host !== '127.0.0.1' && host !== 'localhost') throw new Error('BLOCKED: this test may only reach the stand-in server, not ' + host);",
  "  return real(u, ...rest);",
  "};",
].join('\n'));
let n = 0;
const fresh = () => { const d = join(workdir, `case-${++n}`); mkdirSync(d, { recursive: true }); return d; };

/** Spawn the real CLI without blocking the event loop (the stand-in server lives in THIS process). */
function cli(args, { cwd = workdir, timeout = 60000, envOnly = false } = {}) {
  return new Promise((resolvePromise) => {
    const env = { ...process.env, CREATE_METAMYND_AGENT_NO_MAIN: '', METAMYND_API: API, METAMYND_EMAIL: '', METAMYND_PASSWORD: '', NODE_OPTIONS: `--require ${JSON.stringify(BLOCKER)}` };
    // ALWAYS name the stand-in explicitly. The default API is production; an earlier version of this test relied on
    // METAMYND_API and --claim did not read it, so a few cases reached the real server. Never again: refuse to run
    // anything that does not carry --api.
    // `envOnly` is the one exception: it proves METAMYND_API is honoured with no --api, and is safe only because of
    // the fetch blocker above.
    const withApi = envOnly || args.includes('--api') ? args : ['--api', API, ...args];
    assert.ok(envOnly || withApi.includes(API), 'every CLI call in this test must target the stand-in server');
    const child = spawn(process.execPath, [CLI, ...withApi], { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { out += d; });
    const timer = setTimeout(() => child.kill(), timeout);
    child.on('close', (code) => { clearTimeout(timer); resolvePromise({ code, out: strip(out) }); });
  });
}

const read = (dir, f) => readFileSync(join(dir, f), 'utf8');
function allText(dir) {
  let text = '';
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (name === 'node_modules') continue;
    text += statSync(p).isDirectory() ? allText(p) : `\n${readFileSync(p, 'utf8')}`;
  }
  return text;
}
/** The first payment-shaped word in the generated files, with its file and surrounding text, or null. */
function leak(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (name === 'node_modules' || name === 'agent.metamynd.json') continue;
    if (statSync(p).isDirectory()) { const inner = leak(p); if (inner) return inner; continue; }
    const text = readFileSync(p, 'utf8');
    // The neutral README SAYS "no spend cap and no payment demo" - the point of it. For prose, look for payment
    // CONTENT (a flight, a PNR, an airline); everything that is code or config gets the full check.
    const m = (name.endsWith('.md') ? /flight|bookflight|book-flight|pnr|airline/i : FINANCIAL_LEAK).exec(text);
    if (m) return `${name}: ...${text.slice(Math.max(0, m.index - 60), m.index + 60).replace(/\s+/g, ' ')}...`;
  }
  return null;
}
const auth = ['--email', 'dev@example.test', '--password', 'pw', '--yes'];

// ================================================================= --sandbox
await check('--sandbox --non-financial asks the server for the non-financial agent and scaffolds a payment-free project', async () => {
  modern = true; seen.sandbox.length = 0;
  const out = join(fresh(), 'proj');
  const r = await cli(['--sandbox', '--non-financial', '--yes', '--out', out]);
  assert.equal(r.code, 0, r.out);
  assert.deepEqual(seen.sandbox, [{ financial: false }]);
  assert.match(r.out, /non-financial sandbox agent/);
  assert.equal(JSON.parse(read(out, 'agent.metamynd.json')).financial, false);
  assert.equal(leak(out), null, 'the scaffold must not mention payments');
  assert.ok(existsSync(join(out, 'verify-context.json')), 'npm test needs the passing request context');
  assert.match(read(out, 'README.md'), /perform-action/);
});

await check('--sandbox (no flag) is unchanged: the shared payment agent, the payment demo, an empty request body', async () => {
  modern = true; seen.sandbox.length = 0;
  const out = join(fresh(), 'proj');
  const r = await cli(['--sandbox', '--yes', '--out', out]);
  assert.equal(r.code, 0, r.out);
  assert.deepEqual(seen.sandbox, [{}]);
  assert.match(allText(out), /flight/i);
});

await check('--sandbox --non-financial against a server that predates it STOPS, and writes nothing', async () => {
  modern = false; seen.sandbox.length = 0;
  const out = join(fresh(), 'proj');
  const r = await cli(['--sandbox', '--non-financial', '--yes', '--out', out]);
  assert.notEqual(r.code, 0);
  assert.match(r.out, /does not offer a non-financial sandbox agent yet/);
  assert.match(r.out, /--harness/, 'and it says where to go instead');
  assert.equal(existsSync(out), false, 'no project may be scaffolded on the payment agent');
});

await check('a --config file with no spend and no monetary rule makes --sandbox non-financial, as it does for --harness and the hosted flow', async () => {
  modern = true; seen.sandbox.length = 0;
  const dir = fresh();
  const cfg = join(dir, 'comms.json');
  writeFileSync(cfg, JSON.stringify({ name: 'Notice Bot', scope: 'send-customer-notice', rules: [{ name: 'Consent', when: { predicate: 'consent-missing' }, then: 'block', reasonCode: 'NO_CONSENT' }] }));
  const r = await cli(['--sandbox', '--config', cfg, '--yes', '--out', join(dir, 'proj')]);
  assert.equal(r.code, 0, r.out);
  assert.deepEqual(seen.sandbox, [{ financial: false }]);
  assert.match(r.out, /the rules in the config file are not applied to the shared sandbox agent/, 'it says its rules are the platform defaults');
});

await check('--sandbox --non-financial says when a config file scope is not used (the shared agent has a fixed scope)', async () => {
  modern = true;
  const dir = fresh(); const cfg = join(dir, 'c.json');
  writeFileSync(cfg, JSON.stringify({ name: 'x', scope: 'send-customer-notice' }));
  const r = await cli(['--sandbox', '--config', cfg, '--yes', '--out', join(dir, 'proj')]);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /the scope "send-customer-notice" in the config file is not used/);
});

await check('--sandbox --financial with a spend-free config still gets the payment agent', async () => {
  modern = true; seen.sandbox.length = 0;
  const dir = fresh();
  const cfg = join(dir, 'c.json');
  writeFileSync(cfg, JSON.stringify({ name: 'x', scope: 'send-customer-notice' }));
  const r = await cli(['--sandbox', '--financial', '--config', cfg, '--yes', '--out', join(dir, 'proj')]);
  assert.equal(r.code, 0, r.out);
  assert.deepEqual(seen.sandbox, [{}]);
});

// ================================================================= --request
await check('--request --non-financial asks the owner for NO spending authority: explicit flag, no perTxnMax, saved in the state file', async () => {
  modern = true; seen.requests.length = 0;
  const out = join(fresh(), 'out'); mkdirSync(out);
  const r = await cli(['--request', '--owner', 'owner@example.test', '--non-financial', ...auth, '--out', out]);
  assert.equal(r.code, 0, r.out);
  const [body] = seen.requests;
  assert.equal(body.financial, false);
  assert.ok(!('perTxnMax' in body) && !('maxAmount' in body) && !('currency' in body), `no spend field may be sent: ${JSON.stringify(body)}`);
  assert.equal(body.scope, 'perform-action');
  assert.match(r.out, /no spending authority requested/);
  const state = JSON.parse(read(out, 'metamynd-request.json'));
  assert.equal(state.financial, false);
  assert.ok(!('perTxnMax' in state));
});

await check('--request (no flag) is unchanged: perTxnMax 500 is sent and there is no `financial` key', async () => {
  modern = true; seen.requests.length = 0;
  const out = join(fresh(), 'out'); mkdirSync(out);
  const r = await cli(['--request', '--owner', 'owner@example.test', ...auth, '--out', out]);
  assert.equal(r.code, 0, r.out);
  const [body] = seen.requests;
  assert.equal(body.perTxnMax, 500);
  assert.ok(!('financial' in body));
  assert.equal(JSON.parse(read(out, 'metamynd-request.json')).financial, true);
});

await check('--request sends the other financial fields it was given (currency, maxAmount, merchants) - they used to be read and silently dropped', async () => {
  modern = true; seen.requests.length = 0;
  const dir = fresh(); const out = join(dir, 'out'); mkdirSync(out);
  const cfg = join(dir, 'pay.json');
  writeFileSync(cfg, JSON.stringify({ name: 'Pay Bot', scope: 'pay-invoice', currency: 'GBP', perTxnMax: 250, maxAmount: 20000, merchants: ['acme'] }));
  const r = await cli(['--request', '--owner', 'owner@example.test', '--config', cfg, ...auth, '--out', out]);
  assert.equal(r.code, 0, r.out);
  assert.deepEqual(seen.requests[0], { ownerEmail: 'owner@example.test', name: 'Pay Bot', scope: 'pay-invoice', perTxnMax: 250, maxAmount: 20000, currency: 'GBP', merchants: ['acme'] });
});

await check('--request records the currency it asked for in the claim file, so --claim can build the demo in it', async () => {
  modern = true; seen.requests.length = 0;
  const out = join(fresh(), 'out'); mkdirSync(out);
  const r = await cli(['--request', '--owner', 'owner@example.test', '--per-txn-max', '250', '--currency', 'GBP', ...auth, '--out', out]);
  assert.equal(r.code, 0, r.out);
  assert.equal(seen.requests[0].currency, 'GBP');
  const state = JSON.parse(read(out, 'metamynd-request.json'));
  assert.equal(state.currency, 'GBP');
  assert.equal(state.perTxnMax, 250);
});

await check('--request --non-financial --per-txn-max 900: the spend flag is IGNORED, out loud, and never sent', async () => {
  modern = true; seen.requests.length = 0;
  const out = join(fresh(), 'out'); mkdirSync(out);
  const r = await cli(['--request', '--owner', 'owner@example.test', '--non-financial', '--per-txn-max', '900', ...auth, '--out', out]);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /ignoring --per-txn-max/);
  assert.ok(!('perTxnMax' in seen.requests[0]));
});

await check('--request --non-financial against a server that predates it STOPS, names the request that now exists, and saves no claim file', async () => {
  modern = false; seen.requests.length = 0;
  const out = join(fresh(), 'out'); mkdirSync(out);
  const r = await cli(['--request', '--owner', 'owner@example.test', '--non-financial', ...auth, '--out', out]);
  assert.notEqual(r.code, 0);
  assert.match(r.out, /does not support non-financial requests yet/);
  assert.match(r.out, /req-42/, 'the developer must be told which request was filed');
  assert.match(r.out, /DENY/, 'and who can withdraw it');
  assert.equal(existsSync(join(out, 'metamynd-request.json')), false, 'a claim file for a request we must not build on');
});

await check('a --config file drives the request the same way: a spend-free policy is a non-financial request', async () => {
  modern = true; seen.requests.length = 0;
  const dir = fresh(); const out = join(dir, 'out'); mkdirSync(out);
  const cfg = join(dir, 'comms.json');
  writeFileSync(cfg, JSON.stringify({ name: 'Notice Bot', scope: 'send-customer-notice', rules: [{ name: 'Consent', when: { predicate: 'consent-missing' }, then: 'block', reasonCode: 'NO_CONSENT' }] }));
  const r = await cli(['--request', '--owner', 'owner@example.test', '--config', cfg, ...auth, '--out', out]);
  assert.equal(r.code, 0, r.out);
  assert.equal(seen.requests[0].financial, false);
  assert.equal(seen.requests[0].name, 'Notice Bot');
  assert.equal(seen.requests[0].scope, 'send-customer-notice');
  assert.match(r.out, /rules in the config file are not applied to a delegated request/);
});

// ================================================================= --claim
const claimArgs = (out) => ['--claim', '--request-id', 'req-42', '--token', 'claim-tok', '--yes', '--out', out];
const nonFinancialConfig = () => ({ ...baseConfig('perform-action'), financial: false });

await check('--claim of an approved NON-financial agent scaffolds a payment-free project', async () => {
  claimConfig = nonFinancialConfig();
  const out = join(fresh(), 'proj');
  const r = await cli([...claimArgs(out), '--non-financial']);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /the approved config has no spending authority/);
  assert.equal(leak(out), null);
  assert.ok(existsSync(join(out, 'verify-context.json')));
});

await check('--claim follows what was ISSUED even with no flag: an approved non-financial agent never gets a payment demo', async () => {
  claimConfig = nonFinancialConfig();
  const out = join(fresh(), 'proj');
  const r = await cli(claimArgs(out));
  assert.equal(r.code, 0, r.out);
  assert.equal(leak(out), null);
});

/** A mismatch found only AFTER the claim: the managed key was returned once and is gone from the server. */
function assertKeptNotScaffolded(r, out) {
  assert.notEqual(r.code, 0);
  assert.equal(existsSync(join(out, 'index.mjs')), false, 'nothing may be scaffolded');
  const kept = JSON.parse(read(out, 'agent.metamynd.json'));
  assert.equal(kept.agentKey, KEY, 'the one-time key that was returned must be kept, never discarded with the refusal');
  assert.match(r.out, /already APPROVED, so it cannot be denied/);
  assert.match(r.out, /Contain or rotate/);
  assert.doesNotMatch(r.out, /ask the owner to deny/i, 'an approved request cannot be denied: that advice cannot work');
}

await check('--claim --non-financial when the approved config does NOT say it is non-financial STOPS - and KEEPS the one-time key', async () => {
  claimConfig = baseConfig('perform-action'); // no `financial` field: not confirmed
  const out = join(fresh(), 'proj');
  const r = await cli([...claimArgs(out), '--non-financial']);
  assert.match(r.out, /does not say it is one/);
  assertKeptNotScaffolded(r, out);
});

await check('--claim of a request the state file marks non-financial, approved with spend authority, STOPS and keeps the key', async () => {
  claimConfig = { ...baseConfig('flight-purchase'), financial: true };
  const dir = fresh(); const out = join(dir, 'proj');
  writeFileSync(join(dir, 'metamynd-request.json'), JSON.stringify({ api: API, requestId: 'req-42', claimToken: 'claim-tok', byok: false, name: 'Notice Bot', scope: 'perform-action', financial: false }));
  const r = await cli(['--claim', '--request-file', join(dir, 'metamynd-request.json'), '--yes', '--out', out]);
  assert.match(r.out, /does not say it is one/);
  assertKeptNotScaffolded(r, out);
});

await check('--claim --financial on an approved non-financial agent STOPS and keeps the key: it would contradict what was issued', async () => {
  claimConfig = nonFinancialConfig();
  const out = join(fresh(), 'proj');
  const r = await cli([...claimArgs(out), '--financial']);
  assert.match(r.out, /NO spending authority/);
  assertKeptNotScaffolded(r, out);
});

await check('the kept config never overwrites an existing agent.metamynd.json', async () => {
  claimConfig = baseConfig('perform-action');
  const out = join(fresh(), 'proj'); mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'agent.metamynd.json'), '{"precious":true}');
  const r = await cli([...claimArgs(out), '--non-financial']);
  assert.notEqual(r.code, 0);
  assert.equal(read(out, 'agent.metamynd.json'), '{"precious":true}');
  assert.ok(readdirSync(out).some((f) => /^agent\.metamynd\.req-42.*\.json$/.test(f) || /^agent\.metamynd\.[^.]+\.json$/.test(f)), 'saved beside it under another name');
});

// What can be refused BEFORE the request that wipes the key must be. The stand-in counts claim GETs.
for (const [label, argv, state] of [
  ['--financial with a request file that says non-financial', ['--financial'], { financial: false }],
  ['--non-financial together with --financial', ['--non-financial', '--financial'], {}],
  ['--non-financial with a request file that records spend limits', ['--non-financial'], { financial: true }],
]) {
  await check(`--claim ${label} is refused BEFORE any request is made (so no key is ever consumed)`, async () => {
    claimConfig = nonFinancialConfig();
    const dir = fresh(); const out = join(dir, 'proj');
    const file = join(dir, 'metamynd-request.json');
    writeFileSync(file, JSON.stringify({ api: API, requestId: 'req-42', claimToken: 'claim-tok', byok: false, name: 'Notice Bot', scope: 'perform-action', ...state }));
    seen.claims = 0;
    const r = await cli(['--claim', '--request-file', file, '--yes', '--out', out, ...argv]);
    assert.notEqual(r.code, 0);
    assert.equal(seen.claims, 0, 'the claim endpoint must not have been called');
    assert.equal(existsSync(out), false);
  });
}

await check('--claim reads METAMYND_API like every other mode (with no --api flag and no state file)', async () => {
  claimConfig = nonFinancialConfig();
  const out = join(fresh(), 'proj');
  const r = await cli(['--claim', '--request-id', 'req-42', '--token', 'claim-tok', '--yes', '--out', out], { envOnly: true });
  assert.equal(r.code, 0, r.out);
  assert.doesNotMatch(r.out, /BLOCKED/);
});

await check('the blocker itself works: a CLI pointed at a non-local host cannot connect', async () => {
  const r = await cli(['--sandbox', '--non-financial', '--yes', '--api', 'https://example.invalid/api/v1', '--out', join(fresh(), 'proj')], { envOnly: true });
  assert.notEqual(r.code, 0);
  assert.match(r.out, /BLOCKED|Cannot reach/);
});

await check('--claim of an ordinary financial agent is unchanged', async () => {
  claimConfig = { ...baseConfig('flight-purchase'), financial: true };
  const out = join(fresh(), 'proj');
  const r = await cli(claimArgs(out));
  assert.equal(r.code, 0, r.out);
  assert.match(allText(out), /flight/i);
});

/** The currency the scaffolded demo's requests are made in: the gate refuses any other against a currency-scoped cap. */
const demoCurrencies = (dir) => [...new Set([...allText(dir).matchAll(/currency: '([A-Z]{3})'/g)].map((m) => m[1]))];

await check('--claim builds the demo in the currency the request was filed in (a USD demo against a GBP agent is blocked at step 1)', async () => {
  claimConfig = { ...baseConfig('pay-invoice'), financial: true };
  const dir = fresh(); const out = join(dir, 'proj');
  const file = join(dir, 'metamynd-request.json');
  writeFileSync(file, JSON.stringify({ api: API, requestId: 'req-42', claimToken: 'claim-tok', byok: false, name: 'Pay Bot', scope: 'pay-invoice', financial: true, perTxnMax: 250, currency: 'GBP' }));
  const r = await cli(['--claim', '--request-file', file, '--yes', '--out', out]);
  assert.equal(r.code, 0, r.out);
  assert.deepEqual(demoCurrencies(out), ['GBP']);
  assert.match(allText(out), /GBP 250/);
});

await check('--claim from a request file that recorded no currency (filed before it was recorded) is still USD', async () => {
  claimConfig = { ...baseConfig('pay-invoice'), financial: true };
  const dir = fresh(); const out = join(dir, 'proj');
  const file = join(dir, 'metamynd-request.json');
  writeFileSync(file, JSON.stringify({ api: API, requestId: 'req-42', claimToken: 'claim-tok', byok: false, name: 'Pay Bot', scope: 'pay-invoice', financial: true, perTxnMax: 250 }));
  const r = await cli(['--claim', '--request-file', file, '--yes', '--out', out]);
  assert.equal(r.code, 0, r.out);
  assert.deepEqual(demoCurrencies(out), ['USD']);
});

server.close();
if (failed) { console.log(`\n${failed} check(s) FAILED`); process.exit(1); }
console.log('\nPASS — --non-financial is honoured in --sandbox, --request and --claim, and refused loudly when the server cannot');
