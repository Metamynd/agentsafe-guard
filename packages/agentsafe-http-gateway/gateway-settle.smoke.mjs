// gateway-settle.smoke.mjs — the gateway closes the hold it claimed once the upstream has answered.
//
// The issuer treats a CLAIMED hold as a commitment (it stays against the mandate's cap until settled,
// and can be settled below its amount or voided only with the claim token from the successful claim).
// The gateway is the party that holds that token, so it captures a success, releases a rejection the
// operator has said is a guaranteed non-execution, and parks anything ambiguous as UNKNOWN — never
// guessing toward "free the budget".
//
//   node gateway-settle.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import { createHttpGateway } from './gateway.mjs';

const TOKEN = 'cd'.repeat(32);

/** A guard that "claims" like agentsafe-mcp-guard >= 0.7: the token rides non-enumerable on the verdict. */
function fakeGuard({ claim = true, helpers = true, throwIn } = {}) {
  const calls = [];
  const guard = {
    async verifyRequest(req) {
      const d = { decision: 'allow', reasonCode: 'AUTHORIZED' };
      if (claim) {
        Object.defineProperty(d, 'claimToken', { value: TOKEN, enumerable: false });
        Object.defineProperty(d, 'authorizationId', { value: req.authorizationId, enumerable: false });
      }
      return d;
    },
  };
  if (helpers) {
    const rec = (name) => async (arg) => { calls.push([name, arg]); if (throwIn === name) throw new Error(`${name} exploded`); return { ok: true }; };
    guard.captureAuthorization = rec('capture');
    guard.releaseAuthorization = rec('release');
    guard.markAuthorizationUnknown = rec('unknown');
  }
  return { guard, calls };
}

const signed = { agentDid: 'did:x', action: 'flight-purchase', amount: 250, currency: 'USD', merchant: 'skyward-air', authorizationId: 'auth-1' };
const route = (extra = {}) => ({ method: 'POST', path: '/book', action: 'flight-purchase', bind: false, extract: () => signed, ...extra });
const req = { method: 'POST', path: '/book', headers: {}, rawBody: Buffer.from('{}') };
const upstream = (status, body = { ok: status < 400 }) => async () => ({ status, body });
const make = (opts) => createHttpGateway({ routes: [route(opts.route)], forward: opts.forward, guard: opts.guard, ...(opts.gw ?? {}) });

const t = [];
const test = (name, fn) => t.push([name, fn]);

test('a 2xx is captured at the authorized amount, with the claim token', async () => {
  const { guard, calls } = fakeGuard();
  const res = await make({ guard, forward: upstream(200) })(req);
  assert.equal(res.status, 200);
  assert.deepEqual(calls, [['capture', { authorizationId: 'auth-1', claimToken: TOKEN, amountCharged: 250 }]]);
});

test('the caller-visible result never carries the token', async () => {
  const { guard } = fakeGuard();
  const res = await make({ guard, forward: upstream(200) })(req);
  assert.ok(!JSON.stringify(res).includes(TOKEN));
  assert.equal(res.governance.claimToken, TOKEN, 'the token is still readable by the operator code that needs it');
});

test('a rejection is parked UNKNOWN by default — the budget is NOT released', async () => {
  for (const status of [400, 404, 422, 500, 503]) {
    const { guard, calls } = fakeGuard();
    const res = await make({ guard, forward: upstream(status) })(req);
    assert.equal(res.status, status, 'the upstream response passes through untouched');
    assert.deepEqual(calls.map((c) => c[0]), ['unknown'], `HTTP ${status}`);
  }
});

test('releaseOnStatus opts specific statuses into RELEASE; everything else stays UNKNOWN', async () => {
  let f = fakeGuard();
  await make({ guard: f.guard, forward: upstream(422), gw: { releaseOnStatus: [400, 422] } })(req);
  assert.deepEqual(f.calls, [['release', { authorizationId: 'auth-1', claimToken: TOKEN, reason: 'UPSTREAM_HTTP_422' }]]);
  f = fakeGuard();
  await make({ guard: f.guard, forward: upstream(503), gw: { releaseOnStatus: [400, 422] } })(req);
  assert.deepEqual(f.calls.map((c) => c[0]), ['unknown']);
});

test('a route-level releaseOnStatus overrides the gateway-level one', async () => {
  let f = fakeGuard();
  await make({ guard: f.guard, forward: upstream(404), gw: { releaseOnStatus: [404] }, route: { releaseOnStatus: [] } })(req);
  assert.deepEqual(f.calls.map((c) => c[0]), ['unknown']);
  f = fakeGuard();
  await make({ guard: f.guard, forward: upstream(404), route: { releaseOnStatus: [404] } })(req);
  assert.deepEqual(f.calls.map((c) => c[0]), ['release']);
});

test('a forward() that throws parks the hold UNKNOWN (never released, even if the status list would) and rethrows', async () => {
  const { guard, calls } = fakeGuard();
  const gw = make({ guard, forward: async () => { throw new Error('socket hang up'); }, gw: { releaseOnStatus: [500] } });
  await assert.rejects(() => gw(req), /socket hang up/);
  assert.deepEqual(calls.map((c) => c[0]), ['unknown']);
});

test('settle:false restores the old behaviour: the hold is never touched', async () => {
  const { guard, calls } = fakeGuard();
  await make({ guard, forward: upstream(200), gw: { settle: false } })(req);
  assert.deepEqual(calls, []);
});

test('no claim (requireAuthorization off, or a value-less action) means nothing to close and no crash', async () => {
  const { guard, calls } = fakeGuard({ claim: false });
  const res = await make({ guard, forward: upstream(200) })(req);
  assert.equal(res.status, 200);
  assert.deepEqual(calls, []);
});

test('a guard that predates the settlement helpers keeps working', async () => {
  const { guard } = fakeGuard({ helpers: false });
  assert.equal((await make({ guard, forward: upstream(200) })(req)).status, 200);
  assert.equal((await make({ guard, forward: upstream(500) })(req)).status, 500);
});

test('a failing settlement call never changes the caller\'s response', async () => {
  for (const name of ['capture', 'unknown', 'release']) {
    const { guard } = fakeGuard({ throwIn: name });
    const status = name === 'capture' ? 200 : 422;
    const res = await make({ guard, forward: upstream(status), gw: { releaseOnStatus: [422] } })(req);
    assert.equal(res.status, status, name);
  }
});

test('a blocked verdict never reaches the upstream and never touches a hold', async () => {
  const { guard, calls } = fakeGuard();
  guard.verifyRequest = async () => ({ decision: 'block', reasonCode: 'SOP_SPEND_CAP' });
  let forwarded = false;
  const res = await make({ guard, forward: async () => { forwarded = true; return { status: 200, body: {} }; } })(req);
  assert.equal(res.status, 403);
  assert.equal(forwarded, false);
  assert.deepEqual(calls, []);
});

let failed = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log('  ok   ' + name); }
  catch (err) { failed++; console.log('  FAIL ' + name + '\n       ' + (err?.stack ?? err)); }
}
if (failed) { console.log(`\n${failed} of ${t.length} FAILED`); process.exit(1); }
console.log(`\nPASS — ${t.length} gateway settlement cases`);
