// upstream-unreachable.smoke.mjs — an upstream that never took the connection releases the hold (0.32.2).
//
// Pre-beta evaluation 2026-10-11, L7: with the upstream stopped, an allowed payment through `agentsafe-gateway serve`
// answered 502 GATEWAY_ERROR and the owner's Activity Log showed the hold's effect `unknown` (RESPONSE_LOST:UPSTREAM_ERROR),
// still committed to the budget — although the TCP connection was refused before any byte was sent. A connect failure is
// now told apart from a failure after the request may have been delivered: the first releases the hold and answers
// 502 UPSTREAM_UNREACHABLE; the second still parks it UNKNOWN and rethrows.
//
//   node upstream-unreachable.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { createHttpGateway, connectFailureCode, keepAliveFetch, requestNeverSent } from './gateway.mjs';

const TOKEN = 'cd'.repeat(32);

function fakeGuard({ claim = true } = {}) {
  const calls = [];
  const reports = [];
  const guard = {
    async verifyRequest(req) {
      const d = { decision: 'allow', reasonCode: 'AUTHORIZED' };
      if (claim) {
        Object.defineProperty(d, 'claimToken', { value: TOKEN, enumerable: false });
        Object.defineProperty(d, 'authorizationId', { value: req.authorizationId, enumerable: false });
      }
      return d;
    },
    captureAuthorization: async (a) => { calls.push(['capture', a]); return { ok: true }; },
    releaseAuthorization: async (a) => { calls.push(['release', a]); return { ok: true }; },
    markAuthorizationUnknown: async (a) => { calls.push(['unknown', a]); return { ok: true }; },
    reportOutcome: async (p) => { reports.push(p); return { ok: true }; },
  };
  return { guard, calls, reports };
}

const signed = { agentDid: 'did:x', action: 'flight-purchase', amount: 250, currency: 'USD', merchant: 'skyward-air', authorizationId: 'auth-1' };
const route = { method: 'POST', path: '/book', action: 'flight-purchase', bind: false, extract: () => signed };
const req = { method: 'POST', path: '/book', headers: {}, rawBody: Buffer.from('{}') };

/** server.mjs's forward, pointed at `base`, using the given fetch. */
const forwardTo = (base, fetchImpl) => async (r) => {
  const res = await fetchImpl(base + r.path, { method: r.method, headers: { 'content-type': 'application/json' }, body: r.rawBody });
  return { status: res.status, rawBody: Buffer.from(await res.arrayBuffer()) };
};

/** A port nothing listens on: bind one, then close it. */
async function deadPort() {
  const s = net.createServer();
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const { port } = s.address();
  await new Promise((r) => s.close(r));
  return port;
}

const t = [];
const test = (name, fn) => t.push([name, fn]);

for (const [label, fetchImpl] of [['keepAliveFetch', keepAliveFetch], ['Node fetch', globalThis.fetch]]) {
  test(`${label}: a refused connection releases the hold and answers 502 UPSTREAM_UNREACHABLE (executed: false)`, async () => {
    const { guard, calls } = fakeGuard();
    const port = await deadPort();
    const gw = createHttpGateway({ guard, routes: [route], forward: forwardTo(`http://127.0.0.1:${port}`, fetchImpl), reportOutcomes: false });
    const res = await gw(req);
    assert.equal(res.status, 502);
    assert.equal(res.body.reasonCode, 'UPSTREAM_UNREACHABLE');
    assert.equal(res.body.decision, 'block');
    assert.equal(res.body.executed, false);
    assert.match(res.body.error, /ECONNREFUSED/);
    assert.deepEqual(calls, [['release', { authorizationId: 'auth-1', claimToken: TOKEN, reason: 'UPSTREAM_UNREACHABLE' }]], 'released, never parked UNKNOWN');
    assert.ok(!JSON.stringify(res.body).includes(TOKEN));
  });

  test(`${label}: an upstream that took the request and dropped the connection stays UNKNOWN and rethrows`, async () => {
    const { guard, calls } = fakeGuard();
    let received = 0;
    const server = http.createServer((r) => { received++; r.socket.destroy(); });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    try {
      const gw = createHttpGateway({ guard, routes: [route], forward: forwardTo(`http://127.0.0.1:${server.address().port}`, fetchImpl), reportOutcomes: false });
      await assert.rejects(() => gw(req));
      assert.equal(received, 1, 'the upstream did receive the request');
      assert.deepEqual(calls.map((c) => c[0]), ['unknown'], 'ambiguous: never released');
    } finally {
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
    }
  });
}

test('releaseOnConnectFailure: false treats a refused connection as ambiguous, as before (UNKNOWN + rethrow)', async () => {
  const { guard, calls } = fakeGuard();
  const port = await deadPort();
  const gw = createHttpGateway({ guard, routes: [route], forward: forwardTo(`http://127.0.0.1:${port}`, keepAliveFetch), reportOutcomes: false, releaseOnConnectFailure: false });
  await assert.rejects(() => gw(req), /fetch failed/);
  assert.deepEqual(calls.map((c) => c[0]), ['unknown']);
});

test('an unclaimed (bundle-only) call that never reached the upstream is reported REFUSED, not executed', async () => {
  const { guard, calls, reports } = fakeGuard({ claim: false });
  const port = await deadPort();
  const gw = createHttpGateway({ guard, routes: [route], forward: forwardTo(`http://127.0.0.1:${port}`, keepAliveFetch) });
  const res = await gw(req);
  assert.equal(res.body.reasonCode, 'UPSTREAM_UNREACHABLE');
  await gw.drainSettlements(1000);
  assert.deepEqual(calls, [], 'no hold to release');
  assert.equal(reports.length, 1);
  assert.equal(reports[0].outcome, 'refused');
  assert.equal(reports[0].reasonCode, 'UPSTREAM_UNREACHABLE');
  assert.equal(reports[0].httpStatus, 502);
});

test('classification: connect failures anywhere in the cause chain count; anything after connecting does not', () => {
  const fetchFailed = (cause) => Object.assign(new TypeError('fetch failed'), { cause });
  const withCode = (code) => Object.assign(new Error(code), { code });
  for (const code of ['ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'ENETUNREACH', 'EADDRNOTAVAIL', 'UND_ERR_CONNECT_TIMEOUT']) {
    assert.equal(connectFailureCode(fetchFailed(withCode(code))), code, code);
    assert.equal(requestNeverSent(withCode(code)), true, `${code} at the top level`);
  }
  // Node's happy-eyeballs AggregateError: every attempt failed to connect.
  assert.equal(requestNeverSent(fetchFailed(new AggregateError([withCode('ECONNREFUSED'), withCode('ECONNREFUSED')]))), true);
  // Ambiguous: the request may have been written.
  for (const code of ['ECONNRESET', 'EPIPE', 'ETIMEDOUT', 'UND_ERR_SOCKET', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT', undefined]) {
    assert.equal(requestNeverSent(fetchFailed(withCode(code))), false, String(code));
  }
  assert.equal(requestNeverSent(new Error('socket hang up')), false);
  assert.equal(requestNeverSent(fetchFailed(new AggregateError([withCode('ECONNREFUSED'), withCode('ECONNRESET')]))), false, 'one attempt may have connected');
  assert.equal(requestNeverSent(undefined), false);
  assert.equal(requestNeverSent('ECONNREFUSED'), false, 'a bare string proves nothing');
  // A cycle in the cause chain terminates.
  const a = new Error('a'); const b = new Error('b'); a.cause = b; b.cause = a;
  assert.equal(requestNeverSent(a), false);
});

let failed = 0;
for (const [name, fn] of t) {
  try { await fn(); console.log('  ok   ' + name); }
  catch (err) { failed++; console.log('  FAIL ' + name + '\n       ' + (err?.stack ?? err)); }
}
if (failed) { console.log(`\n${failed} of ${t.length} FAILED`); process.exit(1); }
console.log(`\nPASS — ${t.length} upstream-unreachable cases`);
