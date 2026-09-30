// settle-after-answer.smoke.mjs — the gateway answers first and settles the hold after (settleInBackground, 0.16.0).
//
// The settlement is a round trip to the issuer about a response the caller already has; waiting for it only made every
// governed call slower. It now runs after the response is returned, is retried when the issuer is transiently
// unreachable, is final on a refusal, and can be drained on shutdown.
//
//   node settle-after-answer.smoke.mjs   → PASS when every case matches.
import assert from 'node:assert/strict';
import { createHttpGateway } from './gateway.mjs';

const TOKEN = 'ef'.repeat(32);
const signed = { agentDid: 'did:x', action: 'flight-purchase', amount: 250, currency: 'USD', merchant: 'skyward-air', authorizationId: 'auth-1' };
const route = { method: 'POST', path: '/book', action: 'flight-purchase', bind: false, extract: () => signed };
const req = { method: 'POST', path: '/book', headers: {}, rawBody: Buffer.from('{}') };

/** A guard whose capture answers with the queued results, one per call, only once `release()` is called. */
function slowGuard(results = [{ ok: true }]) {
  const calls = [];
  let open;
  const gate = new Promise((r) => (open = r));
  const guard = {
    async verifyRequest(r) {
      const d = { decision: 'allow', reasonCode: 'AUTHORIZED' };
      Object.defineProperty(d, 'claimToken', { value: TOKEN, enumerable: false });
      Object.defineProperty(d, 'authorizationId', { value: r.authorizationId, enumerable: false });
      return d;
    },
    async captureAuthorization(arg) {
      calls.push(arg);
      await gate;
      return results[Math.min(calls.length - 1, results.length - 1)];
    },
    async releaseAuthorization() { return { ok: true }; },
    async markAuthorizationUnknown() { return { ok: true }; },
  };
  return { guard, calls, release: () => open() };
}

const make = (guard, gw = {}) => createHttpGateway({ routes: [route], forward: async () => ({ status: 200, body: { booked: true } }), guard, settleRetryDelaysMs: [5, 5], ...gw });
const quiet = async (fn) => {
  const warn = console.warn;
  const lines = [];
  console.warn = (...a) => lines.push(a.join(' '));
  try { return await fn(lines); } finally { console.warn = warn; }
};

const tests = [];
const test = (name, fn) => tests.push([name, fn]);

test('the response is returned before the settlement has finished', async () => {
  const g = slowGuard();
  const gw = make(g.guard);
  const res = await gw(req); // the issuer has not answered the capture yet
  assert.equal(res.status, 200);
  assert.equal(g.calls.length, 1, 'the capture was started');
  assert.equal(gw.pendingSettlements(), 1, 'and is still running after the response went back');
  g.release();
  assert.equal(await gw.drainSettlements(1000), 0);
  assert.equal(gw.pendingSettlements(), 0);
});

test('settleInBackground: false settles before answering, as before', async () => {
  const g = slowGuard();
  const gw = make(g.guard, { settleInBackground: false });
  let answered = false;
  const p = gw(req).then((r) => { answered = true; return r; });
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(answered, false, 'still waiting on the settlement');
  g.release();
  assert.equal((await p).status, 200);
});

test('a transiently failed capture is retried until it lands', async () => {
  const g = slowGuard([{ ok: false, reasonCode: 'ISSUER_UNREACHABLE' }, { ok: false, status: 503, reasonCode: 'ISSUER_HTTP_503' }, { ok: true }]);
  g.release();
  const gw = make(g.guard);
  await gw(req);
  await gw.drainSettlements(1000);
  assert.equal(g.calls.length, 3);
});

test('a refusal is final and logged — never retried (e.g. an earlier attempt already captured: NOT_HELD)', async () => {
  const g = slowGuard([{ ok: false, status: 409, reasonCode: 'NOT_HELD' }]);
  g.release();
  const gw = make(g.guard);
  const lines = await quiet(async (l) => { await gw(req); await gw.drainSettlements(1000); return l; });
  assert.equal(g.calls.length, 1);
  assert.ok(lines.some((l) => l.includes('capture of auth-1 not applied (NOT_HELD, HTTP 409)')), lines.join('\n'));
});

test('a capture that keeps failing gives up after the retries and says so (it used to be dropped silently)', async () => {
  const g = slowGuard([{ ok: false, reasonCode: 'ISSUER_UNREACHABLE' }]);
  g.release();
  const gw = make(g.guard);
  const lines = await quiet(async (l) => { await gw(req); await gw.drainSettlements(1000); return l; });
  assert.equal(g.calls.length, 3, 'first attempt + 2 retries');
  assert.ok(lines.some((l) => l.includes('not applied (ISSUER_UNREACHABLE, after 3 attempts)')), lines.join('\n'));
});

test('drainSettlements gives up after its timeout and reports what is still running', async () => {
  const g = slowGuard(); // never released
  const gw = make(g.guard);
  await gw(req);
  assert.equal(await gw.drainSettlements(30), 1);
  g.release();
  assert.equal(await gw.drainSettlements(1000), 0);
});

let failed = 0;
for (const [name, fn] of tests) {
  try {
    await fn();
    console.log(`  ok   ${name}`);
  } catch (err) {
    failed++;
    console.log(`  FAIL ${name}\n       ${err?.message ?? err}`);
  }
}
if (failed) {
  console.log(`\nFAIL — ${failed} of ${tests.length}`);
  process.exit(1);
}
console.log(`\nPASS — the gateway answers first and settles after (${tests.length} cases)`);
